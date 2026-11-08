package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// engine checks and applies a host's resources in order.
type engine struct {
	sys Sys
	log io.Writer
	// ignored are the leftovers from the last Check that are meant to stay.
	ignored map[string][]string
	// owed is what earlier runs left owed, as read before the last Check or
	// Apply. Nil means nothing is.
	owed *owedJournal
}

func (e *engine) newRunState() *runState {
	st := newRunState()
	st.ignored = e.ignored
	if e.owed != nil {
		st.owed = e.owed
	}
	return st
}

// check reports each resource's state. Unlike apply, it carries on past
// failures so the plan shows as much as possible, skipping only the
// clean-ups. It returns the position of the first failure, or -1.
func (e *engine) check(ctx context.Context, list ResourceList, send func(Checked) error) (int, error) {
	st := e.newRunState()
	ctx = withRunState(ctx, st)
	failedAt, pending := -1, false
	for i, r := range list {
		st.declare(r)
		res := Checked{ID: r.ID()}
		if isCleanUp(r) && failedAt >= 0 {
			res.Status = StatusSkipped
		} else {
			change, err := r.Check(ctx, e.sys)
			res.Warning = change.Warning
			switch {
			case errors.Is(err, ErrNotYetCheckable) && pending:
				res.Status, res.Error = StatusDeferred, err.Error()
			case err != nil:
				res.Status, res.Error = StatusFailed, err.Error()
			case change.InSync:
				res.Status = StatusInSync
			default:
				res.Status, res.Diff = StatusDrifted, change.Diff
			}
		}

		switch res.Status {
		case StatusDrifted, StatusDeferred:
			pending = true
			st.modified[r.ID()] = true
		case StatusFailed:
			if failedAt < 0 {
				failedAt = i
			}
		case StatusInSync:
			// Its handlers run without it changing, so later resources
			// aren't told it did.
			if len(st.owed.handlersOf(r)) > 0 {
				res.Status, res.Diff = StatusDrifted, "changed in an earlier run whose handlers didn't run\n"
			}
		default:
		}
		if err := send(res); err != nil {
			return failedAt, err
		}
	}
	return failedAt, nil
}

// apply re-checks and applies each resource, stopping at the first failure,
// then runs the handlers that changed resources notified, and those owed
// from earlier runs. Each change is sent as Applying before it's made and
// Applied after. If send fails, it stops after the resource in progress but
// still runs the due handlers. checkFailedAt is the position of the first
// failure in the check that planned this apply, or -1; the clean-ups after
// it are skipped, as the check skipped them.
func (e *engine) apply(ctx context.Context, list ResourceList, checkFailedAt int, send func(any) error) (bool, error) {
	st := e.newRunState()
	ctx = withRunState(ctx, st)
	watchers := watchersByWatched(list)
	var (
		failed  bool
		sendErr error
		due     = dueHandlers{seen: map[string]bool{}}
	)
	for _, r := range list {
		due.add(st.owed.handlersOf(r))
	}
	starting := func(id string, handler bool) {
		if sendErr == nil {
			sendErr = send(Applying{ID: id, Handler: handler})
		}
	}
	for i, r := range list {
		st.declare(r)
		res := Applied{ID: r.ID(), Status: StatusSkipped}
		if !failed && !skippedByCheck(r, i, checkFailedAt) {
			res = e.applyOne(ctx, st, r, watchers[r.ID()], starting)
		}

		switch res.Status {
		case StatusChanged:
			if n, ok := r.(Notifier); ok {
				due.add(n.Notifies())
			}
		case StatusFailed:
			failed = true
		default:
		}

		e.record(res)
		if err := send(res); sendErr == nil {
			sendErr = err
		}
		if sendErr != nil || ctx.Err() != nil {
			break
		}
	}

	// Handlers run even if the run was cut short, so a validated config
	// that was changed is still picked up.
	hctx := context.WithoutCancel(ctx)
	for _, h := range due.list {
		starting(h.ID(), true)
		res := e.applyHandler(hctx, st, h)
		failed = failed || res.Status == StatusFailed
		e.record(res)
		if sendErr == nil {
			sendErr = send(res)
		}
	}
	return failed, sendErr
}

// dueHandlers are the handlers to run after the resources, each once.
type dueHandlers struct {
	list ResourceList
	seen map[string]bool
}

func (d *dueHandlers) add(handlers ResourceList) {
	for _, h := range handlers {
		if !d.seen[h.ID()] {
			d.seen[h.ID()] = true
			d.list = append(d.list, h)
		}
	}
}

func (e *engine) applyHandler(ctx context.Context, st *runState, h Resource) Applied {
	res := Applied{ID: h.ID(), Handler: true, Status: StatusChanged}
	if err := h.Apply(ctx, e.sys); err != nil {
		res.Status, res.Error = StatusFailed, err.Error()
	} else if err := st.owed.settle(e.sys, st.owed.handlers, h.ID()); err != nil {
		res.Warning = unsettledWarning(err)
	}
	return res
}

// skippedByCheck reports whether r, at position i, is a clean-up the check
// skipped because an earlier resource failed at checkFailedAt.
func skippedByCheck(r Resource, i, checkFailedAt int) bool {
	return checkFailedAt >= 0 && i >= checkFailedAt && isCleanUp(r)
}

// applyOne records what r's change triggers as owed before applying it, so
// a failure or a lost agent later in the run can't lose it, even if r
// itself fails part way. watchers are the IDs of the resources watching r.
func (e *engine) applyOne(
	ctx context.Context,
	st *runState,
	r Resource,
	watchers []string,
	starting func(id string, handler bool),
) Applied {
	res := Applied{ID: r.ID()}
	change, err := r.Check(ctx, e.sys)
	switch {
	case err != nil:
		res.Status, res.Error = StatusFailed, err.Error()
	case change.InSync:
		res.Status = StatusInSync
	default:
		res.Diff = change.Diff
		starting(r.ID(), false)
		var handlers []string
		if n, ok := r.(Notifier); ok {
			for _, h := range n.Notifies() {
				handlers = append(handlers, h.ID())
			}
		}
		if err := st.owed.owe(e.sys, watchers, handlers); err != nil {
			res.Status, res.Error = StatusFailed, "recording what its change triggers: "+err.Error()
			return res
		}
		if err := r.Apply(ctx, e.sys); err != nil {
			res.Status, res.Error = StatusFailed, err.Error()
		} else {
			res.Status = StatusChanged
			st.modified[r.ID()] = true
		}
		st.changed()
		if res.Status != StatusChanged {
			break
		}
		if w, ok := r.(applyWarner); ok {
			res.Warning = w.appliedWarning(ctx, e.sys)
		}
		if err := st.owed.settle(e.sys, st.owed.triggers, r.ID()); err != nil {
			res.Warning += unsettledWarning(err)
		}
	}
	return res
}

func unsettledWarning(err error) string {
	return "couldn't record that it's done, so the next run does it again: " + err.Error() + "\n"
}

// applyWarner is implemented by resources that have something to warn about
// once they've been applied.
type applyWarner interface {
	appliedWarning(ctx context.Context, sys Sys) string
}

// leftovers lists each Pruner's leftovers. Like check, it doesn't stop at
// failures.
func (e *engine) leftovers(ctx context.Context, list ResourceList, send func(Leftovers) error) (bool, error) {
	st := e.newRunState()
	ctx = withRunState(ctx, st)
	failed := false
	for _, r := range list {
		st.declare(r)
		p, ok := r.(Pruner)
		if !ok {
			continue
		}
		items, err := p.Leftovers(ctx, e.sys)
		res := Leftovers{ID: r.ID(), Items: st.unignored(r.ID(), items)}
		if err != nil {
			res.Error, failed = err.Error(), true
		}
		if len(res.Items) == 0 && res.Error == "" {
			continue
		}
		if err := send(res); err != nil {
			return failed, err
		}
	}
	return failed, nil
}

// remove prunes one of the leftovers of the Pruner with the given ID, as
// long as it still lists the item.
func (e *engine) remove(ctx context.Context, list ResourceList, id, item string) error {
	ctx, p, err := e.listed(ctx, list, id, item)
	if err != nil {
		return err
	}
	err = p.Prune(ctx, e.sys, item)
	res := "removed"
	if err != nil {
		res = "failed: " + err.Error()
	}
	_, _ = fmt.Fprintf(e.log, "prune %s %s: %s\n", id, item, res)
	return err
}

// preview shows what's at one of the leftovers of the Pruner with the given
// ID, as long as it still lists the item and the item is a path.
func (e *engine) preview(ctx context.Context, list ResourceList, id, item string) ([]string, string, error) {
	if !filepath.IsAbs(item) {
		return nil, "", fmt.Errorf("%s isn't a path", item)
	}
	if _, _, err := e.listed(ctx, list, id, item); err != nil {
		return nil, "", err
	}
	return previewPath(e.sys, item)
}

// listed finds the Pruner with the given ID, checking it still lists item.
// The context it returns has the run state the Pruner was listed with.
func (e *engine) listed(ctx context.Context, list ResourceList, id, item string) (context.Context, Pruner, error) {
	st := e.newRunState()
	ctx = withRunState(ctx, st)
	for _, r := range list {
		st.declare(r)
		p, ok := r.(Pruner)
		if !ok || r.ID() != id {
			continue
		}
		items, err := p.Leftovers(ctx, e.sys)
		if err != nil {
			return nil, nil, err
		}
		if !slices.Contains(items, item) {
			return nil, nil, fmt.Errorf("%s is no longer a leftover", item)
		}
		return ctx, p, nil
	}
	return nil, nil, fmt.Errorf("no resource %s with leftovers", id)
}

func (e *engine) record(res Applied) {
	kind := "resource"
	if res.Handler {
		kind = "handler"
	}
	if res.Error != "" {
		_, _ = fmt.Fprintf(e.log, "%s %s: %s: %s\n", kind, res.ID, res.Status, res.Error)
	} else {
		_, _ = fmt.Fprintf(e.log, "%s %s: %s\n", kind, res.ID, res.Status)
	}
}

// isCleanUp reports whether r removes what earlier resources didn't declare,
// which is only safe if they all succeeded.
func isCleanUp(r Resource) bool {
	switch r.(type) {
	case OwnedDir, ComposeProjects, DockerNetworks, SystemdUnits, Migrations, CertRecords:
		return true
	default:
		return false
	}
}

// OwedPath is where the agent keeps what earlier runs changed but didn't
// act on: the resources watching others that haven't applied since one of
// them changed, and the handlers that haven't run since they were notified.
// Without it, a run that stops part way, or an agent that's killed, would
// lose them for good.
const OwedPath = "/var/lib/sensible/owed.json"

// owedJournal is what OwedPath holds, as sets of IDs. Entries for resources
// that are no longer declared are kept, as an apply may be given only some
// of a host's resources, as bootstrap's is, and only declared resources
// read them.
type owedJournal struct {
	triggers map[string]bool
	handlers map[string]bool
}

type owedFile struct {
	Triggers []string `json:"triggers,omitempty"`
	Handlers []string `json:"handlers,omitempty"`
}

func newOwedJournal() *owedJournal {
	return &owedJournal{triggers: map[string]bool{}, handlers: map[string]bool{}}
}

func readOwed(sys FileReader) (*owedJournal, error) {
	o := newOwedJournal()
	data, err := sys.ReadFile(OwedPath)
	if errors.Is(err, fs.ErrNotExist) {
		return o, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", OwedPath, err)
	}
	var f owedFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", OwedPath, err)
	}
	for _, id := range f.Triggers {
		o.triggers[id] = true
	}
	for _, id := range f.Handlers {
		o.handlers[id] = true
	}
	return o, nil
}

// owe records the resources with the given IDs as triggered, and the
// handlers as notified, writing the journal if that's new.
func (o *owedJournal) owe(sys FileWriter, triggers, handlers []string) error {
	changed := false
	for _, id := range triggers {
		changed = changed || !o.triggers[id]
		o.triggers[id] = true
	}
	for _, id := range handlers {
		changed = changed || !o.handlers[id]
		o.handlers[id] = true
	}
	if !changed {
		return nil
	}
	return o.write(sys)
}

// settle removes id from set, one of o's, once it's acted.
func (o *owedJournal) settle(sys FileWriter, set map[string]bool, id string) error {
	if !set[id] {
		return nil
	}
	delete(set, id)
	return o.write(sys)
}

func (o *owedJournal) handlersOf(r Resource) ResourceList {
	n, ok := r.(Notifier)
	if !ok || len(o.handlers) == 0 {
		return nil
	}
	return slices.DeleteFunc(slices.Clone(n.Notifies()), func(h Resource) bool { return !o.handlers[h.ID()] })
}

func (o *owedJournal) write(sys FileWriter) error {
	data, err := json.Marshal(
		owedFile{Triggers: slices.Sorted(maps.Keys(o.triggers)), Handlers: slices.Sorted(maps.Keys(o.handlers))},
	)
	if err != nil {
		return err
	}
	if err := sys.MkdirAll(filepath.Dir(OwedPath), 0o755); err != nil {
		return err
	}
	return sys.WriteFile(OwedPath, append(data, '\n'), WriteOptions{UID: -1, GID: -1, Mode: 0o600})
}

// watcher is implemented by resources that act when a resource they watch
// changes earlier in the run.
type watcher interface {
	watches() []string
}

// watchersByWatched maps the ID of each watched resource in list to the IDs
// of those watching it.
func watchersByWatched(list ResourceList) map[string][]string {
	byWatched := map[string][]string{}
	for _, r := range list {
		if w, ok := r.(watcher); ok {
			for _, id := range w.watches() {
				byWatched[id] = append(byWatched[id], r.ID())
			}
		}
	}
	return byWatched
}

// runState is shared by the resources in one check or apply.
type runState struct {
	// declared holds the paths of every File, Dir, Symlink, GitCheckout,
	// Download, ComposeStack, Migration, CertRecord and apt source and key
	// seen so far, for the clean-up resources.
	declared map[string]bool
	// modified holds the IDs of resources that changed earlier in an apply,
	// or that a check found would change.
	modified map[string]bool
	owed     *owedJournal
	// networks holds the names of every DockerNetwork seen so far.
	networks map[string]bool
	// users holds the names of every User seen so far that isn't Absent.
	users map[string]bool
	// packages holds the names of every Package seen so far that isn't
	// Absent, every AURPackage, and those Commands install.
	packages map[string]bool

	osFamily string

	pacman *pacmanDB
	dpkg   map[string]dpkgPackage

	// aptSourcesChanged is set when an apt source changes, so the next
	// install refreshes the package index.
	aptSourcesChanged bool
	aptUpdated        bool

	// containers is every container on the host, for ComposeStack.
	containers []composeContainer

	// ignored are leftovers that are meant to stay, as items by the ID of
	// the Pruner that lists them.
	ignored map[string][]string
	// keptPaths and keptPackages are the patterns of every KeptLeftovers
	// seen so far.
	keptPaths, keptPackages []string
}

func newRunState() *runState {
	return &runState{
		declared: map[string]bool{},
		modified: map[string]bool{},
		networks: map[string]bool{},
		users:    map[string]bool{},
		packages: map[string]bool{},
		owed:     newOwedJournal(),
	}
}

func (s *runState) declare(r Resource) {
	switch r := r.(type) {
	case File:
		s.declared[r.Path] = true
	case Dir:
		s.declared[r.Path] = true
	case Symlink:
		s.declared[r.Path] = true
	case GitCheckout:
		s.declared[r.Path] = true
	case Download:
		s.declared[r.Path] = true
	case ComposeStack:
		s.declared[r.Dir] = true
	case AptRepo:
		s.declared[r.sourcesPath()] = true
	case DockerNetwork:
		s.networks[r.Name] = true
	case User:
		if !r.Absent {
			s.users[r.Name] = true
		}
	case Package:
		if !r.Absent {
			s.packages[r.Name] = true
		}
	case AURPackage:
		s.packages[r.Name] = true
	case Command:
		for _, name := range r.Packages {
			s.packages[name] = true
		}
	case Migration:
		s.declared[filepath.Dir(r.dir())] = true
		s.declared[r.dir()] = true
	case CertRecord:
		s.declared[filepath.Join(CertRecordsDir, r.Name)] = true
	case KeptLeftovers:
		s.keptPaths = append(s.keptPaths, r.Paths...)
		s.keptPackages = append(s.keptPackages, r.Packages...)
	default:
	}
}

// triggered reports whether a watcher should act for a change in this run
// (now) or in an earlier one it hasn't acted on (owed).
func (s *runState) triggered(id string, watch []string) (now, owed bool) {
	now = slices.ContainsFunc(watch, func(w string) bool { return s.modified[w] })
	return now, s.owed.triggers[id]
}

// unignored drops the items that are ignored for the Pruner with the given
// ID, and those a KeptLeftovers keeps.
func (s *runState) unignored(id string, items []string) []string {
	ignored := s.ignored[id]
	if len(ignored) == 0 && len(s.keptPaths) == 0 && len(s.keptPackages) == 0 {
		return items
	}
	return slices.DeleteFunc(
		slices.Clone(items),
		func(item string) bool { return slices.Contains(ignored, item) || s.kept(item) },
	)
}

// kept reports whether a leftover, a path or "package <name>", matches a
// KeptLeftovers pattern.
func (s *runState) kept(item string) bool {
	patterns, name := s.keptPaths, item
	if pkg, ok := strings.CutPrefix(item, "package "); ok {
		patterns, name = s.keptPackages, pkg
	}
	return slices.ContainsFunc(
		patterns,
		func(p string) bool {
			ok, _ := filepath.Match(p, name)
			return ok
		},
	)
}

// changed drops cached package state, as any change may have installed or
// removed packages.
func (s *runState) changed() {
	s.pacman = nil
	s.dpkg = nil
	s.containers = nil
}

type runStateKey struct{}

func withRunState(ctx context.Context, st *runState) context.Context {
	return context.WithValue(ctx, runStateKey{}, st)
}

// state returns the run's state, or a fresh one for resources used outside
// an engine.
func state(ctx context.Context) *runState {
	if st, ok := ctx.Value(runStateKey{}).(*runState); ok {
		return st
	}
	return newRunState()
}
