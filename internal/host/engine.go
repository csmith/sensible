package host

import (
	"context"
	"errors"
	"fmt"
	"io"
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
}

func (e *engine) newRunState() *runState {
	st := newRunState()
	st.ignored = e.ignored
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
		default:
		}
		if err := send(res); err != nil {
			return failedAt, err
		}
	}
	return failedAt, nil
}

// apply re-checks and applies each resource, stopping at the first failure,
// then runs the handlers that changed resources notified. Each change is
// sent as Applying before it's made and Applied after. If send fails, it
// stops after the resource in progress but still runs the due handlers.
// checkFailedAt is the position of the first failure in the check that
// planned this apply, or -1; the clean-ups after it are skipped, as the
// check skipped them.
func (e *engine) apply(ctx context.Context, list ResourceList, checkFailedAt int, send func(any) error) (bool, error) {
	st := e.newRunState()
	ctx = withRunState(ctx, st)
	var (
		failed   bool
		sendErr  error
		handlers ResourceList
		notified = map[string]bool{}
	)
	starting := func(id string, handler bool) {
		if sendErr == nil {
			sendErr = send(Applying{ID: id, Handler: handler})
		}
	}
	for i, r := range list {
		st.declare(r)
		res := Applied{ID: r.ID(), Status: StatusSkipped}
		if !failed && !skippedByCheck(r, i, checkFailedAt) {
			res = e.applyOne(ctx, st, r, starting)
		}

		switch res.Status {
		case StatusChanged:
			if n, ok := r.(Notifier); ok {
				for _, h := range n.Notifies() {
					if !notified[h.ID()] {
						notified[h.ID()] = true
						handlers = append(handlers, h)
					}
				}
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
	for _, h := range handlers {
		res := Applied{ID: h.ID(), Handler: true, Status: StatusChanged}
		starting(h.ID(), true)
		if err := h.Apply(hctx, e.sys); err != nil {
			res.Status, res.Error = StatusFailed, err.Error()
			failed = true
		}
		e.record(res)
		if sendErr == nil {
			sendErr = send(res)
		}
	}
	return failed, sendErr
}

// skippedByCheck reports whether r, at position i, is a clean-up the check
// skipped because an earlier resource failed at checkFailedAt.
func skippedByCheck(r Resource, i, checkFailedAt int) bool {
	return checkFailedAt >= 0 && i >= checkFailedAt && isCleanUp(r)
}

func (e *engine) applyOne(
	ctx context.Context,
	st *runState,
	r Resource,
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
		if err := r.Apply(ctx, e.sys); err != nil {
			res.Status, res.Error = StatusFailed, err.Error()
		} else {
			res.Status = StatusChanged
			st.modified[r.ID()] = true
		}
		st.changed()
		if w, ok := r.(applyWarner); ok && res.Status == StatusChanged {
			res.Warning = w.appliedWarning(ctx, e.sys)
		}
	}
	return res
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
			return err
		}
		if !slices.Contains(items, item) {
			return fmt.Errorf("%s is no longer a leftover", item)
		}
		err = p.Prune(ctx, e.sys, item)
		res := "removed"
		if err != nil {
			res = "failed: " + err.Error()
		}
		_, _ = fmt.Fprintf(e.log, "prune %s %s: %s\n", id, item, res)
		return err
	}
	return fmt.Errorf("no resource %s to prune", id)
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

// runState is shared by the resources in one check or apply.
type runState struct {
	// declared holds the paths of every File, Dir, Symlink, GitCheckout,
	// Download, ComposeStack, Migration, CertRecord and apt source and key
	// seen so far, for the clean-up resources.
	declared map[string]bool
	// modified holds the IDs of resources that changed earlier in an apply,
	// or that a check found would change.
	modified map[string]bool
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
