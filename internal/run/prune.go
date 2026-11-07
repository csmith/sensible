package run

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

// PruneOptions select the hosts for Prune.
type PruneOptions struct {
	ConfigDir string
	// Hosts limits the run to these inventory names. Empty means all hosts.
	Hosts []string
}

// Prune finds what the selected hosts have left over, such as volumes no
// role declares any more, and offers to remove each item.
func Prune(ctx context.Context, opts PruneOptions) error {
	out := os.Stdout
	repo, err := openRepo(opts.ConfigDir, out)
	if err != nil {
		return err
	}
	names, err := selectHosts(repo.Inventory(), opts.Hosts)
	if err != nil {
		return err
	}
	targets := make([]target, len(names))
	for i, name := range names {
		targets[i] = newTarget(repo, name)
	}
	r := &Runner{
		Out:     out,
		Confirm: confirmOnTerminal,
		Builds:  NewEmbeddedBuilds(),
		Compile: compiler(repo),
	}
	return r.Prune(ctx, targets)
}

// leftover is one item that prune offers to remove.
type leftover struct {
	h *hostRun
	// label says what's removed, e.g. a path.
	label  string
	remove func() error
	// after, if set, must be removed first, or this is kept.
	after   *leftover
	removed bool
}

// Prune checks the targets and offers to remove each of their leftovers.
// Hosts with changes still to apply are skipped, as their leftovers may
// change once the changes are applied.
func (r *Runner) Prune(ctx context.Context, targets []target) error {
	out := newRenderer(r.Out)
	runs := r.connect(ctx, targets)
	defer byeAll(runs)
	out.agents(runs)

	r.checkAll(runs)
	var wg sync.WaitGroup
	for _, h := range runs {
		if h.agent == nil {
			continue
		}
		t := out.beginSection("Finding leftovers on " + h.name)
		wg.Go(
			func() {
				<-h.done
				if h.err == nil && !h.failed && !h.pending() {
					h.findLeftovers()
				}
				out.finish(t, indentItems(leftoverLines(h, out.p))...)
			},
		)
	}
	wg.Wait()

	failed := anyFailed(runs)
	var items []*leftover
	for _, h := range runs {
		items = append(items, h.leftovers...)
	}
	if len(items) == 0 {
		if !failed {
			out.line("")
			out.line(out.p.bold("Nothing to prune"))
		}
		return failedErr(failed)
	}

	out.line("")
	out.section("Pruning")
	for _, l := range items {
		if l.after != nil && !l.after.removed {
			out.item(out.p.dim("- " + l.h.name + ": " + l.label + "  kept with " + l.after.label))
			continue
		}
		ok, err := r.Confirm(fmt.Sprintf("Remove %s from %s? [y/N] ", l.label, l.h.name))
		if err != nil {
			return errors.Join(err, failedErr(failed))
		}
		if !ok {
			out.item(out.p.dim("- " + l.h.name + ": " + l.label + "  kept"))
			continue
		}
		if err := l.remove(); err != nil {
			failed = true
			out.item(out.p.fail("✗ " + l.h.name + ": " + l.label + ": " + err.Error()))
			continue
		}
		l.removed = true
		out.item(out.p.ok("✓") + " " + l.h.name + ": " + l.label)
	}
	return failedErr(failed)
}

func (h *hostRun) findLeftovers() {
	found, err := h.agent.leftovers()
	if err != nil {
		h.err = err
		return
	}
	for _, f := range found {
		if f.Error != "" {
			h.failed = true
			h.unlisted = append(h.unlisted, f)
		}
		for _, item := range f.Items {
			h.leftovers = append(
				h.leftovers,
				&leftover{h: h, label: item, remove: func() error { return h.agent.remove(f.ID, item) }},
			)
		}
	}
	h.findUnusedSecrets()
}

// findUnusedSecrets offers the values saved for stacks the host no longer
// has. A stack's volume directory may hold data that uses them, so they're
// only offered once it's gone: they come after the host's other leftovers,
// and are kept unless the directory is removed first. If the host's
// leftovers couldn't all be listed, the directory may be there unlisted.
func (h *hostRun) findUnusedSecrets() {
	if len(h.unlisted) > 0 {
		return
	}
	volumes := slices.Clone(h.leftovers)
	for _, s := range h.unusedSecrets {
		l := &leftover{
			h:      h,
			label:  "generated secrets for " + s.stack + " (" + strings.Join(s.names, ", ") + ")",
			remove: s.drop,
		}
		dir := filepath.Join(config.VolumesDir, s.stack)
		if i := slices.IndexFunc(volumes, func(v *leftover) bool { return v.label == dir }); i >= 0 {
			l.after = volumes[i]
		}
		h.leftovers = append(h.leftovers, l)
	}
}

func leftoverLines(h *hostRun, p palette) []string {
	if h.err != nil {
		return []string{p.fail("✗ " + h.err.Error())}
	}
	var lines []string
	pending := 0
	for _, c := range h.checked {
		switch c.Status {
		case host.StatusFailed:
			lines = append(lines, p.fail("✗ "+displayID(c.ID)+": "+c.Error))
		case host.StatusDrifted, host.StatusDeferred:
			pending++
		default:
		}
	}
	if pending > 0 {
		lines = append(lines, p.change("! "+plural(pending, "change")+" to apply first"))
	}
	for _, f := range h.unlisted {
		lines = append(lines, p.fail("✗ "+displayID(f.ID)+": "+f.Error))
	}
	for _, l := range h.leftovers {
		line := p.change("-") + " " + l.label
		if l.after != nil {
			line += p.dim("  once " + l.after.label + " is removed")
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		lines = append(lines, p.dim("✓ nothing left over"))
	}
	return lines
}

func (a *agent) leftovers() ([]host.Leftovers, error) {
	if err := a.conn.Send(host.Prune{}); err != nil {
		return nil, err
	}
	var found []host.Leftovers
	for {
		msg, err := a.receive()
		if err != nil {
			return nil, err
		}
		switch m := msg.(type) {
		case host.Leftovers:
			found = append(found, m)
		case host.Done:
			return found, nil
		default:
			return nil, fmt.Errorf("unexpected %T while finding leftovers", msg)
		}
	}
}

func (a *agent) remove(id, item string) error {
	if err := a.conn.Send(host.Remove{ID: id, Item: item}); err != nil {
		return err
	}
	removed, err := receive[host.Removed](a)
	if err != nil {
		return err
	}
	if removed.ID != id || removed.Item != item {
		return fmt.Errorf("agent removed %s from %s, not %s", removed.Item, removed.ID, item)
	}
	if removed.Error != "" {
		return errors.New(removed.Error)
	}
	return nil
}
