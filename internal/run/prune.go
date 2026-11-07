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
		Ask:     askOnTerminal,
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
	// ignore, if set, records that it's meant to stay.
	ignore func() error
	// note, if set, warns what removing it may affect.
	note string
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
		ok, err := r.pruneOne(out, l)
		if err != nil {
			return errors.Join(err, failedErr(failed))
		}
		failed = failed || !ok
	}
	return failedErr(failed)
}

// pruneOne asks what to do with a leftover and does it, reporting whether
// that succeeded. It only returns an error if the question couldn't be
// asked.
func (r *Runner) pruneOne(out *renderer, l *leftover) (bool, error) {
	if l.after != nil && !l.after.removed {
		out.item(out.p.dim("- " + l.h.name + ": " + l.label + "  kept with " + l.after.label))
		return true, nil
	}
	prompt := fmt.Sprintf("Remove %s from %s? ", l.label, l.h.name)
	if l.note != "" {
		prompt += strings.ToUpper(l.note[:1]) + l.note[1:] + ". "
	}
	choices := "[y/N] "
	if l.ignore != nil {
		choices = "[y/N/i] "
	}
	answer, err := r.Ask(prompt + choices)
	if err != nil {
		return false, err
	}
	ignore := l.ignore != nil && (answer == "i" || answer == "ignore")
	if !ignore && answer != "y" && answer != "yes" {
		out.item(out.p.dim("- " + l.h.name + ": " + l.label + "  kept"))
		return true, nil
	}
	act := l.remove
	if ignore {
		act = l.ignore
	}
	if err := act(); err != nil {
		out.item(out.p.failure(l.h.name + ": " + l.label + ": " + err.Error())...)
		return false, nil
	}
	if ignore {
		out.item(out.p.dim("- " + l.h.name + ": " + l.label + "  ignored"))
		return true, nil
	}
	l.removed = true
	out.item(out.p.ok("✓") + " " + l.h.name + ": " + l.label)
	return true, nil
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
			l := &leftover{h: h, label: item, remove: func() error { return h.agent.remove(f.ID, item) }}
			if h.ignore != nil {
				l.ignore = func() error { return h.ignore(f.ID, item) }
			}
			h.leftovers = append(h.leftovers, l)
		}
	}
	h.findUnusedSecrets()
}

// findUnusedSecrets offers the values saved for stacks the host no longer
// has, and those its stacks no longer use. A removed stack's volume
// directory may hold data that uses them, so they're only offered once it's
// gone: they come after the host's other leftovers, and are kept unless the
// directory is removed first. If the host's leftovers couldn't all be
// listed, or it's ignored, the directory may be there unlisted. A stack's
// own volumes are still there, so its values come with a warning.
func (h *hostRun) findUnusedSecrets() {
	volumes := slices.Clone(h.leftovers)
	ignoredVolumes := h.ignored[host.Volumes{Path: config.VolumesDir}.ID()]
	for _, s := range h.unusedSecrets {
		names := " (" + strings.Join(s.names, ", ") + ")"
		if s.inUse {
			h.leftovers = append(
				h.leftovers,
				&leftover{
					h:      h,
					label:  "generated secrets " + s.stack + " no longer uses" + names,
					note:   "data in its volumes may still use them",
					remove: s.drop,
				},
			)
			continue
		}
		if len(h.unlisted) > 0 {
			continue
		}
		dir := filepath.Join(config.VolumesDir, s.stack)
		if slices.Contains(ignoredVolumes, dir) {
			continue
		}
		l := &leftover{
			h:      h,
			label:  "generated secrets for " + s.stack + names,
			remove: s.drop,
		}
		if i := slices.IndexFunc(volumes, func(v *leftover) bool { return v.label == dir }); i >= 0 {
			l.after = volumes[i]
		}
		h.leftovers = append(h.leftovers, l)
	}
}

func leftoverLines(h *hostRun, p palette) []string {
	if h.err != nil {
		return p.failure(h.err.Error())
	}
	var lines []string
	pending := 0
	for _, c := range h.checked {
		switch c.Status {
		case host.StatusFailed:
			lines = append(lines, p.failure(displayID(c.ID)+": "+c.Error)...)
		case host.StatusDrifted, host.StatusDeferred:
			pending++
		default:
		}
	}
	if pending > 0 {
		lines = append(lines, p.change("! "+plural(pending, "change")+" to apply first"))
	}
	for _, f := range h.unlisted {
		lines = append(lines, p.failure(displayID(f.ID)+": "+f.Error)...)
	}
	for _, l := range h.leftovers {
		line := p.change("-") + " " + l.label
		if l.after != nil {
			line += p.dim("  once " + l.after.label + " is removed")
		}
		if l.note != "" {
			line += p.dim("  " + l.note)
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
