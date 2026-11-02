package host

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// engine checks and applies a host's resources in order.
type engine struct {
	sys Sys
	log io.Writer
}

// check reports each resource's state. Unlike apply, it carries on past
// failures so the plan shows as much as possible.
func (e *engine) check(ctx context.Context, list ResourceList, send func(Checked) error) (bool, error) {
	st := newRunState()
	ctx = withRunState(ctx, st)
	failed, pending := false, false
	for _, r := range list {
		st.declare(r)
		res := Checked{ID: r.ID()}
		if isCleanUp(r) && failed {
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
			failed = true
		default:
		}
		if err := send(res); err != nil {
			return failed, err
		}
	}
	return failed, nil
}

// apply re-checks and applies each resource, stopping at the first failure,
// then runs the handlers that changed resources notified. If send fails, it
// stops after the resource in progress but still runs the due handlers.
func (e *engine) apply(ctx context.Context, list ResourceList, send func(Applied) error) (bool, error) {
	st := newRunState()
	ctx = withRunState(ctx, st)
	var (
		failed   bool
		sendErr  error
		handlers ResourceList
		notified = map[string]bool{}
	)
	for _, r := range list {
		st.declare(r)
		res := Applied{ID: r.ID(), Status: StatusSkipped}
		if !failed {
			res = e.applyOne(ctx, st, r)
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
		if sendErr = send(res); sendErr != nil || ctx.Err() != nil {
			break
		}
	}

	// Handlers run even if the run was cut short, so a validated config
	// that was changed is still picked up.
	hctx := context.WithoutCancel(ctx)
	for _, h := range handlers {
		res := Applied{ID: h.ID(), Handler: true, Status: StatusChanged}
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

func (e *engine) applyOne(ctx context.Context, st *runState, r Resource) Applied {
	res := Applied{ID: r.ID()}
	change, err := r.Check(ctx, e.sys)
	switch {
	case err != nil:
		res.Status, res.Error = StatusFailed, err.Error()
	case change.InSync:
		res.Status = StatusInSync
	default:
		res.Diff = change.Diff
		if err := r.Apply(ctx, e.sys); err != nil {
			res.Status, res.Error = StatusFailed, err.Error()
		} else {
			res.Status = StatusChanged
			st.modified[r.ID()] = true
		}
		st.changed()
	}
	return res
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
	case OwnedDir, ComposeProjects, DockerNetworks, SystemdUnits:
		return true
	default:
		return false
	}
}

// runState is shared by the resources in one check or apply.
type runState struct {
	// declared holds the paths of every File, Dir, ComposeStack and apt
	// source and key seen so far, for the clean-up resources.
	declared map[string]bool
	// modified holds the IDs of resources that changed earlier in an apply,
	// or that a check found would change.
	modified map[string]bool
	// networks holds the names of every DockerNetwork seen so far.
	networks map[string]bool

	osFamily string

	pacman *pacmanDB
	dpkg   map[string]dpkgPackage

	// aptSourcesChanged is set when an apt source changes, so the next
	// install refreshes the package index.
	aptSourcesChanged bool
	aptUpdated        bool

	// containers is every container on the host, for ComposeStack.
	containers []composeContainer
}

func newRunState() *runState {
	return &runState{declared: map[string]bool{}, modified: map[string]bool{}, networks: map[string]bool{}}
}

func (s *runState) declare(r Resource) {
	switch r := r.(type) {
	case File:
		s.declared[r.Path] = true
	case Dir:
		s.declared[r.Path] = true
	case ComposeStack:
		s.declared[r.Dir] = true
	case AptRepo:
		s.declared[r.sourcesPath()] = true
	case DockerNetwork:
		s.networks[r.Name] = true
	default:
	}
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
