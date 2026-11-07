package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// MigrationsDir holds what each stack's migrations last ran with, in
// <stack>/<migration>.
const MigrationsDir = "/var/lib/sensible/migrations"

const (
	PhaseBefore = "before"
	PhaseAfter  = "after"
)

// Migration runs commands around a stack's recreate when a value changes
// from the one recorded when it last ran on the host. With no record, it
// records the value without running anything, as there's nothing to
// migrate from.
//
// Each migration is listed twice: ahead of the stack's files, so a failure
// leaves the stack untouched, and once the stack is up, where it's retried
// alone if it fails.
type Migration struct {
	// Stack is the stack's directory, where the commands run, with the
	// variables in its .env.
	Stack string `json:"stack"`
	Name  string `json:"name"`
	Phase string `json:"phase"`
	On    string `json:"on"`
	// Secret keeps On out of diffs and records.
	Secret bool `json:"secret,omitempty"`
	// Before and After may be empty. Both get $MIGRATION_DIR, which is kept
	// from the start of Before until After succeeds.
	Before []string `json:"before,omitempty"`
	After  []string `json:"after,omitempty"`
}

// Migrations removes the records of migrations that no Migration earlier in
// the same run declared. It's skipped if anything on the host failed.
type Migrations struct{}

func (r Migration) ID() string { return "migration-" + r.Phase + ":" + r.stackName() + "/" + r.Name }

func (r Migrations) ID() string { return "migrations" }

func (r Migration) Check(_ context.Context, sys Sys) (Change, error) {
	rec, ok, err := r.record(sys)
	switch {
	case err != nil:
		return Change{}, err
	case !ok && r.Phase == PhaseBefore:
		return drift("record " + r.value().Shown + "\n"), nil
	case !ok:
		return Change{InSync: true}, nil
	}
	switch {
	case rec.Pending != nil && r.Phase == PhaseAfter:
		return drift(fmt.Sprintf("finish migrating %s → %s\n", rec.Shown, rec.Pending.Shown)), nil
	case rec.Pending != nil || rec.Hash == r.value().Hash:
		return Change{InSync: true}, nil
	case r.Phase == PhaseBefore:
		return drift(fmt.Sprintf("migrate %s → %s\n", rec.Shown, r.value().Shown)), nil
	default:
		return drift(fmt.Sprintf("finish migrating %s → %s\n", rec.Shown, r.value().Shown)), nil
	}
}

func (r Migration) Apply(ctx context.Context, sys Sys) error {
	rec, ok, err := r.record(sys)
	if err != nil {
		return err
	}
	if r.Phase == PhaseBefore {
		return r.before(ctx, sys, rec, ok)
	}
	if !ok || rec.Pending == nil {
		return fmt.Errorf("migration %s hasn't run its before phase", r.Name)
	}
	if err := r.run(ctx, sys, r.After); err != nil {
		return err
	}
	if err := r.write(sys, migrationRecord{migrationValue: *rec.Pending}); err != nil {
		return err
	}
	return sys.RemoveAll(r.workDir())
}

func (r Migration) before(ctx context.Context, sys Sys, rec migrationRecord, ok bool) error {
	if !ok {
		return r.write(sys, migrationRecord{migrationValue: r.value()})
	}
	if rec.Pending != nil || rec.Hash == r.value().Hash {
		return nil
	}
	// Left by a before that failed, which is run again from scratch.
	if err := sys.RemoveAll(r.workDir()); err != nil {
		return err
	}
	if err := sys.MkdirAll(r.workDir(), 0o700); err != nil {
		return err
	}
	if err := r.run(ctx, sys, r.Before); err != nil {
		return err
	}
	pending := r.value()
	rec.Pending = &pending
	return r.write(sys, rec)
}

func (r Migration) run(ctx context.Context, sys Sys, argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	env, err := stackEnv(sys, r.Stack)
	if err != nil {
		return err
	}
	env["MIGRATION_DIR"] = r.workDir()
	_, err = runOK(ctx, sys, Cmd{Argv: argv, Env: env, Dir: r.Stack})
	if err != nil {
		return fmt.Errorf("migration %s: %s: %w", r.Name, r.Phase, err)
	}
	return nil
}

// stackEnv reads the variables in a stack's .env, which sensible writes
// with single-quoted values.
func stackEnv(sys Sys, dir string) (map[string]string, error) {
	env := map[string]string{}
	data, err := sys.ReadFile(filepath.Join(dir, ".env"))
	if errors.Is(err, fs.ErrNotExist) {
		return env, nil
	}
	if err != nil {
		return nil, err
	}
	for line := range strings.Lines(string(data)) {
		name, value, ok := strings.Cut(strings.TrimRight(line, "\n"), "=")
		if !ok {
			continue
		}
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}
		env[name] = value
	}
	return env, nil
}

// migrationRecord is what a migration last ran with, and what it's
// migrating to if its before phase has finished but its after hasn't.
type migrationRecord struct {
	migrationValue
	Pending *migrationValue `json:"pending,omitempty"`
}

// migrationValue is a hash of On, so a secret isn't kept, and On as diffs
// show it.
type migrationValue struct {
	Hash  string `json:"hash"`
	Shown string `json:"shown"`
}

func (r Migration) value() migrationValue {
	sum := sha256.Sum256([]byte(r.On))
	shown := r.On
	if r.Secret {
		shown = "(secret)"
	}
	return migrationValue{Hash: hex.EncodeToString(sum[:]), Shown: shown}
}

func (r Migration) stackName() string { return filepath.Base(r.Stack) }

func (r Migration) dir() string { return filepath.Join(MigrationsDir, r.stackName(), r.Name) }

func (r Migration) workDir() string { return filepath.Join(r.dir(), "work") }

func (r Migration) recordPath() string { return filepath.Join(r.dir(), "record.json") }

func (r Migration) record(sys Sys) (migrationRecord, bool, error) {
	data, err := sys.ReadFile(r.recordPath())
	if errors.Is(err, fs.ErrNotExist) {
		return migrationRecord{}, false, nil
	}
	if err != nil {
		return migrationRecord{}, false, err
	}
	var rec migrationRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return migrationRecord{}, false, fmt.Errorf("parsing %s: %w", r.recordPath(), err)
	}
	return rec, true, nil
}

func (r Migration) write(sys Sys, rec migrationRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := sys.MkdirAll(r.dir(), 0o700); err != nil {
		return err
	}
	return sys.WriteFile(r.recordPath(), append(data, '\n'), WriteOptions{UID: -1, GID: -1, Mode: 0o600})
}

func (r Migrations) Check(ctx context.Context, sys Sys) (Change, error) {
	extra, err := r.undeclared(ctx, sys)
	if err != nil {
		return Change{}, err
	}
	var diff strings.Builder
	for _, path := range extra {
		rel, _ := filepath.Rel(MigrationsDir, path)
		diff.WriteString("forget migration " + rel + "\n")
	}
	return Change{InSync: len(extra) == 0, Diff: diff.String()}, nil
}

func (r Migrations) Apply(ctx context.Context, sys Sys) error {
	extra, err := r.undeclared(ctx, sys)
	if err != nil {
		return err
	}
	for _, path := range extra {
		if err := sys.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

// undeclared lists the stacks' directories in MigrationsDir with no
// migrations declared, and the undeclared migrations in the rest.
func (r Migrations) undeclared(ctx context.Context, sys Sys) ([]string, error) {
	return undeclaredInGroups(sys, state(ctx).declared, MigrationsDir)
}
