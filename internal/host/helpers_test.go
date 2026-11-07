package host

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testSys is a localSys rooted in a temporary directory, with scripted
// commands and downloads. /etc/passwd and /etc/group define "alice" and
// "bob" with the test process's own IDs, so files can be chowned to them.
type testSys struct {
	*localSys
	t        *testing.T
	commands map[string]func(Cmd) Result
	ran      []string
	urls     map[string]string
	now      time.Time
}

func newTestSys(t *testing.T) *testSys {
	t.Helper()
	s := &testSys{
		t:        t,
		commands: map[string]func(Cmd) Result{},
		urls:     map[string]string{},
		now:      time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
	}
	s.localSys = &localSys{
		root: t.TempDir(),
		runner: func(_ context.Context, cmd Cmd) (Result, error) {
			line := strings.Join(cmd.Argv, " ")
			s.ran = append(s.ran, line)
			if fn, ok := s.commands[line]; ok {
				return fn(cmd), nil
			}
			for pattern, fn := range s.commands {
				if prefix, ok := strings.CutSuffix(pattern, "*"); ok && strings.HasPrefix(line, prefix) {
					return fn(cmd), nil
				}
			}
			return Result{}, fmt.Errorf("running %s: %w", cmd.Argv[0], exec.ErrNotFound)
		},
		fetcher: func(_ context.Context, url string) ([]byte, error) {
			if body, ok := s.urls[url]; ok {
				return []byte(body), nil
			}
			return nil, fmt.Errorf("fetching %s: not found", url)
		},
		clock: func() time.Time { return s.now },
	}
	uid, gid := os.Getuid(), os.Getgid()
	s.write(
		"/etc/passwd",
		fmt.Sprintf(
			"alice:x:%d:%d::/home/alice:/bin/bash\nbob:x:%d:%d::/home/bob:/bin/sh\n",
			uid,
			gid,
			uid,
			gid,
		),
	)
	s.write("/etc/group", fmt.Sprintf("users:x:%d:\nwheel:x:%d:bob\n", gid, gid+1))
	s.write("/etc/shadow", "alice:$y$abc:1::::::\nbob:!:1::::::\n")
	return s
}

// on scripts a command, keyed by its argv joined with spaces. A key ending
// " *" matches any further arguments.
func (s *testSys) on(argv string, stdout string, code int) {
	s.commands[argv] = func(Cmd) Result { return Result{Stdout: stdout, Code: code} }
}

// path is where p is outside the test's root.
func (s *testSys) path(p string) string {
	return filepath.Join(s.root, p)
}

func (s *testSys) write(path, content string) {
	s.t.Helper()
	full := s.path(path)
	require.NoError(s.t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(s.t, os.WriteFile(full, []byte(content), 0o644))
}

func (s *testSys) read(path string) string {
	s.t.Helper()
	data, err := os.ReadFile(s.path(path))
	require.NoError(s.t, err)
	return string(data)
}

func (s *testSys) exists(path string) bool {
	_, err := os.Lstat(s.path(path))
	return err == nil
}

// checkApply checks r expecting drift, applies it, and checks it's then in
// sync, all within one run.
func checkApply(t *testing.T, sys Sys, r Resource) Change {
	t.Helper()
	ctx := withRunState(context.Background(), newRunState())
	change, err := r.Check(ctx, sys)
	require.NoError(t, err)
	require.False(t, change.InSync, "expected drift")
	require.NoError(t, r.Apply(ctx, sys))
	after, err := r.Check(ctx, sys)
	require.NoError(t, err)
	require.True(t, after.InSync, "still drifted: %s", after.Diff)
	return change
}
