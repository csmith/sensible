package run

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const modulePath = "chameth.com/sensible"

// Build is an agent binary for one architecture.
type Build struct {
	Path string
	// Hash is the hex SHA-256 of the binary, as the agent reports in Hello.
	Hash string
}

// Builder builds agents from the source checkout the tool runs from, caching
// them by the hash of their source.
type Builder struct {
	root     string
	cacheDir string

	mu     sync.Mutex
	builds map[string]Build
}

func NewBuilder() (*Builder, error) {
	root, err := moduleRoot()
	if err != nil {
		return nil, err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	return &Builder{
		root:     root,
		cacheDir: filepath.Join(cache, "sensible", "agents"),
		builds:   map[string]Build{},
	}, nil
}

// Build returns the agent for GOOS=linux and the given GOARCH, building it
// if the source has changed since it was last built.
func (b *Builder) Build(ctx context.Context, goarch string) (Build, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if build, ok := b.builds[goarch]; ok {
		return build, nil
	}

	version, err := b.goVersion(ctx)
	if err != nil {
		return Build{}, err
	}
	key, err := sourceKey(b.root, goarch, version)
	if err != nil {
		return Build{}, err
	}
	path := filepath.Join(b.cacheDir, key+"-"+goarch)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		if err := b.compile(ctx, goarch, path); err != nil {
			return Build{}, err
		}
	} else if err != nil {
		return Build{}, err
	}

	hash, err := fileHash(path)
	if err != nil {
		return Build{}, err
	}
	build := Build{Path: path, Hash: hash}
	b.builds[goarch] = build
	return build, nil
}

func (b *Builder) goVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "env", "GOVERSION")
	cmd.Dir = b.root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go env GOVERSION: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (b *Builder) compile(ctx context.Context, goarch, path string) error {
	if err := os.MkdirAll(b.cacheDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(b.cacheDir, ".build-*")
	if err != nil {
		return err
	}
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmp.Name()) }()

	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", tmp.Name(), "./cmd/sensible")
	cmd.Dir = b.root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("building agent for %s: %w\n%s", goarch, err, out)
	}
	return os.Rename(tmp.Name(), path)
}

// sourceKey hashes everything that goes into a build, other than tests.
func sourceKey(root, goarch, goVersion string) (string, error) {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00", goarch, goVersion)
	for _, file := range []string{"go.mod", "go.sum"} {
		if err := hashFile(h, root, file); err != nil {
			return "", err
		}
	}
	for _, dir := range []string{"cmd", "internal"} {
		if err := filepath.WalkDir(filepath.Join(root, dir), sourceHasher(h, root)); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sourceHasher(h io.Writer, root string) fs.WalkDirFunc {
	return func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		return hashFile(h, root, rel)
	}
}

func hashFile(h io.Writer, root, rel string) error {
	content, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(h, "%s\x00%d\x00", filepath.ToSlash(rel), len(content))
	_, _ = h.Write(content)
	return nil
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// moduleRoot finds the checkout the tool runs from. `go run` builds into a
// temporary directory, so the source file's own path is tried first, then
// the working directory and the executable's directory.
func moduleRoot() (string, error) {
	var starts []string
	if _, file, _, ok := runtime.Caller(0); ok && filepath.IsAbs(file) {
		starts = append(starts, filepath.Dir(file))
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	for _, dir := range starts {
		if root, ok := findModule(dir, modulePath); ok {
			return root, nil
		}
	}
	return "", fmt.Errorf("can't find the %s source checkout; run sensible from inside it", modulePath)
}

func findModule(dir, module string) (string, bool) {
	for {
		if content, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && moduleName(content) == module {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func moduleName(gomod []byte) string {
	s := bufio.NewScanner(bytes.NewReader(gomod))
	for s.Scan() {
		if name, ok := strings.CutPrefix(strings.TrimSpace(s.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(name), `"`)
		}
	}
	return ""
}
