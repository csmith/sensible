package run

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync"
)

//go:generate go run gen_agents.go amd64 arm64

var agentArchs = []string{"amd64", "arm64"}

// Build is an agent binary for one architecture.
type Build struct {
	Binary []byte
	// Hash is the hex SHA-256 of the binary, as the agent reports in Hello.
	Hash string
}

// EmbeddedBuilds provides the agents embedded in this binary by go generate.
type EmbeddedBuilds struct {
	files fs.FS

	mu     sync.Mutex
	builds map[string]Build
}

func NewEmbeddedBuilds() *EmbeddedBuilds {
	return &EmbeddedBuilds{files: agentFiles, builds: map[string]Build{}}
}

// Build returns the agent for GOOS=linux and the given GOARCH.
func (e *EmbeddedBuilds) Build(_ context.Context, goarch string) (Build, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if build, ok := e.builds[goarch]; ok {
		return build, nil
	}

	f, err := e.files.Open("agents/linux-" + goarch + ".gz")
	if errors.Is(err, fs.ErrNotExist) {
		return Build{}, fmt.Errorf("no agent for %s in this binary (run go generate before building)", goarch)
	} else if err != nil {
		return Build{}, err
	}
	defer func() { _ = f.Close() }()
	r, err := gzip.NewReader(f)
	if err != nil {
		return Build{}, fmt.Errorf("reading %s agent: %w", goarch, err)
	}
	binary, err := io.ReadAll(r)
	if err != nil {
		return Build{}, fmt.Errorf("reading %s agent: %w", goarch, err)
	}

	sum := sha256.Sum256(binary)
	build := Build{Binary: binary, Hash: hex.EncodeToString(sum[:])}
	e.builds[goarch] = build
	return build, nil
}
