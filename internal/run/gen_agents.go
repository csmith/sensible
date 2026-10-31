//go:build ignore

package main

import (
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// main builds the agent for each GOARCH given as an argument, writing them
// gzipped to agents/ for embedding.
func main() {
	for _, arch := range os.Args[1:] {
		if err := build(arch); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "building %s agent: %v\n", arch, err)
			os.Exit(1)
		}
	}
}

func build(arch string) error {
	tmp, err := os.MkdirTemp("", "sensible-agent-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	binary := filepath.Join(tmp, "sensible")
	cmd := exec.Command(
		"go",
		"build",
		"-tags",
		"agent",
		"-trimpath",
		"-ldflags",
		"-s -w",
		"-o",
		binary,
		"chameth.com/sensible/cmd/sensible",
	)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	content, err := os.ReadFile(binary)
	if err != nil {
		return err
	}

	out, err := os.CreateTemp("agents", ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(out.Name()) }()
	zw, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := zw.Write(content); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), filepath.Join("agents", "linux-"+arch+".gz"))
}
