package run

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindModule(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/tool\n\ngo 1.27\n")
	writeFile(t, filepath.Join(root, "nested", "go.mod"), "module example.com/other\n")
	deep := filepath.Join(root, "nested", "a", "b")
	require.NoError(t, os.MkdirAll(deep, 0o700))

	found, ok := findModule(deep, "example.com/tool")
	assert.True(t, ok)
	assert.Equal(t, root, found)

	_, ok = findModule(deep, "example.com/missing")
	assert.False(t, ok)
}

func TestSourceKey(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/tool\n")
	writeFile(t, filepath.Join(root, "go.sum"), "")
	writeFile(t, filepath.Join(root, "cmd", "tool", "main.go"), "package main\n")
	writeFile(t, filepath.Join(root, "internal", "x", "x_test.go"), "package x\n")
	writeFile(t, filepath.Join(root, "config", "hosts.yml"), "hosts: {}\n")

	key := func() string {
		k, err := sourceKey(root, "amd64", "go1.27")
		require.NoError(t, err)
		return k
	}
	original := key()

	writeFile(t, filepath.Join(root, "internal", "x", "x_test.go"), "package x\n// changed\n")
	writeFile(t, filepath.Join(root, "config", "hosts.yml"), "hosts: {a: {}}\n")
	assert.Equal(t, original, key(), "tests and config don't affect the build")

	writeFile(t, filepath.Join(root, "internal", "x", "zshrc.tmpl"), "embedded")
	assert.NotEqual(t, original, key())

	other, err := sourceKey(root, "arm64", "go1.27")
	require.NoError(t, err)
	assert.NotEqual(t, key(), other)
}

func TestBuilder_buildsAndCachesAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the whole tool")
	}
	root, err := moduleRoot()
	require.NoError(t, err)
	b := &Builder{root: root, cacheDir: t.TempDir(), builds: map[string]Build{}}

	build, err := b.Build(t.Context(), "arm64")
	require.NoError(t, err)
	hash, err := fileHash(build.Path)
	require.NoError(t, err)
	assert.Equal(t, hash, build.Hash)

	fresh := &Builder{root: root, cacheDir: b.cacheDir, builds: map[string]Build{}}
	again, err := fresh.Build(t.Context(), "arm64")
	require.NoError(t, err)
	assert.Equal(t, build, again)
}

func TestSourceRoot(t *testing.T) {
	root, err := moduleRoot()
	require.NoError(t, err)

	got, err := sourceRoot(root)
	require.NoError(t, err)
	assert.Equal(t, root, got)

	_, err = sourceRoot(t.TempDir())
	require.ErrorContains(t, err, "isn't the "+modulePath+" source checkout")
}
