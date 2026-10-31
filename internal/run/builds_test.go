package run

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmbeddedBuilds_decompressesAndHashesAgent(t *testing.T) {
	binary := []byte("arm64 agent")
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, err := zw.Write(binary)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	e := &EmbeddedBuilds{
		files:  fstest.MapFS{"agents/linux-arm64.gz": {Data: compressed.Bytes()}},
		builds: map[string]Build{},
	}

	build, err := e.Build(t.Context(), "arm64")
	require.NoError(t, err)
	sum := sha256.Sum256(binary)
	assert.Equal(t, Build{Binary: binary, Hash: hex.EncodeToString(sum[:])}, build)

	_, err = e.Build(t.Context(), "amd64")
	require.ErrorContains(t, err, "no agent for amd64")
}

func TestEmbeddedBuilds_agentsMatchTheirArch(t *testing.T) {
	machines := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}
	e := NewEmbeddedBuilds()
	for _, arch := range agentArchs {
		if _, err := fs.Stat(e.files, "agents/linux-"+arch+".gz"); errors.Is(err, fs.ErrNotExist) {
			t.Skipf("no %s agent embedded; run go generate ./...", arch)
		}
		build, err := e.Build(t.Context(), arch)
		require.NoError(t, err)
		f, err := elf.NewFile(bytes.NewReader(build.Binary))
		require.NoError(t, err)
		assert.Equal(t, machines[arch], f.Machine, arch)
		assert.Equal(t, elf.ET_EXEC, f.Type, arch)
	}
}

func TestExtractAgent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agents")
	build := Build{Binary: []byte("agent"), Hash: "abc123"}

	path, err := extractAgent(dir, build)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "abc123"), path)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, build.Binary, content)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	require.NoError(t, os.WriteFile(path, []byte("upgraded in place"), 0o700))
	again, err := extractAgent(dir, build)
	require.NoError(t, err)
	assert.Equal(t, path, again)
	content, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("upgraded in place"), content, "an existing copy is reused")
}
