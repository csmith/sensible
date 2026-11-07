package host

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certRun checks and applies a cert's resources for each of certs, by name
// and directory, then the clean-up, as a whole run on the host would.
func certRun(t *testing.T, sys Sys, certs map[string]string) string {
	t.Helper()
	list := make(ResourceList, 0, 3*len(certs)+1)
	for name, dir := range certs {
		path := dir + "/tls.key"
		list = append(
			list,
			CertRecord{Name: name, Paths: []string{path}},
			Dir{Path: dir},
			File{Path: path, Content: name + "\n", Mode: 0o600},
		)
	}
	list = append(list, CertRecords{})

	var diff string
	e := &engine{sys: sys, log: io.Discard}
	failed, err := e.apply(
		context.Background(),
		list,
		-1,
		func(msg any) error {
			if applied, ok := msg.(Applied); ok && applied.ID == (CertRecords{}).ID() {
				diff = applied.Diff
			}
			return nil
		},
	)
	require.NoError(t, err)
	require.False(t, failed)
	return diff
}

func TestCertRecord_recordsPathsBeforeWriting(t *testing.T) {
	sys := newTestSys(t)
	r := CertRecord{Name: "api", Paths: []string{"/srv/certs/api/tls.crt", "/srv/certs/api/tls.key"}}

	change := checkApply(t, sys, r)

	assert.Contains(t, change.Diff, "/srv/certs/api/tls.key")
	assert.False(t, sys.exists("/srv/certs/api/tls.key"))
	var rec certRecord
	require.NoError(t, json.Unmarshal([]byte(sys.read(certRecordPath("api"))), &rec))
	assert.Equal(t, r.Paths, rec.Paths)
}

func TestCertRecords_keepsWhatsDeclared(t *testing.T) {
	sys := newTestSys(t)
	certRun(t, sys, map[string]string{"api": "/srv/certs/api"})

	assert.Empty(t, certRun(t, sys, map[string]string{"api": "/srv/certs/api"}))
	assert.Equal(t, "api\n", sys.read("/srv/certs/api/tls.key"))
}

func TestCertRecords_removesCertsThatAreGone(t *testing.T) {
	sys := newTestSys(t)
	certRun(t, sys, map[string]string{"api": "/srv/certs/api"})

	diff := certRun(t, sys, nil)

	assert.Contains(t, diff, "/srv/certs/api/tls.key")
	assert.False(t, sys.exists("/srv/certs/api"))
	assert.False(t, sys.exists(certRecordPath("api")))
}

func TestCertRecords_leavesOtherFilesInACustomDir(t *testing.T) {
	sys := newTestSys(t)
	sys.write("/home/alice/.config/tool/config.yml", "mine\n")
	certRun(t, sys, map[string]string{"tool": "/home/alice/.config/tool"})

	certRun(t, sys, nil)

	assert.False(t, sys.exists("/home/alice/.config/tool/tls.key"))
	assert.Equal(t, "mine\n", sys.read("/home/alice/.config/tool/config.yml"))
}

func TestCertRecords_movesWithItsDir(t *testing.T) {
	sys := newTestSys(t)
	certRun(t, sys, map[string]string{"api": "/old/certs"})

	certRun(t, sys, map[string]string{"api": "/new/certs"})

	assert.False(t, sys.exists("/old/certs"))
	assert.Equal(t, "api\n", sys.read("/new/certs/tls.key"))

	var rec certRecord
	require.NoError(t, json.Unmarshal([]byte(sys.read(certRecordPath("api"))), &rec))
	assert.Equal(t, []string{"/new/certs/tls.key"}, rec.Paths)
}

func TestCertRecords_renamedCertKeepsItsFiles(t *testing.T) {
	sys := newTestSys(t)
	certRun(t, sys, map[string]string{"old": "/srv/certs/shared"})

	certRun(t, sys, map[string]string{"new": "/srv/certs/shared"})

	assert.Equal(t, "new\n", sys.read("/srv/certs/shared/tls.key"))
	assert.False(t, sys.exists(certRecordPath("old")))
}

func TestCertRecords_swappedDirs(t *testing.T) {
	sys := newTestSys(t)
	certRun(t, sys, map[string]string{"a": "/certs/one", "b": "/certs/two"})

	certRun(t, sys, map[string]string{"a": "/certs/two", "b": "/certs/one"})

	assert.Equal(t, "a\n", sys.read("/certs/two/tls.key"))
	assert.Equal(t, "b\n", sys.read("/certs/one/tls.key"))
}

func TestCertRecords_checkChangesNothing(t *testing.T) {
	sys := newTestSys(t)
	certRun(t, sys, map[string]string{"api": "/srv/certs/api"})

	change, err := CertRecords{}.Check(withRunState(context.Background(), newRunState()), sys)
	require.NoError(t, err)

	assert.False(t, change.InSync)
	assert.Contains(t, change.Diff, "remove /srv/certs/api/tls.key")
	assert.True(t, sys.exists("/srv/certs/api/tls.key"))
}

func TestCertRecords_nothingRecorded(t *testing.T) {
	change, err := CertRecords{}.Check(withRunState(context.Background(), newRunState()), newTestSys(t))
	require.NoError(t, err)
	assert.True(t, change.InSync)
}

func TestCertRecords_skippedAfterAFailure(t *testing.T) {
	sys := newTestSys(t)
	certRun(t, sys, map[string]string{"api": "/srv/certs/api"})

	e := &engine{sys: sys, log: io.Discard}
	sys.on("false", "", 1)
	failed, err := e.apply(
		context.Background(),
		ResourceList{Command{Name: "fails", CheckArgv: []string{"false"}, ApplyArgv: []string{"false"}}, CertRecords{}},
		-1,
		func(any) error { return nil },
	)
	require.NoError(t, err)
	require.True(t, failed)
	assert.True(t, sys.exists("/srv/certs/api/tls.key"))
}
