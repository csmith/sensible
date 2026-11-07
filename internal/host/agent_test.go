package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptedResource can cross the protocol, unlike fakeResource.
type scriptedResource struct {
	Name   string       `json:"name"`
	Drift  bool         `json:"drift"`
	Fail   string       `json:"fail"`
	Notify ResourceList `json:"notify"`
}

var (
	scriptedMutex   sync.Mutex
	scriptedApplied []string
)

func init() {
	resourceTypes["scriptedResource"] = reflect.TypeFor[scriptedResource]()
}

func (r scriptedResource) ID() string             { return "scripted:" + r.Name }
func (r scriptedResource) Notifies() ResourceList { return r.Notify }

func (r scriptedResource) Check(context.Context, Sys) (Change, error) {
	return Change{InSync: !r.Drift, Diff: "+ " + r.Name}, nil
}

func (r scriptedResource) Apply(context.Context, Sys) error {
	scriptedMutex.Lock()
	defer scriptedMutex.Unlock()
	scriptedApplied = append(scriptedApplied, r.Name)
	if r.Fail != "" {
		return errors.New(r.Fail)
	}
	return nil
}

type testAgent struct {
	agent    *agent
	ctrl     *Conn
	fromCtrl *io.PipeWriter
	toCtrl   *io.PipeReader
	done     chan error
	execed   []string
}

func startAgent(t *testing.T, execErr error) *testAgent {
	t.Helper()
	scriptedApplied = nil
	sys := newTestSys(t)
	sys.write("/etc/os-release", "ID=debian\nVERSION_CODENAME=trixie\n")
	sys.on("uname -m", "aarch64\n", 0)
	sys.on("ip -j -4 route get 1.1.1.1", `[{"dst":"1.1.1.1","gateway":"192.0.2.1","prefsrc":"192.0.2.10"}]`, 0)
	sys.on("ip -j -6 route get 2606:4700:4700::1111", "", 2)

	exe := filepath.Join(t.TempDir(), "sensible-agent")
	require.NoError(t, os.WriteFile(exe, []byte("old binary"), 0o755))

	ta := &testAgent{done: make(chan error, 1)}
	ta.agent = &agent{
		sys:        sys,
		log:        io.Discard,
		executable: exe,
		exec: func(argv0 string, _ []string, _ []string) error {
			ta.execed = append(ta.execed, argv0)
			return execErr
		},
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ta.fromCtrl, ta.toCtrl = inW, outR
	ta.ctrl = NewConn(outR, inW)
	go func() {
		err := ta.agent.serve(context.Background(), inR, outW)
		_ = outW.Close()
		ta.done <- err
	}()
	t.Cleanup(
		func() {
			_ = inW.Close()
			_ = outR.Close()
		},
	)
	return ta
}

func (ta *testAgent) receive(t *testing.T) any {
	t.Helper()
	msg, err := ta.ctrl.Receive()
	require.NoError(t, err)
	return msg
}

func TestServe_HelloFactsCheckApplyBye(t *testing.T) {
	ta := startAgent(t, nil)

	sum := sha256.Sum256([]byte("old binary"))
	assert.Equal(t, Hello{Proto: ProtocolVersion, Hash: hex.EncodeToString(sum[:]), Arch: runtime.GOARCH}, ta.receive(t))

	require.NoError(t, ta.ctrl.Send(FactsRequest{}))
	facts := ta.receive(t).(FactsReply).Facts
	assert.Equal(t, "debian", facts.OSFamily)
	assert.Equal(t, "trixie", facts.Release)
	assert.Equal(t, "aarch64", facts.Arch)
	assert.Equal(t, "192.0.2.10", facts.DefaultIPv4)
	assert.Empty(t, facts.DefaultIPv6)

	list := ResourceList{
		scriptedResource{Name: "a", Drift: true, Notify: ResourceList{scriptedResource{Name: "h"}}},
		scriptedResource{Name: "b"},
	}
	require.NoError(t, ta.ctrl.Send(Check{Resources: list}))
	assert.Equal(t, Checked{ID: "scripted:a", Status: StatusDrifted, Diff: "+ a"}, ta.receive(t))
	assert.Equal(t, Checked{ID: "scripted:b", Status: StatusInSync}, ta.receive(t))
	assert.Equal(t, Done{}, ta.receive(t))

	require.NoError(t, ta.ctrl.Send(Apply{}))
	assert.Equal(t, Applying{ID: "scripted:a"}, ta.receive(t))
	assert.Equal(t, Applied{ID: "scripted:a", Status: StatusChanged, Diff: "+ a"}, ta.receive(t))
	assert.Equal(t, Applied{ID: "scripted:b", Status: StatusInSync}, ta.receive(t))
	assert.Equal(t, Applying{ID: "scripted:h", Handler: true}, ta.receive(t))
	assert.Equal(t, Applied{ID: "scripted:h", Status: StatusChanged, Handler: true}, ta.receive(t))
	assert.Equal(t, Done{}, ta.receive(t))

	require.NoError(t, ta.ctrl.Send(Bye{}))
	assert.NoError(t, <-ta.done)
	assert.Equal(t, []string{"a", "h"}, scriptedApplied)
}

func TestServe_ApplyWithoutCheckIsAnError(t *testing.T) {
	ta := startAgent(t, nil)
	ta.receive(t)

	require.NoError(t, ta.ctrl.Send(Apply{}))
	assert.IsType(t, Error{}, ta.receive(t))

	require.NoError(t, ta.fromCtrl.Close())
	assert.NoError(t, <-ta.done, "EOF ends the session cleanly")
}

func TestServe_UpgradeReplacesAndExecs(t *testing.T) {
	ta := startAgent(t, nil)
	ta.receive(t)

	require.NoError(t, ta.ctrl.Send(Upgrade{Binary: []byte("new binary")}))
	require.NoError(t, ta.ctrl.Send(Bye{}))
	require.NoError(t, <-ta.done)

	assert.Equal(t, []string{ta.agent.executable}, ta.execed)
	data, err := os.ReadFile(ta.agent.executable)
	require.NoError(t, err)
	assert.Equal(t, "new binary", string(data))
	assert.NoFileExists(t, ta.agent.executable+".new")
}

func TestServe_FailedUpgradeKeepsServing(t *testing.T) {
	ta := startAgent(t, errors.New("exec format error"))
	ta.receive(t)

	require.NoError(t, ta.ctrl.Send(Upgrade{Binary: []byte("new binary")}))
	msg := ta.receive(t)
	require.IsType(t, Error{}, msg)
	assert.Contains(t, msg.(Error).Message, "exec format error")

	require.NoError(t, ta.ctrl.Send(FactsRequest{}))
	assert.IsType(t, FactsReply{}, ta.receive(t))
}

func TestServe_LostConnectionFinishesWithHandlers(t *testing.T) {
	ta := startAgent(t, nil)
	ta.receive(t)
	list := ResourceList{
		scriptedResource{Name: "a", Drift: true, Notify: ResourceList{scriptedResource{Name: "h"}}},
		scriptedResource{Name: "b", Drift: true},
	}
	require.NoError(t, ta.ctrl.Send(Check{Resources: list}))
	for range 3 {
		ta.receive(t)
	}

	require.NoError(t, ta.ctrl.Send(Apply{}))
	require.NoError(t, ta.toCtrl.Close())

	require.Error(t, <-ta.done)
	assert.Equal(t, []string{"a", "h"}, scriptedApplied)
}

func TestServe_PruneListsAndRemovesLeftovers(t *testing.T) {
	ta := startAgent(t, nil)
	ta.receive(t)
	sys := ta.agent.sys.(*testSys)
	sys.write("/srv/volumes/old/data/file", "")
	sys.write("/srv/volumes/older/data/file", "")

	require.NoError(t, ta.ctrl.Send(Check{Resources: ResourceList{Volumes{Path: "/srv/volumes"}}}))
	ta.receive(t)
	ta.receive(t)

	require.NoError(t, ta.ctrl.Send(Prune{}))
	assert.Equal(
		t,
		Leftovers{ID: "volumes:/srv/volumes", Items: []string{"/srv/volumes/old", "/srv/volumes/older"}},
		ta.receive(t),
	)
	assert.Equal(t, Done{}, ta.receive(t))

	require.NoError(t, ta.ctrl.Send(Remove{ID: "volumes:/srv/volumes", Item: "/srv/volumes/old"}))
	assert.Equal(t, Removed{ID: "volumes:/srv/volumes", Item: "/srv/volumes/old"}, ta.receive(t))
	assert.False(t, sys.exists("/srv/volumes/old"))
	assert.True(t, sys.exists("/srv/volumes/older/data/file"))

	require.NoError(t, ta.ctrl.Send(Remove{ID: "volumes:/srv/volumes", Item: "/etc"}))
	removed := ta.receive(t).(Removed)
	assert.Contains(t, removed.Error, "no longer a leftover")
	assert.True(t, sys.exists("/etc/os-release"))
}

func TestServe_PruneWithoutCheckIsAnError(t *testing.T) {
	ta := startAgent(t, nil)
	ta.receive(t)

	require.NoError(t, ta.ctrl.Send(Prune{}))
	assert.IsType(t, Error{}, ta.receive(t))
}
