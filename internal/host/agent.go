package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// Serve runs the agent protocol over the given streams until Bye or EOF.
func Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	// A dropped connection mustn't kill the agent part way through a
	// change; writes fail instead.
	signal.Ignore(syscall.SIGPIPE)

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	a := &agent{
		sys:        NewSys(),
		log:        systemLog(),
		executable: exe,
		exec:       syscall.Exec,
	}
	return a.serve(ctx, in, out)
}

// systemLog is where the agent records what it does, so there's a record on
// the host if the controller goes away. stdout is the protocol, so it falls
// back to stderr.
func systemLog() io.Writer {
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "sensible-agent")
	if err != nil {
		return os.Stderr
	}
	return w
}

type agent struct {
	sys        Sys
	log        io.Writer
	executable string
	exec       func(argv0 string, argv []string, envv []string) error
}

func (a *agent) serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sess := &session{agent: a, conn: NewConn(in, out), engine: &engine{sys: a.sys, log: a.log}}
	if err := a.hello(sess.conn); err != nil {
		return err
	}
	for {
		msg, err := sess.conn.Receive()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, ok := msg.(Bye); ok {
			return nil
		}
		if err := sess.handle(ctx, msg); err != nil {
			return err
		}
	}
}

// session is one connection to the controller. Its handlers return errors
// only when the session can't continue.
type session struct {
	agent  *agent
	conn   *Conn
	engine *engine
	// resources are from the last Check, ready for Apply.
	resources ResourceList
}

func (s *session) handle(ctx context.Context, msg any) error {
	switch msg := msg.(type) {
	case Upgrade:
		if err := s.agent.upgrade(msg.Binary); err != nil {
			_, _ = fmt.Fprintf(s.agent.log, "upgrade failed: %v\n", err)
			return s.conn.Send(Error{Message: "upgrading: " + err.Error()})
		}
		return nil
	case FactsRequest:
		facts, err := gatherFacts(ctx, s.agent.sys)
		if err != nil {
			return s.conn.Send(Error{Message: "gathering facts: " + err.Error()})
		}
		return s.conn.Send(FactsReply{Facts: facts})
	case Check:
		s.resources = msg.Resources
		failed, err := s.engine.check(ctx, s.resources, func(c Checked) error { return s.conn.Send(c) })
		if err != nil {
			return err
		}
		return s.conn.Send(Done{Failed: failed})
	case Apply:
		return s.apply(ctx)
	default:
		return s.conn.Send(Error{Message: fmt.Sprintf("unexpected %T", msg)})
	}
}

func (s *session) apply(ctx context.Context) error {
	if s.resources == nil {
		return s.conn.Send(Error{Message: "apply without a check"})
	}
	failed, err := s.engine.apply(ctx, s.resources, s.conn.Send)
	s.resources = nil
	if err == nil {
		err = s.conn.Send(Done{Failed: failed})
	}
	if err != nil {
		_, _ = fmt.Fprintf(s.agent.log, "exiting after losing the connection to the controller: %v\n", err)
	}
	return err
}

func (a *agent) hello(conn *Conn) error {
	data, err := os.ReadFile(a.executable)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	return conn.Send(Hello{Proto: ProtocolVersion, Hash: hex.EncodeToString(sum[:]), Arch: runtime.GOARCH})
}

// upgrade replaces the executable and re-execs it, so only returns if that
// fails. The old binary stays in place until the new one is complete.
func (a *agent) upgrade(binary []byte) error {
	tmp := a.executable + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := f.Write(binary); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, a.executable); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(a.executable))
	_, _ = fmt.Fprintf(a.log, "upgraded %s; re-executing\n", a.executable)
	return a.exec(a.executable, os.Args, os.Environ())
}

func gatherFacts(ctx context.Context, sys Sys) (Facts, error) {
	osRelease, err := sys.ReadFile("/etc/os-release")
	if err != nil {
		return Facts{}, err
	}
	family, release, err := parseOSRelease(string(osRelease))
	if err != nil {
		return Facts{}, err
	}
	uname, err := runOK(ctx, sys, argv("uname", "-m"))
	if err != nil {
		return Facts{}, err
	}
	return Facts{
		OSFamily:    family,
		Release:     release,
		Arch:        strings.TrimSpace(uname.Stdout),
		DefaultIPv4: defaultSource(ctx, sys, "-4", "1.1.1.1"),
		DefaultIPv6: defaultSource(ctx, sys, "-6", "2606:4700:4700::1111"),
	}, nil
}

// defaultSource returns the address the host would send from to reach dest,
// or "" if it has no route. Nothing is sent.
func defaultSource(ctx context.Context, sys Sys, family, dest string) string {
	res, err := runOK(ctx, sys, argv("ip", "-j", family, "route", "get", dest))
	if err != nil {
		return ""
	}
	var routes []struct {
		PrefSrc string `json:"prefsrc"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &routes); err != nil || len(routes) == 0 {
		return ""
	}
	return routes[0].PrefSrc
}
