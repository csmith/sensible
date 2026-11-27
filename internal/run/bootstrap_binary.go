package run

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"chameth.com/x/file"
	"golang.org/x/crypto/ssh"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/features"
)

type BootstrapBinaryOptions struct {
	ConfigDir string
	Output    string
	// Arch is the GOARCH to build for.
	Arch string
}

// BootstrapBinary writes an agent with the repo's bootstrap key embedded,
// making the key first if there isn't one. Run as root on a new host, it
// sets the host up for bootstrap with --bootstrap-key. Nothing in it is
// specific to a host, and the same key gives the same binary.
func BootstrapBinary(ctx context.Context, opts BootstrapBinaryOptions) error {
	if !slices.Contains(agentArchs, opts.Arch) {
		return fmt.Errorf("unsupported architecture %q; use one of %s", opts.Arch, strings.Join(agentArchs, ", "))
	}
	repo, err := openRepo(opts.ConfigDir, os.Stdout)
	if err != nil {
		return err
	}
	if err := writeBootstrapBinary(ctx, repo, NewEmbeddedBuilds(), opts.Arch, opts.Output); err != nil {
		return err
	}
	_, _ = fmt.Printf(
		"Wrote %s. Run it as root on a new host, then bootstrap the host with --bootstrap-key.\n",
		opts.Output,
	)
	return nil
}

func writeBootstrapBinary(ctx context.Context, repo *config.Repo, builds Builds, arch, path string) error {
	key := repo.BootstrapKey()
	if key.PublicKey == "" {
		creds, err := newKey(bootstrapKeyName)
		if err != nil {
			return err
		}
		if err := repo.SaveBootstrapKey(creds.authorizedKey, creds.keyPEM); err != nil {
			return err
		}
		key = repo.BootstrapKey()
		_, _ = fmt.Printf("Made a bootstrap key: %s\n", key.PublicKey)
	}
	build, err := builds.Build(ctx, arch)
	if err != nil {
		return err
	}
	return file.Write(path, withBootstrapKey(build.Binary, key.PublicKey), 0o755)
}

const bootstrapKeyName = "bootstrap"

func revealBootstrapKey(key config.BootstrapKey) (credentials, error) {
	pem, err := key.SSHKey.Reveal()
	if err != nil {
		return credentials{}, fmt.Errorf("bootstrap key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(pem))
	if err != nil {
		return credentials{}, fmt.Errorf("bootstrap key: %w", err)
	}
	return credentials{
		keyPEM:        pem,
		signer:        signer,
		authorizedKey: authorizedKey(signer.PublicKey(), bootstrapKeyName),
	}, nil
}

// bootstrapTrailer ends a bootstrap binary, after the key and the key's
// length as a big-endian uint64. ELF loaders ignore what follows the
// sections, so the binary runs as it is.
const bootstrapTrailer = "\x00sensible-bootstrap-key\x00"

func withBootstrapKey(agent []byte, key string) []byte {
	out := slices.Concat(agent, []byte(key))
	out = binary.BigEndian.AppendUint64(out, uint64(len(key)))
	return append(out, bootstrapTrailer...)
}

// splitBootstrapBinary returns the agent and key in a bootstrap binary, or
// ok false for any other file.
func splitBootstrapBinary(data []byte) (agent []byte, key string, ok bool) {
	rest, found := bytes.CutSuffix(data, []byte(bootstrapTrailer))
	if !found || len(rest) < 8 {
		return nil, "", false
	}
	n := binary.BigEndian.Uint64(rest[len(rest)-8:])
	rest = rest[:len(rest)-8]
	if n > uint64(len(rest)) {
		return nil, "", false
	}
	cut := len(rest) - int(n)
	return rest[:cut], string(rest[cut:]), true
}

// IsBootstrapBinary reports whether this executable was written by
// BootstrapBinary. Only its end is read, as it's checked on every run
// without a command.
func IsBootstrapBinary() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	f, err := os.Open(exe)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || info.Size() < int64(len(bootstrapTrailer)) {
		return false
	}
	tail := make([]byte, len(bootstrapTrailer))
	if _, err := f.ReadAt(tail, info.Size()-int64(len(tail))); err != nil {
		return false
	}
	return string(tail) == bootstrapTrailer
}

// SetUpForBootstrapKey sets up the machine this bootstrap binary runs on as
// bootstrap does, for the key embedded in it, and prints the host keys to
// check when bootstrapping it from the controller.
func SetUpForBootstrapKey(ctx context.Context, out io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("run this as root")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	agent, key, ok := splitBootstrapBinary(data)
	if !ok {
		return errors.New("this isn't a bootstrap binary")
	}

	tmp, err := os.CreateTemp("", "sensible-agent-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(agent); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	sum := sha256.Sum256(agent)

	cmd := exec.CommandContext(ctx, "sh", "-s")
	cmd.Stdin = strings.NewReader(
		setupScript{
			AgentTmp:   tmp.Name(),
			AgentHash:  hex.EncodeToString(sum[:]),
			Access:     features.BootstrapAccessFiles(key),
			EnsureSSHD: true,
		}.String(),
	)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running setup: %w", err)
	}

	keys, err := readHostKeys(filepath.Dir(localHostKeyPath))
	if err != nil {
		return err
	}
	name, _ := os.Hostname()
	name, _, _ = strings.Cut(name, ".")
	if name == "" {
		name = "<host>"
	}
	_, _ = fmt.Fprintf(out, "\nThis machine is ready for sensible. Its host keys are:\n")
	for _, k := range keys {
		_, _ = fmt.Fprintf(out, "  %-20s %s\n", k.Type(), ssh.FingerprintSHA256(k))
	}
	_, _ = fmt.Fprintf(out, "\nOn the controller, add it to hosts.d with its address, then run:\n")
	_, _ = fmt.Fprintf(
		out,
		"  sensible bootstrap %s --bootstrap-key --host-key %s\n",
		name,
		ssh.FingerprintSHA256(keys[0]),
	)
	return nil
}

// readHostKeys reads the host's public keys from dir, ed25519 first, as
// that's the one bootstrap asks for.
func readHostKeys(dir string) ([]ssh.PublicKey, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "ssh_host_*_key.pub"))
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		// Types sensible can't parse, such as ML-DSA, can't be used to
		// connect either.
		if key, _, _, _, err := ssh.ParseAuthorizedKey(data); err == nil {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no host keys in %s", dir)
	}
	rank := func(k ssh.PublicKey) int {
		if i := slices.Index(preferredHostKeyAlgorithms, k.Type()); i >= 0 {
			return i
		}
		return len(preferredHostKeyAlgorithms)
	}
	slices.SortStableFunc(keys, func(a, b ssh.PublicKey) int { return rank(a) - rank(b) })
	return keys, nil
}
