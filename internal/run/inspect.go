package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"golang.org/x/term"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/host"
)

// Facts prints the selected hosts' facts, as their agents report them, as a
// JSON object keyed by host name. Empty hosts means all hosts. Progress and
// unreachable hosts are reported on stderr; the hosts that could be reached
// are still printed.
func Facts(ctx context.Context, configDir string, hosts []string, out io.Writer) error {
	repo, err := openRepo(configDir, os.Stderr)
	if err != nil {
		return err
	}
	names, err := selectHosts(repo.Inventory(), hosts)
	if err != nil {
		return err
	}
	builder := NewEmbeddedBuilds()
	targets := make([]target, len(names))
	for i, name := range names {
		targets[i] = newTarget(repo, name, builder)
	}
	r := &Runner{Out: os.Stderr, Builds: builder}
	return r.Facts(ctx, targets, out)
}

// Facts connects to the targets and writes the facts of those it reached
// to out.
func (r *Runner) Facts(ctx context.Context, targets []target, out io.Writer) error {
	runs := r.connect(ctx, targets)
	defer byeAll(runs)
	newRenderer(r.Out).agents(runs)

	facts := map[string]host.Facts{}
	for _, h := range runs {
		if h.err == nil {
			facts[h.name] = h.facts
		}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(facts); err != nil {
		return err
	}
	return failedErr(anyFailed(runs))
}

// EncryptSecret encrypts in to sensible.yml's recipients and prints it as
// a !age scalar. One trailing newline is dropped, as `<<<` adds one. If raw
// is set, it prints an armored age file instead, and keeps piped input as it
// is, as it's usually a whole file.
func EncryptSecret(configDir string, raw bool, in io.Reader, out io.Writer) error {
	repo, err := config.OpenSettings(configDir)
	if err != nil {
		return err
	}
	plaintext, err := readSecret(in, !raw)
	if err != nil {
		return err
	}
	encrypt := repo.Encrypt
	if raw {
		encrypt = repo.EncryptFile
	}
	text, err := encrypt(plaintext)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, strings.TrimRight(text, "\n"))
	return err
}

// readSecret asks for the value without echoing it when in is a terminal,
// and otherwise reads all of in, dropping one trailing newline if trim is
// set.
func readSecret(in io.Reader, trim bool) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return passwordFromTerminal("Value to encrypt: ")
	}
	plaintext, err := io.ReadAll(in)
	if trim {
		return strings.TrimSuffix(string(plaintext), "\n"), err
	}
	return string(plaintext), err
}

// ShowSecret decrypts the !age value at a dotted path in a config file,
// e.g. "dns.auth_key" in "sensible.yml". Relative files are in the
// config directory.
func ShowSecret(configDir, file, path string, out io.Writer) error {
	repo, err := config.Open(configDir, nil)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(file) {
		file = filepath.Join(configDir, file)
	}
	armored, err := secretAt(file, path)
	if err != nil {
		return err
	}
	identity, err := repo.CommandIdentity()()
	if err != nil {
		return err
	}
	plaintext, err := decrypt(armored, identity)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, plaintext)
	return err
}

func secretAt(file, path string) (string, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	parsed, err := parser.ParseBytes(content, 0)
	if err != nil {
		return "", err
	}
	p, err := yaml.PathString("$." + path)
	if err != nil {
		return "", fmt.Errorf("invalid path %q: %w", path, err)
	}
	node, err := p.FilterFile(parsed)
	if err != nil {
		return "", fmt.Errorf("%s: %s: %w", file, path, err)
	}
	tag, ok := node.(*ast.TagNode)
	if !ok || tag.Start.Value != "!age" {
		return "", fmt.Errorf("%s: %s isn't an !age value", file, path)
	}
	switch v := tag.Value.(type) {
	case *ast.StringNode:
		return v.Value, nil
	case *ast.LiteralNode:
		return v.Value.Value, nil
	default:
		return "", fmt.Errorf("%s: %s isn't an !age value", file, path)
	}
}

func decrypt(armored string, identity age.Identity) (string, error) {
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(strings.TrimSpace(armored)+"\n")), identity)
	if err != nil {
		return "", fmt.Errorf("decrypting: %w", err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("decrypting: %w", err)
	}
	return string(b), nil
}
