package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"filippo.io/age/armor"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"chameth.com/sensible/internal/config"
	"chameth.com/sensible/internal/features"
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
		targets[i] = newTarget(repo, name)
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

// RenderOptions select the hosts for Render and how to show them.
type RenderOptions struct {
	ConfigDir string
	// Hosts limits the render to these inventory names. Empty means all
	// hosts.
	Hosts []string
	// FactsFile holds the hosts' facts as Facts prints them. Empty means
	// connecting to the hosts for them.
	FactsFile string
	JSON      bool
}

// Render prints what apply would make the selected hosts have, without
// changing anything. Secrets that can't be decrypted, and generated values
// that haven't been saved, are shown as placeholders.
func Render(ctx context.Context, opts RenderOptions, out io.Writer) error {
	repo, err := openRepo(opts.ConfigDir, os.Stderr)
	if err != nil {
		return err
	}
	if opts.FactsFile == "" {
		if err := repo.LoadIdentity(); err != nil {
			return fmt.Errorf("%w; use --facts to render without connecting", err)
		}
	}
	stderr := newRenderer(os.Stderr)
	repo.Preview(func(msg string) { stderr.line(stderr.p.warning(msg)...) })
	names, err := selectHosts(repo.Inventory(), opts.Hosts)
	if err != nil {
		return err
	}

	var facts map[string]host.Facts
	if opts.FactsFile != "" {
		if facts, err = readFacts(opts.FactsFile); err != nil {
			return err
		}
	}
	builder := NewEmbeddedBuilds()
	targets := make([]target, len(names))
	for i, name := range names {
		if facts == nil {
			targets[i] = newTarget(repo, name)
		} else {
			targets[i] = previewTarget(repo, name)
		}
	}
	r := &Runner{Out: os.Stderr, Builds: builder, Compile: compiler(repo)}
	return r.Render(ctx, targets, facts, out, opts.JSON)
}

func readFacts(file string) (map[string]host.Facts, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	facts := map[string]host.Facts{}
	if err := json.Unmarshal(b, &facts); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return facts, nil
}

// previewTarget is a target that won't be connected to, so it needs only
// the public half of its key, which is a placeholder if the key can't be
// decrypted.
func previewTarget(repo *config.Repo, name string) target {
	entry := repo.Inventory().Hosts[name]
	t := target{name: name, dnsName: entry.DNSName}
	if entry.SSHKey.IsZero() {
		t.err = fmt.Errorf("no credentials; run `sensible bootstrap %s`", name)
		return t
	}
	key, err := entry.SSHKey.Reveal()
	if err != nil {
		t.err = fmt.Errorf("ssh_key: %w", err)
		return t
	}
	if key == entry.SSHKey.Placeholder() {
		t.sensibleKey = key + " " + features.SensibleUser + "@" + name
		return t
	}
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		t.err = fmt.Errorf("ssh_key: %w", err)
		return t
	}
	t.sensibleKey = authorizedKey(signer.PublicKey(), name)
	return t
}

// Render writes each target's resources to out. Their facts come from
// facts, or from connecting to them if it's nil.
func (r *Runner) Render(
	ctx context.Context,
	targets []target,
	facts map[string]host.Facts,
	out io.Writer,
	asJSON bool,
) error {
	var runs []*hostRun
	if facts == nil {
		runs = r.connect(ctx, targets)
		newRenderer(r.Out).agents(runs)
		byeAll(runs)
	} else {
		for _, t := range targets {
			h := &hostRun{target: t}
			if f, ok := facts[t.name]; ok {
				h.facts = f
			} else if h.err == nil {
				h.err = errors.New("no facts for this host")
			}
			runs = append(runs, h)
		}
	}

	status := newRenderer(r.Out)
	rendered := map[string][]map[string]any{}
	var text strings.Builder
	for _, h := range runs {
		if h.err == nil {
			var c compiled
			c, h.err = r.Compile(h.target, h.facts)
			h.resources = c.resources
		}
		if h.err != nil {
			status.line(status.p.failure(h.name + ": " + h.err.Error())...)
			continue
		}
		if asJSON {
			entries, err := resourceEntries(h.resources)
			if err != nil {
				return err
			}
			rendered[h.name] = entries
		} else {
			writeResources(&text, h.name, h.resources)
		}
	}

	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(rendered); err != nil {
			return err
		}
	} else if _, err := io.WriteString(out, text.String()); err != nil {
		return err
	}
	return failedErr(anyFailed(runs))
}

// resourceEntries are the resources as JSON objects, each with its type
// and ID alongside its fields.
func resourceEntries(resources host.ResourceList) ([]map[string]any, error) {
	entries := make([]map[string]any, 0, len(resources))
	for _, res := range resources {
		fields, err := resourceFields(res)
		if err != nil {
			return nil, err
		}
		fields["type"] = reflect.TypeOf(res).Name()
		fields["id"] = res.ID()
		entries = append(entries, fields)
	}
	return entries, nil
}

func resourceFields(res host.Resource) (map[string]any, error) {
	b, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{}
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// writeResources writes a host's resources, files and directories with
// their ownership and content, and the rest one line each.
func writeResources(w *strings.Builder, name string, resources host.ResourceList) {
	if w.Len() > 0 {
		w.WriteString("\n")
	}
	w.WriteString(name + "\n")
	for _, res := range resources {
		switch res := res.(type) {
		case host.File:
			w.WriteString(itemIndent + displayID(res.ID()) + "  " + ownership(res.Owner, res.Group, res.Mode) + "\n")
			if len(res.Validate) > 0 {
				w.WriteString(itemIndent + "  validate: " + strings.Join(res.Validate, " ") + "\n")
			}
			for _, n := range res.Notify {
				w.WriteString(itemIndent + "  then " + displayID(n.ID()) + "\n")
			}
			for line := range strings.Lines(res.Content) {
				w.WriteString(itemIndent + "  | " + strings.TrimSuffix(line, "\n") + "\n")
			}
			if res.Content != "" && !strings.HasSuffix(res.Content, "\n") {
				w.WriteString(itemIndent + "  \\ No newline at end of file\n")
			}
		case host.Dir:
			w.WriteString(itemIndent + displayID(res.ID()) + "  " + ownership(res.Owner, res.Group, res.Mode) + "\n")
		default:
			w.WriteString(itemIndent + resourceLine(res) + "\n")
		}
	}
}

// resourceLine is the resource's ID followed by those of its fields the ID
// doesn't already show.
func resourceLine(res host.Resource) string {
	id := res.ID()
	fields, err := resourceFields(res)
	if err != nil {
		return displayID(id) + "  " + err.Error()
	}
	for k, v := range fields {
		if s, ok := v.(string); ok && strings.Contains(":"+id+":", ":"+s+":") {
			delete(fields, k)
		}
		if k == "mode" {
			if m, ok := v.(float64); ok {
				fields[k] = fmt.Sprintf("%04o", int(m))
			}
		}
	}
	if len(fields) == 0 {
		return displayID(id)
	}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fields); err != nil {
		return displayID(id) + "  " + err.Error()
	}
	return displayID(id) + "  " + strings.TrimSuffix(b.String(), "\n")
}

func ownership(owner, group string, mode fs.FileMode) string {
	if owner == "" {
		owner = "-"
	}
	if group == "" {
		group = "-"
	}
	m := "-"
	if mode != 0 {
		m = fmt.Sprintf("%04o", mode.Perm())
	}
	return owner + ":" + group + " " + m
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
// e.g. "dns.mydnshost.auth_key" in "sensible.yml". With no path, it lists
// the paths instead, which doesn't need the identity, or decrypts the file
// if it's a whole-file secret. Relative files are in the config directory.
func ShowSecret(configDir, file, path string, out io.Writer) error {
	file = configFile(configDir, file)
	content, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if bytes.HasPrefix(content, []byte(armor.Header)) {
		if path != "" {
			return fmt.Errorf("%s is a whole-file secret, so has no paths", file)
		}
		plaintext, err := decryptFile(configDir, string(content))
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, plaintext)
		return err
	}
	if path == "" {
		return listSecrets(file, content, out)
	}
	armored, err := secretAt(file, content, path)
	if err != nil {
		return err
	}
	plaintext, err := decryptFile(configDir, armored)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, plaintext)
	return err
}

func listSecrets(file string, content []byte, out io.Writer) error {
	secrets, err := secretsIn(file, content)
	if err != nil {
		return err
	}
	for _, s := range secrets {
		if _, err := fmt.Fprintln(out, s.path); err != nil {
			return err
		}
	}
	return nil
}

func decryptFile(configDir, armored string) (string, error) {
	repo, err := config.Open(configDir, nil)
	if err != nil {
		return "", err
	}
	return repo.DecryptFile(armored)
}

func configFile(configDir, file string) string {
	if filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(configDir, file)
}

func secretAt(file string, content []byte, path string) (string, error) {
	secrets, err := secretsIn(file, content)
	if err != nil {
		return "", err
	}
	for _, s := range secrets {
		if s.path == path {
			return s.armored, nil
		}
	}
	return "", fmt.Errorf("%s: no !age value at %s", file, path)
}

type fileSecret struct {
	path    string
	armored string
}

func secretsIn(file string, content []byte) ([]fileSecret, error) {
	parsed, err := parser.ParseBytes(content, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var secrets []fileSecret
	for _, doc := range parsed.Docs {
		secrets = appendSecrets(secrets, doc.Body, "")
	}
	return secrets, nil
}

func appendSecrets(secrets []fileSecret, node ast.Node, path string) []fileSecret {
	switch n := node.(type) {
	case *ast.TagNode:
		if n.Start.Value != "!age" {
			return appendSecrets(secrets, n.Value, path)
		}
		switch v := n.Value.(type) {
		case *ast.StringNode:
			return append(secrets, fileSecret{path, v.Value})
		case *ast.LiteralNode:
			return append(secrets, fileSecret{path, v.Value.Value})
		default:
		}
	case *ast.AnchorNode:
		return appendSecrets(secrets, n.Value, path)
	case *ast.MappingNode:
		for _, mv := range n.Values {
			secrets = appendSecrets(secrets, mv, path)
		}
	case *ast.MappingValueNode:
		key := pathKey(n.Key.GetToken().Value)
		if path != "" {
			key = path + "." + key
		}
		return appendSecrets(secrets, n.Value, key)
	case *ast.SequenceNode:
		for i, item := range n.Values {
			secrets = appendSecrets(secrets, item, fmt.Sprintf("%s[%d]", path, i))
		}
	default:
	}
	return secrets
}

// pathKey quotes a mapping key that a path couldn't otherwise tell apart from
// nested keys, such as a host named acidburn.example.com.
func pathKey(key string) string {
	if !strings.ContainsAny(key, ".[]'\\") {
		return key
	}
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(key) + "'"
}
