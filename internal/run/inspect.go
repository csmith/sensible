package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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

// Facts prints a host's facts as its agent reports them.
func Facts(ctx context.Context, configDir, sourceDir, name, addr string, out io.Writer) error {
	repo, err := openRepo(configDir, os.Stderr)
	if err != nil {
		return err
	}
	facts, err := fetchFacts(ctx, repo, sourceDir, name, addr)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(facts)
}

func fetchFacts(ctx context.Context, repo *config.Repo, sourceDir, name, addr string) (host.Facts, error) {
	if _, ok := repo.Inventory().Hosts[name]; !ok {
		return host.Facts{}, unknownHost(repo.Inventory(), name)
	}
	builder, err := NewBuilder(sourceDir)
	if err != nil {
		return host.Facts{}, err
	}
	t := newTarget(repo, name, addr, builder)
	if t.err != nil {
		return host.Facts{}, t.err
	}
	a, _, err := connect(ctx, t.transport, builder)
	if err != nil {
		return host.Facts{}, err
	}
	defer a.bye()
	return a.facts()
}

// ShowConfig prints a host's merged configuration with secrets masked. The
// OS family picks the os/ layer; if it's empty, it's read from the host.
func ShowConfig(ctx context.Context, configDir, sourceDir, name, osFamily, addr string, out io.Writer) error {
	repo, err := openRepo(configDir, os.Stderr)
	if err != nil {
		return err
	}
	if osFamily == "" {
		facts, err := fetchFacts(ctx, repo, sourceDir, name, addr)
		if err != nil {
			return err
		}
		osFamily = facts.OSFamily
	}
	cfg, err := repo.HostConfig(name, osFamily)
	if err != nil {
		return err
	}
	text, err := yaml.Marshal(masked(reflect.ValueOf(cfg)))
	if err != nil {
		return err
	}
	_, err = out.Write(text)
	return err
}

var secretType = reflect.TypeFor[config.Secret]()

// masked converts a config value to plain YAML-ready data, in field order,
// leaving out empty values and replacing secrets with a placeholder.
func masked(v reflect.Value) any {
	if v.Type() == secretType {
		if v.Interface().(config.Secret).IsZero() {
			return nil
		}
		return "<secret>"
	}
	switch v.Kind() {
	case reflect.Struct:
		var m yaml.MapSlice
		for i := range v.NumField() {
			field := v.Type().Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if !field.IsExported() || name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			if value := masked(v.Field(i)); value != nil {
				m = append(m, yaml.MapItem{Key: name, Value: value})
			}
		}
		if len(m) == 0 {
			return nil
		}
		return m
	case reflect.Map:
		if v.Len() == 0 {
			return nil
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		var m yaml.MapSlice
		for _, k := range keys {
			m = append(m, yaml.MapItem{Key: k.Interface(), Value: orEmpty(masked(v.MapIndex(k)))})
		}
		return m
	case reflect.Slice:
		if v.Len() == 0 {
			return nil
		}
		items := make([]any, v.Len())
		for i := range items {
			items[i] = masked(v.Index(i))
		}
		return items
	default:
		if v.IsZero() && v.Kind() != reflect.Bool {
			return nil
		}
		return v.Interface()
	}
}

// orEmpty keeps map entries whose values are empty, as their keys matter.
func orEmpty(v any) any {
	if v == nil {
		return yaml.MapSlice{}
	}
	return v
}

// EncryptSecret encrypts in to secrets.yml's recipients and prints it as
// a !age scalar. One trailing newline is dropped, as `<<<` adds one.
func EncryptSecret(configDir string, in io.Reader, out io.Writer) error {
	repo, err := config.Open(configDir, nil)
	if err != nil {
		return err
	}
	plaintext, err := readSecret(in)
	if err != nil {
		return err
	}
	text, err := repo.Encrypt(plaintext)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, strings.TrimRight(text, "\n"))
	return err
}

// readSecret asks for the value without echoing it when in is a terminal,
// and otherwise reads all of in, dropping one trailing newline.
func readSecret(in io.Reader) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return passwordFromTerminal("Value to encrypt: ")
	}
	plaintext, err := io.ReadAll(in)
	return strings.TrimSuffix(string(plaintext), "\n"), err
}

// ShowSecret decrypts the !age value at a dotted path in a config file,
// e.g. "dns.auth_key" in "hosts/acidburn.yml". Relative files are in the
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
