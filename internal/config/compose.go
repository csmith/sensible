package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"filippo.io/age/armor"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"

	"chameth.com/sensible/internal/host"
)

const (
	// StacksDir holds each stack's files, in a directory named after it.
	StacksDir = "/srv/compose"
	// VolumesDir holds the volumes each role declares, in a directory named
	// as the role's stack would be.
	VolumesDir = "/srv/volumes"
)

const (
	volumeTag = "!volume"
	ageSuffix = ".age"
)

// Stack is a Docker Compose project, from a role with a docker-compose.yml.
type Stack struct {
	// Name is the role's name with "/" replaced by "-". It's also the
	// project's name.
	Name string
	// Files are the stack's files, including docker-compose.yml, with
	// secrets decrypted.
	Files []StackFile
	// Dirs are the directories within listed directories, by path relative
	// to the stack's directory. Other directories are root:docker 0750.
	Dirs map[string]Perms
}

func (s Stack) Dir() string {
	return filepath.Join(StacksDir, s.Name)
}

type StackFile struct {
	// Path is relative to the stack's directory.
	Path    string
	Content string
	Perms   Perms
	// Secrets are decrypted values within Content.
	Secrets []string
	// Hidden is set when all of Content is secret.
	Hidden bool
}

type Perms struct {
	// Owner and Group are names or numeric IDs. An empty Group means the
	// owner's primary group if Owner is a name, and is otherwise left alone.
	Owner string      `yaml:"owner"`
	Group string      `yaml:"group"`
	Mode  fs.FileMode `yaml:"mode"`
}

// Volume is a directory a role declares in compose.volumes, for its own
// stack or its children's to mount with !volume. Sensible manages the
// directory itself but never its contents.
type Volume struct {
	Path string
	Perms
}

// fileEntry is one of compose.files: a path, or a mapping that also sets
// its files' ownership and mode.
type fileEntry struct {
	Path string `yaml:"path"`
	Perms
}

func (e *fileEntry) UnmarshalYAML(ctx context.Context, node ast.Node) error {
	if s, ok := node.(*ast.StringNode); ok {
		*e = fileEntry{Path: s.Value}
		return nil
	}
	var v struct {
		Path  string `yaml:"path"`
		Perms `yaml:",inline"`
	}
	if err := decode(ctx, node, &v); err != nil {
		return err
	}
	if v.Path == "" {
		return nodeError(node, "a file needs a path")
	}
	*e = fileEntry(v)
	return nil
}

// filePerms fills in the defaults for a stack's files, root:docker 0640.
func filePerms(p Perms) Perms {
	if p.Owner == "" {
		p.Owner = "root"
		if p.Group == "" {
			p.Group = "docker"
		}
	}
	if p.Mode == 0 {
		p.Mode = 0o640
	}
	return p
}

// dirPerms is p for a directory, searchable wherever it's readable.
func dirPerms(p Perms) Perms {
	p.Mode |= (p.Mode & 0o444) >> 2
	return p
}

// stackDef is what a stack's role declares.
type stackDef struct {
	role string
	name string
	// files are the paths of every file to copy, relative to the role's
	// directory, excluding the compose file.
	files []string
	// perms are each file's ownership and mode, by its path in files.
	perms map[string]Perms
	dirs  map[string]Perms
}

// roleSettings are the keys in a role's role.yml that apply to the role
// alone, rather than being merged into its hosts' config.
type roleSettings struct {
	Children []string `yaml:"children"`
	Compose  *struct {
		Files   []fileEntry      `yaml:"files"`
		Volumes map[string]Perms `yaml:"volumes"`
	} `yaml:"compose"`
}

var roleSettingKeys = []string{"children", "compose"}

func (r *Repo) readRoleSettings(role string) (roleSettings, error) {
	file := filepath.Join("roles", role, "role.yml")
	node, err := r.readLayer(file, true)
	if err != nil || node == nil {
		return roleSettings{}, err
	}
	if tag, ok := node.(*ast.TagNode); ok {
		node = tag.Value
	}
	only := ast.Mapping(node.GetToken(), false)
	for _, v := range node.(*ast.MappingNode).Values {
		if slices.Contains(roleSettingKeys, keyString(v.Key)) {
			only.Values = append(only.Values, v)
		}
	}
	var s roleSettings
	if err := decode(r.keys.context(), only, &s); err != nil {
		return roleSettings{}, fmt.Errorf("%s: %w", r.path(file), err)
	}
	return s, nil
}

var projectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// checkStack records the stack a role declares, returning the names of the
// role directory's entries its files cover.
func (r *Repo) checkStack(role string, s roleSettings) (map[string]bool, error) {
	roleFile := r.path("roles", role, "role.yml")
	def := &stackDef{role: role, name: stackName(role), perms: map[string]Perms{}, dirs: map[string]Perms{}}
	if !projectName.MatchString(def.name) {
		return nil, fmt.Errorf(
			"%s: %q can't be a Docker Compose project name; use lower case letters, digits, \"-\" and \"_\"",
			r.path("roles", role),
			def.name,
		)
	}
	var files []fileEntry
	if s.Compose != nil {
		files = s.Compose.Files
	}

	covered := map[string]bool{}
	written := map[string]string{}
	for _, entry := range files {
		clean := filepath.Clean(entry.Path)
		if entry.Path == "" || filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("%s: compose.files: %q isn't a path inside the role", roleFile, entry.Path)
		}
		top, _, _ := strings.Cut(clean, "/")
		if top == "role.yml" || top == host.ComposeFile || isVariantFile(top) {
			return nil, fmt.Errorf("%s: compose.files: %q is read by sensible, so can't be copied", roleFile, entry.Path)
		}
		covered[top] = true
		if err := def.addFiles(r.path("roles", role), clean, filePerms(entry.Perms), written); err != nil {
			return nil, fmt.Errorf("%s: compose.files: %w", roleFile, err)
		}
	}
	slices.Sort(def.files)
	r.stacks[role] = def
	return covered, nil
}

// addFiles adds every file at entry, a path in the role directory dir.
// written maps where each file added so far is written to its path.
func (d *stackDef) addFiles(dir, entry string, perms Perms, written map[string]string) error {
	return filepath.WalkDir(
		filepath.Join(dir, entry),
		func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, path)
			if e.IsDir() {
				return setPerms(d.dirs, rel, dirPerms(perms))
			}
			prev, ok := written[stackPath(rel)]
			switch {
			case !ok:
				written[stackPath(rel)] = rel
				d.files = append(d.files, rel)
			case prev != rel:
				return fmt.Errorf("%s and %s would both be written as %s", prev, rel, stackPath(rel))
			}
			return setPerms(d.perms, rel, perms)
		},
	)
}

// setPerms records the perms for path, which mustn't conflict with any
// already recorded for it by another entry.
func setPerms(m map[string]Perms, path string, p Perms) error {
	if prev, ok := m[path]; ok && prev != p {
		return fmt.Errorf("%s is listed more than once, with different owners or modes", path)
	}
	m[path] = p
	return nil
}

// stackPath is where a role's file is written in its stack, without any
// .age suffix.
func stackPath(rel string) string {
	return strings.TrimSuffix(rel, ageSuffix)
}

// stackName is the name of the role's stack and of its volumes' directory.
func stackName(role string) string {
	return strings.ReplaceAll(role, "/", "-")
}

// checkVolumes records the volumes a role declares.
func (r *Repo) checkVolumes(role string, volumes map[string]Perms) error {
	for name := range volumes {
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/:") {
			return fmt.Errorf("%s: invalid volume name %q", r.path("roles", role, "role.yml"), name)
		}
	}
	if len(volumes) > 0 {
		r.volumes[role] = volumes
	}
	return nil
}

// checkStackNames rejects roles with stacks or volumes whose names map to
// the same stack name.
func (r *Repo) checkStackNames() error {
	roles := slices.Collect(maps.Keys(r.stacks))
	for role := range r.volumes {
		if _, ok := r.stacks[role]; !ok {
			roles = append(roles, role)
		}
	}
	slices.Sort(roles)
	seen := map[string]string{}
	for _, role := range roles {
		name := stackName(role)
		if other, ok := seen[name]; ok {
			return fmt.Errorf("roles %q and %q would both use the stack name %q", other, role, name)
		}
		seen[name] = role
	}
	return nil
}

// hostVolumes are the volumes of the given roles and of their parents.
func (r *Repo) hostVolumes(roles []string) []Volume {
	owners := map[string]bool{}
	for _, role := range roles {
		owners[role] = true
		if parent, _, ok := strings.Cut(role, "/"); ok {
			owners[parent] = true
		}
	}
	var volumes []Volume
	for role := range owners {
		for name, perms := range r.volumes[role] {
			volumes = append(volumes, Volume{Path: filepath.Join(VolumesDir, stackName(role), name), Perms: perms})
		}
	}
	slices.SortFunc(volumes, func(a, b Volume) int { return strings.Compare(a.Path, b.Path) })
	return volumes
}

// renderStack reads a stack's files, replacing the compose file's tags and
// decrypting .age files.
func (r *Repo) renderStack(role string, params map[string]ast.Node) (Stack, error) {
	def := r.stacks[role]
	s := Stack{Name: def.name, Dirs: def.dirs}

	composePath := filepath.Join("roles", role, host.ComposeFile)
	compose, err := r.renderCompose(composePath, def, params)
	if err != nil {
		return Stack{}, fmt.Errorf("%s: %w", r.path(composePath), err)
	}
	s.Files = append(s.Files, compose)

	for _, rel := range def.files {
		path := r.path("roles", role, rel)
		b, err := os.ReadFile(path)
		if err != nil {
			return Stack{}, err
		}
		f := StackFile{Path: stackPath(rel), Content: string(b), Perms: def.perms[rel]}
		if f.Path != rel {
			secret, err := parseArmored(string(b))
			if err != nil {
				return Stack{}, fmt.Errorf("%s: %w", path, err)
			}
			secret.keys = r.keys
			if f.Content, err = secret.Reveal(); err != nil {
				return Stack{}, fmt.Errorf("%s: %w", path, err)
			}
			f.Hidden = true
		}
		s.Files = append(s.Files, f)
	}
	return s, nil
}

// renderCompose replaces the tags in a compose file, leaving the rest of it,
// including comments, as written.
func (r *Repo) renderCompose(file string, def *stackDef, params map[string]ast.Node) (StackFile, error) {
	src, err := os.ReadFile(r.path(file))
	if err != nil {
		return StackFile{}, err
	}
	f, err := parser.ParseBytes(src, parser.ParseComments)
	if err != nil {
		return StackFile{}, err
	}
	if len(f.Docs) != 1 {
		return StackFile{}, fmt.Errorf("expected a single YAML document, found %d", len(f.Docs))
	}
	c := &composeRenderer{repo: r, def: def, params: params}
	body, _, err := c.replace(f.Docs[0].Body)
	if err != nil {
		return StackFile{}, err
	}
	f.Docs[0].Body = body
	content := f.String()
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return StackFile{Path: host.ComposeFile, Content: content, Perms: filePerms(Perms{}), Secrets: c.secrets}, nil
}

type composeRenderer struct {
	repo    *Repo
	def     *stackDef
	params  map[string]ast.Node
	secrets []string
}

// replace returns node with its tags replaced, and whether it was a !param
// whose value is null, which drops it from its mapping or list.
func (c *composeRenderer) replace(node ast.Node) (ast.Node, bool, error) {
	switch n := node.(type) {
	case *ast.TagNode:
		switch n.Start.Value {
		case paramTag:
			return c.param(n)
		case ageTag, volumeTag:
			s, err := c.scalar(n)
			if err != nil {
				return nil, false, err
			}
			v, err := flowNode(s)
			return v, false, err
		default:
			v, _, err := c.replace(n.Value)
			n.Value = v
			return n, false, err
		}
	case *ast.AnchorNode:
		v, _, err := c.replace(n.Value)
		n.Value = v
		return n, false, err
	case *ast.MappingNode:
		kept := n.Values[:0]
		for _, mv := range n.Values {
			v, drop, err := c.replace(mv.Value)
			if err != nil {
				return nil, false, err
			}
			if !drop {
				mv.Value = v
				kept = append(kept, mv)
			}
		}
		n.Values = kept
	case *ast.MappingValueNode:
		v, _, err := c.replace(n.Value)
		n.Value = v
		return n, false, err
	case *ast.SequenceNode:
		kept := n.Values[:0]
		for _, item := range n.Values {
			v, drop, err := c.replace(item)
			if err != nil {
				return nil, false, err
			}
			if !drop {
				kept = append(kept, v)
			}
		}
		n.Values = kept
	default:
	}
	return node, false, nil
}

// param writes a parameter's value in flow style, as goccy-yaml can't
// print a block node moved into a different place.
func (c *composeRenderer) param(tag *ast.TagNode) (ast.Node, bool, error) {
	name, ok := tag.Value.(*ast.StringNode)
	if !ok {
		return nil, false, nodeError(tag, "!param needs a parameter name")
	}
	v, ok := c.params[name.Value]
	if !ok {
		return nil, false, nodeError(tag, fmt.Sprintf("unknown parameter %q", name.Value))
	}
	if isNull(v) {
		return v, true, nil
	}
	value, err := c.value(v)
	if err != nil {
		return nil, false, err
	}
	n, err := flowNode(value)
	return n, false, err
}

func (c *composeRenderer) value(node ast.Node) (any, error) {
	switch n := node.(type) {
	case *ast.TagNode:
		if n.Start.Value == ageTag || n.Start.Value == volumeTag {
			return c.scalar(n)
		}
		return c.value(n.Value)
	case *ast.MappingNode:
		m := yaml.MapSlice{}
		for _, mv := range n.Values {
			v, err := c.value(mv.Value)
			if err != nil {
				return nil, err
			}
			m = append(m, yaml.MapItem{Key: keyString(mv.Key), Value: v})
		}
		return m, nil
	case *ast.SequenceNode:
		var s []any
		for _, item := range n.Values {
			v, err := c.value(item)
			if err != nil {
				return nil, err
			}
			s = append(s, v)
		}
		return s, nil
	default:
		var v any
		if err := yaml.NodeToValue(node, &v); err != nil {
			return nil, err
		}
		return v, nil
	}
}

// volume resolves a !volume tag: a volume name, or ../ and the name of the
// parent role's volume, optionally followed by the rest of a mount.
func (c *composeRenderer) volume(tag *ast.TagNode) (string, error) {
	v, ok := tag.Value.(*ast.StringNode)
	if !ok {
		return "", nodeError(tag, "!volume needs a volume name")
	}
	name, rest, mount := strings.Cut(v.Value, ":")
	owner := c.def.role
	if parentName, ok := strings.CutPrefix(name, "../"); ok {
		parent, _, isChild := strings.Cut(owner, "/")
		if !isChild {
			return "", nodeError(tag, fmt.Sprintf("volume %q is a parent's, but role %s has no parent", name, owner))
		}
		owner, name = parent, parentName
	}
	if _, ok := c.repo.volumes[owner][name]; !ok {
		return "", nodeError(tag, fmt.Sprintf("volume %q isn't in role %s's compose.volumes", name, owner))
	}
	path := filepath.Join(VolumesDir, stackName(owner), name)
	if mount {
		path += ":" + rest
	}
	return path, nil
}

// scalar resolves an !age or !volume tag to the string that replaces it.
func (c *composeRenderer) scalar(tag *ast.TagNode) (string, error) {
	if tag.Start.Value == volumeTag {
		return c.volume(tag)
	}

	var s Secret
	if err := s.UnmarshalYAML(c.repo.keys.context(), tag); err != nil {
		return "", err
	}
	plain, err := s.Reveal()
	if err != nil {
		return "", nodeError(tag, err.Error())
	}
	// Compose would otherwise read "$" as the start of a variable.
	escaped := strings.ReplaceAll(plain, "$", "$$")
	quoted, err := jsonText(escaped)
	if err != nil {
		return "", err
	}
	// As it appears in the file, between the quotes.
	c.secrets = append(c.secrets, quoted[1:len(quoted)-1])
	return escaped, nil
}

// flowNode parses v written as JSON, which YAML reads the same way and
// which prints on one line wherever it's put.
func flowNode(v any) (ast.Node, error) {
	text, err := jsonText(v)
	if err != nil {
		return nil, err
	}
	f, err := parser.ParseBytes([]byte(text), 0)
	if err != nil {
		return nil, err
	}
	return f.Docs[0].Body, nil
}

func jsonText(v any) (string, error) {
	var buf bytes.Buffer
	if err := writeJSON(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func writeJSON(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case yaml.MapSlice:
		buf.WriteByte('{')
		for i, item := range v {
			if i > 0 {
				buf.WriteString(", ")
			}
			if err := writeJSON(buf, fmt.Sprint(item.Key)); err != nil {
				return err
			}
			buf.WriteString(": ")
			if err := writeJSON(buf, item.Value); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteString(", ")
			}
			if err := writeJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return err
		}
		buf.Truncate(buf.Len() - 1)
	}
	return nil
}

// parseArmored reads a whole file as an ASCII-armored age file.
func parseArmored(content string) (Secret, error) {
	armored := strings.TrimSpace(content)
	if !strings.HasPrefix(armored, armor.Header) || !strings.HasSuffix(armored, armor.Footer) {
		return Secret{}, errors.New("expected an ASCII-armored age file, as `sensible secret encrypt --raw` prints")
	}
	return Secret{armored: armored + "\n"}, nil
}
