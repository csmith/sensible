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
	vhostTag  = "!vhost"
	ageSuffix = ".age"
	// envFile is where compose.env is written, which compose reads for the
	// variables in the stack's compose file.
	envFile = ".env"
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
	// Generated are the values of !generated tags that were created for
	// this stack rather than saved for the host, by name. Repo.SaveGenerated
	// must save them before the stack is deployed with them.
	Generated map[string]string
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
	Children []string     `yaml:"children"`
	Partials []partialRef `yaml:"partials"`
	Compose  *struct {
		Files   []fileEntry      `yaml:"files"`
		Volumes map[string]Perms `yaml:"volumes"`
		// Env is resolved for each host, as it may hold role parameters.
		Env rawNode `yaml:"env"`
	} `yaml:"compose"`
}

// rawNode is a value left undecoded.
type rawNode struct {
	node ast.Node
}

func (n *rawNode) UnmarshalYAML(_ context.Context, node ast.Node) error {
	n.node = node
	return nil
}

var roleSettingKeys = []string{"children", "compose", "partials"}

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
// decrypting .age files. generated are the host's saved generated values,
// by stack.
func (r *Repo) renderStack(role string, e expansion, generated map[string]map[string]Secret) (Stack, error) {
	def := r.stacks[role]
	s := Stack{Name: def.name, Dirs: def.dirs}

	c := &composeRenderer{repo: r, def: def, params: e.params, gen: &generator{saved: generated[def.name]}}
	compose, err := c.renderCompose(e)
	if err != nil {
		return Stack{}, err
	}
	s.Files = append(s.Files, compose)
	env, err := c.renderEnv(e.env)
	if err != nil {
		return Stack{}, fmt.Errorf("compose.env: %w", err)
	}
	if env != nil {
		if slices.Contains(def.files, envFile) || slices.Contains(def.files, envFile+ageSuffix) {
			return Stack{}, fmt.Errorf("compose.env is written to %s, so it can't also be in compose.files", envFile)
		}
		s.Files = append(s.Files, *env)
	}
	s.Generated = c.gen.created

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

// renderCompose merges the role's compose file over its partials' and
// replaces their tags, leaving the rest of them, including comments, as
// written.
func (c *composeRenderer) renderCompose(e expansion) (StackFile, error) {
	f, set, err := c.partialsCompose(e.partials)
	if err != nil {
		return StackFile{}, err
	}
	file := filepath.Join("roles", c.def.role, host.ComposeFile)
	if _, err := os.Stat(c.repo.path(file)); f == nil || err == nil {
		if f, err = c.roleCompose(file, f, set); err != nil {
			return StackFile{}, fmt.Errorf("%s: %w", c.repo.path(file), err)
		}
	}
	content := f.String()
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return StackFile{Path: host.ComposeFile, Content: content, Perms: filePerms(Perms{}), Secrets: c.secrets}, nil
}

// partialsCompose merges the compose fragments of the role's partials,
// returning nil if none has one, and what set each value, for the role's
// compose file to be checked against.
func (c *composeRenderer) partialsCompose(values []map[string]ast.Node) (*ast.File, map[string]setBy, error) {
	var f *ast.File
	set := map[string]setBy{}
	for i, use := range c.repo.rolePartials[c.def.role] {
		if !use.def.hasCompose {
			continue
		}
		file := c.repo.path(use.def.file(host.ComposeFile))
		pf, err := c.partialCompose(use, values[i])
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		if err := checkConflicts(use.source(), pf.Docs[0].Body, set); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", c.repo.path("roles", c.def.role), err)
		}
		if f == nil {
			f = pf
			continue
		}
		body, err := c.overlay(pf.Docs[0].Body, f.Docs[0].Body, 0, false)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		f.Docs[0].Body = body
	}
	return f, set, nil
}

// roleCompose reads the role's compose file, merged over partials if
// they're not nil.
func (c *composeRenderer) roleCompose(file string, partials *ast.File, set map[string]setBy) (*ast.File, error) {
	f, err := c.repo.parseCompose(file)
	if err != nil {
		return nil, err
	}
	body, _, err := c.replace(f.Docs[0].Body)
	if err != nil {
		return nil, err
	}
	if partials != nil {
		if err := checkConflicts(c.repo.path(file), withoutReplaced(body), set); err != nil {
			return nil, err
		}
		if body, err = c.overlay(partials.Docs[0].Body, body, 0, false); err != nil {
			return nil, err
		}
		body = withoutReplaceTags(body)
	}
	f.Docs[0].Body = body
	return f, nil
}

type composeRenderer struct {
	repo    *Repo
	def     *stackDef
	params  map[string]ast.Node
	gen     *generator
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
		case ageTag, generatedTag, volumeTag, vhostTag:
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
		switch n.Start.Value {
		case ageTag, generatedTag, volumeTag, vhostTag:
			return c.scalar(n)
		default:
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

// volumePath resolves a !volume tag written in the role: a volume name, or
// ../ and the name of the parent role's volume, optionally followed by the
// rest of a mount.
func (r *Repo) volumePath(role string, tag *ast.TagNode) (string, error) {
	v, ok := tag.Value.(*ast.StringNode)
	if !ok {
		return "", nodeError(tag, "!volume needs a volume name")
	}
	name, rest, mount := strings.Cut(v.Value, ":")
	owner := role
	if parentName, ok := strings.CutPrefix(name, "../"); ok {
		parent, _, isChild := strings.Cut(owner, "/")
		if !isChild {
			return "", nodeError(tag, fmt.Sprintf("volume %q is a parent's, but role %s has no parent", name, owner))
		}
		owner, name = parent, parentName
	}
	if _, ok := r.volumes[owner][name]; !ok {
		return "", nodeError(tag, fmt.Sprintf("volume %q isn't in role %s's compose.volumes", name, owner))
	}
	path := filepath.Join(VolumesDir, stackName(owner), name)
	if mount {
		path += ":" + rest
	}
	return path, nil
}

// scalar resolves an !age, !generated, !volume or !vhost tag to the string
// that replaces it in the compose file.
func (c *composeRenderer) scalar(tag *ast.TagNode) (string, error) {
	switch tag.Start.Value {
	case volumeTag:
		return c.repo.volumePath(c.def.role, tag)
	case vhostTag:
		return vhostText(tag)
	default:
	}

	plain, err := c.secret(tag)
	if err != nil {
		return "", err
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

// secret reveals an !age or !generated tag.
func (c *composeRenderer) secret(tag *ast.TagNode) (string, error) {
	if tag.Start.Value == generatedTag {
		return c.gen.value(tag)
	}
	var s Secret
	if err := s.UnmarshalYAML(c.repo.keys.context(), tag); err != nil {
		return "", err
	}
	plain, err := s.Reveal()
	if err != nil {
		return "", nodeError(tag, err.Error())
	}
	return plain, nil
}

// renderEnv writes compose.env as the stack's .env, returning nil if it sets
// nothing. Values are single-quoted, which compose reads literally.
func (c *composeRenderer) renderEnv(env ast.Node) (*StackFile, error) {
	var lines, secrets []string
	allSecret := true
	for _, mv := range mappingValues(env) {
		name := keyString(mv.Key)
		if isNull(mv.Value) {
			continue
		}
		value, secret, err := c.envValue(mv.Value)
		if err != nil {
			return nil, err
		}
		if strings.ContainsAny(value, "'\r\n") {
			return nil, nodeError(
				mv.Value,
				fmt.Sprintf("%s can't be written to %s, as it holds a single quote or line break", name, envFile),
			)
		}
		lines = append(lines, name+"='"+value+"'")
		if secret {
			secrets = append(secrets, value)
		} else {
			allSecret = false
		}
	}
	if len(lines) == 0 {
		return nil, nil
	}
	slices.Sort(lines)
	return &StackFile{
		Path:    envFile,
		Content: strings.Join(lines, "\n") + "\n",
		Perms:   filePerms(Perms{}),
		Secrets: secrets,
		Hidden:  allSecret,
	}, nil
}

// envValue is a compose.env value as written to .env, and whether it's
// secret.
func (c *composeRenderer) envValue(node ast.Node) (string, bool, error) {
	if tag, ok := node.(*ast.TagNode); ok {
		switch tag.Start.Value {
		case ageTag, generatedTag:
			v, err := c.secret(tag)
			return v, true, err
		case volumeTag, vhostTag:
			v, err := c.scalar(tag)
			return v, false, err
		default:
			return "", false, nodeError(tag, tag.Start.Value+" can't be used in compose.env")
		}
	}
	if s, ok := node.(ast.ScalarNode); ok {
		return fmt.Sprint(s.GetValue()), false, nil
	}
	return "", false, nodeError(node, "a compose.env value must be a string, number or bool")
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
