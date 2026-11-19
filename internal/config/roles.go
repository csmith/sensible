package config

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"

	"chameth.com/sensible/internal/host"
)

const paramTag = "!param"

// HostConfig merges the named host's roles. osFamily is the host's
// Facts.OSFamily, which picks each role's role.<os>.yml; empty reads none.
func (r *Repo) HostConfig(name, osFamily string) (Config, error) {
	if err := r.checkHost(name); err != nil {
		return Config{}, err
	}
	if osFamily != "" && !slices.Contains(host.OSFamilies, osFamily) {
		return Config{}, fmt.Errorf("invalid OS family %q", osFamily)
	}

	roles := r.hostRoles(name)
	var merged ast.Node
	expansions := map[string]expansion{}
	set := map[string]setBy{}
	written := map[string]string{}
	dirs := map[string]Perms{}
	secretRoles := map[string]string{}
	for _, role := range slices.Sorted(maps.Keys(roles)) {
		e, err := r.expandRole(name, role, osFamily, roles[role])
		if err != nil {
			return Config{}, fmt.Errorf("%s: role %s: %w", name, role, err)
		}
		if e.oidcSecrets, err = r.roleOIDCSecrets(role, e.node, secretRoles); err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
		if _, ok := r.stacks[role]; ok {
			expansions[role] = e
		}
		if err := checkConflicts("role "+role, e.node, set); err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
		if err := checkFilePaths(role, e.node, written, dirs); err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
		merged = merge(merged, e.node)
	}

	var c Config
	if merged != nil {
		// A module a role names without settings is still on.
		m := merged.(*ast.MappingNode)
		for i, v := range m.Values {
			if isNull(v.Value) {
				m.Values[i] = ast.MappingValue(v.Start, v.Key, ast.Mapping(v.Value.GetToken(), true))
			}
		}
		if err := decode(r.keys.context(), merged, &c); err != nil {
			return Config{}, fmt.Errorf("merging configuration for %s: %w", name, err)
		}
	}
	if err := c.reveal(r.keys); err != nil {
		return Config{}, fmt.Errorf("%s: %w", name, err)
	}

	var err error
	if c.IssuedCerts, err = r.hostCerts(name, c.Certs); err != nil {
		return Config{}, fmt.Errorf("%s: %w", name, err)
	}
	// After the certificates, as a stack's !cert tags need to know where
	// they're written.
	for _, role := range slices.Sorted(maps.Keys(expansions)) {
		s, err := r.renderStack(role, expansions[role], r.inventory.Hosts[name].Generated, c.IssuedCerts)
		if err != nil {
			return Config{}, fmt.Errorf("%s: role %s: %w", name, role, err)
		}
		c.Stacks = append(c.Stacks, s)
	}
	if err := c.finishOIDCClients(r.keys); err != nil {
		return Config{}, fmt.Errorf("%s: %w", name, err)
	}
	if err := c.finishOIDCAPIs(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", name, err)
	}
	slices.SortFunc(c.Stacks, func(a, b Stack) int { return strings.Compare(a.Name, b.Name) })
	c.Volumes = r.hostVolumes(slices.Collect(maps.Keys(roles)))
	return c, nil
}

// hostRoles are the host's roles and the children of those roles, which come
// in without parameters.
func (r *Repo) hostRoles(name string) map[string]RoleParams {
	roles := maps.Clone(r.inventory.Hosts[name].Roles)
	for role := range r.inventory.Hosts[name].Roles {
		for _, child := range r.roles[role] {
			roles[child] = RoleParams{}
		}
	}
	return roles
}

// RoleParams are the parameters a host sets for one of its roles.
type RoleParams struct {
	node *ast.MappingNode
}

func (p *RoleParams) UnmarshalYAML(_ context.Context, node ast.Node) error {
	if node.Type() == ast.NullType {
		*p = RoleParams{}
		return nil
	}
	m, ok := node.(*ast.MappingNode)
	if !ok {
		return nodeError(node, "role parameters must be a mapping")
	}
	p.node = m
	return nil
}

func (p RoleParams) String() string {
	if p.node == nil {
		return ""
	}
	return p.node.String()
}

// expansion is a role as it applies to a host.
type expansion struct {
	// node is the role's settings, merged over its partials'.
	node ast.Node
	// params are the values of the role's parameters.
	params map[string]ast.Node
	// partials are the values of each of the role's partials' placeholders.
	partials []map[string]ast.Node
	// env is the stack's compose.env, merged over its partials'.
	env ast.Node
	// migrations are the stack's migrations, merged over its partials', as
	// a mapping with only the migrations key.
	migrations ast.Node
	// placeholders fill the stack's compose file.
	placeholders roleFiller
	// oidcSecrets are the !generated secrets of the OIDC clients in node,
	// by client ID.
	oidcSecrets map[string]*ast.TagNode
}

func (r *Repo) expandRole(host, role, osFamily string, params RoleParams) (expansion, error) {
	files := []string{filepath.Join("roles", role, "role.yml")}
	if osFamily != "" {
		files = append(files, filepath.Join("roles", role, "role."+osFamily+".yml"))
	}

	type layer struct {
		file string
		base bool
		node *ast.MappingNode
	}
	var layers []layer
	var declared ast.Node
	placeholders := roleFiller{host: host, stack: stackName(role)}
	for i, file := range files {
		// The layout check has made sure role.yml exists unless the role is
		// a parent that doesn't need one.
		node, err := r.readLayer(file, true)
		if err != nil {
			return expansion{}, err
		}
		if node == nil {
			continue
		}
		body, p, err := r.prepareLayer(role, node, i == 0, placeholders)
		if err != nil {
			return expansion{}, fmt.Errorf("%s: %w", r.path(file), err)
		}
		declared = merge(declared, p)
		layers = append(layers, layer{file, i == 0, body})
	}

	values, perr := resolveParams(declared, params)
	if perr != nil {
		return expansion{}, fmt.Errorf("%s: %w", r.sources[joinPath(host, "roles", role, perr.key)].source, perr)
	}

	merged, partials, set, err := r.expandPartials(host, role, values)
	if err != nil {
		return expansion{}, err
	}
	for _, l := range layers {
		node, err := substitute(l.node, values)
		if err != nil {
			return expansion{}, fmt.Errorf("%s: %w", r.path(l.file), err)
		}
		if err := resolveSources(node, r.path("roles", role, sourcesDir)); err != nil {
			return expansion{}, fmt.Errorf("%s: %w", r.path(l.file), err)
		}
		if err := r.checkLayer(node); err != nil {
			return expansion{}, fmt.Errorf("%s: %w", r.path(l.file), err)
		}
		// The role's partials are beneath role.yml, which can only replace
		// what they set with !replace. Its variants replace freely.
		if l.base && set != nil {
			if err := checkConflicts(r.path(l.file), withoutReplaced(node), set); err != nil {
				return expansion{}, fmt.Errorf("%s: %w", r.path("roles", role), err)
			}
		}
		merged = merge(merged, node)
	}
	env, err := r.stackEnv(role, placeholders, values, partials)
	if err != nil {
		return expansion{}, err
	}
	merged, migrations := splitMigrations(merged)
	if _, ok := r.stacks[role]; !ok && migrations != nil {
		return expansion{}, fmt.Errorf("%s: migrations only work in a role with a stack", r.path("roles", role))
	}
	return expansion{
		node:         merged,
		params:       values,
		partials:     partials,
		env:          env,
		migrations:   migrations,
		placeholders: placeholders,
	}, nil
}

// prepareLayer splits a role file into its settings and parameters, and fills
// in what doesn't depend on the host's parameters, which are used as written.
func (r *Repo) prepareLayer(
	role string,
	node ast.Node,
	base bool,
	placeholders roleFiller,
) (*ast.MappingNode, ast.Node, error) {
	body, p, err := splitParams(node, base)
	if err != nil {
		return nil, nil, err
	}
	if _, err := placeholders.fill(body); err != nil {
		return nil, nil, err
	}
	if p, err = placeholders.fill(p); err != nil {
		return nil, nil, err
	}
	// So a !volume always resolves against the role that wrote it.
	volumePath := func(tag *ast.TagNode) (string, error) { return r.volumePath(role, tag) }
	if err := resolveTags(body, volumeTag, volumePath); err != nil {
		return nil, nil, err
	}
	if err := resolveTags(p, volumeTag, volumePath); err != nil {
		return nil, nil, err
	}
	return body, p, nil
}

// sourcesDir is the directory in a role or partial that files entries with
// a source read from.
const sourcesDir = "files"

// resolveSources makes each source in the files of node, a role or partial
// file's settings, and each logo of its OIDC clients, a path in dir, the
// files directory of that role or partial.
func resolveSources(node ast.Node, dir string) error {
	for _, v := range mappingValues(node) {
		switch keyString(v.Key) {
		case "files":
			for _, item := range sequenceValues(v.Value) {
				if err := resolveSourceFields(item, dir, "files", "source"); err != nil {
					return err
				}
			}
		case oidcClientsKey:
			for _, c := range mappingValues(v.Value) {
				what := oidcClientsKey + "." + keyString(c.Key)
				if err := resolveSourceFields(c.Value, dir, what, "logo", "dark_logo"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// resolveSourceFields makes the fields of node with the given names paths
// in dir. what names node in errors.
func resolveSourceFields(node ast.Node, dir, what string, names ...string) error {
	for _, f := range mappingValues(node) {
		name := keyString(f.Key)
		if !slices.Contains(names, name) {
			continue
		}
		s, ok := f.Value.(*ast.StringNode)
		if !ok {
			return nodeError(f.Value, fmt.Sprintf("%s: %s must be a path in %s", what, name, sourcesDir))
		}
		clean := filepath.Clean(s.Value)
		if s.Value == "" || filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			return nodeError(f.Value, fmt.Sprintf("%s: %s %q isn't a path in %s", what, name, s.Value, sourcesDir))
		}
		n, err := flowNode(filepath.Join(dir, clean))
		if err != nil {
			return err
		}
		f.Value = n
	}
	return nil
}

func sequenceValues(node ast.Node) []ast.Node {
	for {
		switch n := node.(type) {
		case *ast.TagNode:
			if n.Start.Value != replaceTag {
				return nil
			}
			node = n.Value
		case *ast.AnchorNode:
			node = n.Value
		case *ast.SequenceNode:
			return n.Values
		default:
			return nil
		}
	}
}

// checkLayer checks a role file's settings, with its parameters' values,
// alone, so errors name the file at fault. It resolves its !vhost tags.
func (r *Repo) checkLayer(node ast.Node) error {
	settings, _ := splitMigrations(node)
	if err := checkStackTags(settings); err != nil {
		return err
	}
	if err := decode(r.keys.context(), merge(nil, settings), &Config{}); err != nil {
		return err
	}
	// After substitution, as a host's parameters may hold a !vhost.
	return resolveTags(node, vhostTag, vhostText)
}

// composeSetting is the named setting under compose in a role or partial
// file, or nil.
func composeSetting(node ast.Node, key string) *ast.MappingValueNode {
	for _, v := range mappingValues(node) {
		if keyString(v.Key) != "compose" {
			continue
		}
		for _, c := range mappingValues(v.Value) {
			if keyString(c.Key) == key {
				return c
			}
		}
	}
	return nil
}

func composeEnv(node ast.Node) ast.Node {
	if s := composeSetting(node, "env"); s != nil {
		return s.Value
	}
	return nil
}

// stackEnv merges the role's compose.env, with its parameters' values, over
// its partials'. As with other settings, the role can only change what a
// partial sets with !replace.
func (r *Repo) stackEnv(
	role string,
	placeholders roleFiller,
	values map[string]ast.Node,
	partials []map[string]ast.Node,
) (ast.Node, error) {
	roleFile := filepath.Join("roles", role, "role.yml")
	node, err := r.readLayer(roleFile, true)
	if err != nil {
		return nil, err
	}
	env, err := placeholders.fill(composeEnv(node))
	if err == nil {
		env, err = substitute(env, values)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: compose.env: %w", r.path(roleFile), err)
	}
	var merged ast.Node
	set := map[string]setBy{}
	for i, use := range r.rolePartials[role] {
		file := use.def.file(partialFile)
		node, err := r.readLayer(file, false)
		if err != nil {
			return nil, err
		}
		partialEnv := composeEnv(node)
		if isNull(partialEnv) {
			continue
		}
		f := filler{values: partials[i], exact: copyValue}
		filled, _, err := f.fill(partialEnv)
		if err == nil {
			err = checkEnv(filled)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: compose.env: %w", r.path(file), err)
		}
		if err := checkConflicts(use.source, filled, set); err != nil {
			return nil, fmt.Errorf("%s: compose.env: %w", r.path("roles", role), err)
		}
		merged = merge(merged, filled)
	}
	if isNull(env) {
		return merged, nil
	}
	if err := checkEnv(env); err != nil {
		return nil, fmt.Errorf("%s: compose.env: %w", r.path("roles", role, "role.yml"), err)
	}
	if err := checkConflicts(r.path("roles", role, "role.yml"), withoutReplaced(env), set); err != nil {
		return nil, fmt.Errorf("%s: compose.env: %w", r.path("roles", role), err)
	}
	return merge(merged, env), nil
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// checkEnv rejects compose.env entries that can't be variables.
func checkEnv(env ast.Node) error {
	if env.Type() != ast.MappingType {
		return nodeError(env, "compose.env must be a mapping")
	}
	for _, mv := range mappingValues(env) {
		if name := keyString(mv.Key); !envName.MatchString(name) {
			return nodeError(mv.Key, fmt.Sprintf("%q isn't a variable name", name))
		}
		v := mv.Value
		if tag, ok := v.(*ast.TagNode); ok && tag.Start.Value == replaceTag {
			v = tag.Value
		}
		if _, ok := v.(ast.ScalarNode); !ok {
			return nodeError(v, "a compose.env value must be a string, number or bool")
		}
	}
	return nil
}

// checkStackTags rejects the tags that are only resolved for stacks, where
// they would be read as their values. OIDC clients' secrets are left to
// HostConfig.
func checkStackTags(node ast.Node) error {
	nodes := []ast.Node{node}
	if clients := oidcClientsSetting(node); clients != nil {
		nodes = []ast.Node{withoutSetting(node, clients)}
		for _, c := range mappingValues(clients.Value) {
			for _, field := range mappingValues(c.Value) {
				if keyString(field.Key) != "secret" {
					nodes = append(nodes, field.Value)
				}
			}
		}
	}
	for _, n := range nodes {
		for _, name := range []string{generatedTag, certTag} {
			if tag := findTag(n, name); tag != nil {
				return nodeError(
					tag,
					name+" only works in a stack's compose file, compose.env, migrations' on and oidc_clients' secret",
				)
			}
		}
	}
	return nil
}

const oidcClientsKey = "oidc_clients"

func oidcClientsSetting(node ast.Node) *ast.MappingValueNode {
	for _, v := range mappingValues(node) {
		if keyString(v.Key) == oidcClientsKey {
			return v
		}
	}
	return nil
}

// withoutSetting is a mapping with node's values other than setting.
func withoutSetting(node ast.Node, setting *ast.MappingValueNode) ast.Node {
	m := ast.Mapping(node.GetToken(), false)
	for _, v := range mappingValues(node) {
		if v != setting {
			m.Values = append(m.Values, v)
		}
	}
	return m
}

// roleOIDCSecrets are the !generated secrets of the OIDC clients in node,
// the role's settings, by client ID. Only a role with a stack has values
// for them, and only one role may set each. secretRoles maps each client to
// the role that set its secret so far.
func (r *Repo) roleOIDCSecrets(
	role string,
	node ast.Node,
	secretRoles map[string]string,
) (map[string]*ast.TagNode, error) {
	secrets := oidcSecrets(node)
	for _, id := range slices.Sorted(maps.Keys(secrets)) {
		if prev, ok := secretRoles[id]; ok {
			return nil, fmt.Errorf("roles %s and %s both set %s.%s.secret", prev, role, oidcClientsKey, id)
		}
		secretRoles[id] = role
		if _, ok := r.stacks[role]; !ok {
			return nil, fmt.Errorf("role %s: %s.%s.secret: !generated needs a role with a stack", role, oidcClientsKey, id)
		}
	}
	return secrets, nil
}

// oidcSecrets are the !generated tags that are the secrets of the OIDC
// clients in node, a role's settings, by client ID.
func oidcSecrets(node ast.Node) map[string]*ast.TagNode {
	clients := oidcClientsSetting(node)
	if clients == nil {
		return nil
	}
	secrets := map[string]*ast.TagNode{}
	for _, c := range mappingValues(clients.Value) {
		for _, field := range mappingValues(c.Value) {
			if tag, ok := field.Value.(*ast.TagNode); ok && keyString(field.Key) == "secret" && tag.Start.Value == generatedTag {
				secrets[keyString(c.Key)] = tag
			}
		}
	}
	return secrets
}

// splitParams separates a role file's parameters from the settings it
// merges into hosts' config. The settings that apply to the role alone are
// dropped from base, the role.yml, as checkLayout has read them.
func splitParams(node ast.Node, base bool) (*ast.MappingNode, ast.Node, error) {
	if tag, ok := node.(*ast.TagNode); ok && tag.Start.Value == replaceTag {
		node = tag.Value
	}
	m := node.(*ast.MappingNode)
	body := ast.Mapping(m.Start, m.IsFlowStyle)
	var params ast.Node
	for _, v := range m.Values {
		key := keyString(v.Key)
		if base && slices.Contains(roleSettingKeys, key) {
			continue
		}
		if key != "params" {
			body.Values = append(body.Values, v)
			continue
		}
		params = v.Value
		if params != nil && params.Type() != ast.NullType && params.Type() != ast.MappingType {
			return nil, nil, nodeError(params, "params must be a mapping")
		}
		if err := checkParamNames(params); err != nil {
			return nil, nil, err
		}
	}
	return body, params, nil
}

// resolveParams merges the host's parameters over the role's defaults. Lists
// the host sets replace the default rather than adding to it.
func resolveParams(declared ast.Node, params RoleParams) (map[string]ast.Node, *paramError) {
	values := map[string]ast.Node{}
	if m, ok := declared.(*ast.MappingNode); ok {
		for _, v := range m.Values {
			values[keyString(v.Key)] = v.Value
		}
	}
	if params.node != nil {
		for _, v := range params.node.Values {
			key := keyString(v.Key)
			def, ok := values[key]
			if !ok {
				return nil, &paramError{key, nodeError(v.Key, fmt.Sprintf("unknown parameter %q", key))}
			}
			values[key] = merge(withoutSetSequences(def, v.Value), v.Value)
		}
	}
	return values, nil
}

type paramError struct {
	key string
	err error
}

func (e *paramError) Error() string { return e.err.Error() }

// substitute replaces each !param with its value, dropping map keys and list
// items whose value is null. It modifies node.
func substitute(node ast.Node, values map[string]ast.Node) (ast.Node, error) {
	switch n := node.(type) {
	case *ast.TagNode:
		if n.Start.Value != paramTag {
			v, err := substitute(n.Value, values)
			n.Value = v
			return n, err
		}
		name, ok := n.Value.(*ast.StringNode)
		if !ok {
			return nil, nodeError(n, "!param needs a parameter name")
		}
		v, ok := values[name.Value]
		if !ok {
			return nil, nodeError(n, fmt.Sprintf("unknown parameter %q", name.Value))
		}
		return merge(nil, v), nil
	case *ast.MappingNode:
		kept := n.Values[:0]
		for _, mv := range n.Values {
			v, err := substitute(mv.Value, values)
			if err != nil {
				return nil, err
			}
			if isTag(mv.Value, paramTag) && isNull(v) {
				continue
			}
			mv.Value = v
			kept = append(kept, mv)
		}
		n.Values = kept
	case *ast.SequenceNode:
		kept := n.Values[:0]
		for _, item := range n.Values {
			v, err := substitute(item, values)
			if err != nil {
				return nil, err
			}
			if isTag(item, paramTag) && isNull(v) {
				continue
			}
			kept = append(kept, v)
		}
		n.Values = kept
	}
	return node, nil
}

// rolePlaceholder matches the placeholders a role's own files can use. Other
// braces in them are left as written, so a doubled placeholder, such as
// {{host}}, stands for the placeholder itself.
var rolePlaceholder = regexp.MustCompile(
	fmt.Sprintf(`\{\{(%[1]s|%[2]s)\}\}|\{(%[1]s|%[2]s)\}`, hostPlaceholder, stackPlaceholder),
)

// roleFiller replaces the placeholders in a role's own files.
type roleFiller struct {
	host, stack string
	// fixed is what's being filled if it must be the same on every host,
	// which rejects {host}.
	fixed string
}

// fill returns node with its placeholders replaced. It modifies node.
func (f roleFiller) fill(node ast.Node) (ast.Node, error) {
	var err error
	switch n := node.(type) {
	case *ast.StringNode:
		return f.fillString(n, n.Value)
	case *ast.LiteralNode:
		return f.fillString(n, n.Value.Value)
	case *ast.TagNode:
		n.Value, err = f.fill(n.Value)
	case *ast.AnchorNode:
		n.Value, err = f.fill(n.Value)
	case *ast.MappingNode:
		if n.IsFlowStyle && len(n.Values) == 1 && isNull(n.Values[0].Value) &&
			rolePlaceholder.MatchString("{"+keyString(n.Values[0].Key)+"}") {
			return nil, nodeError(n, "quote placeholders, e.g. \"{host}\", or YAML reads them as mappings")
		}
		for _, mv := range n.Values {
			if err := f.fillValue(mv); err != nil {
				return nil, err
			}
		}
	case *ast.MappingValueNode:
		err = f.fillValue(n)
	case *ast.SequenceNode:
		for i, item := range n.Values {
			if n.Values[i], err = f.fill(item); err != nil {
				return nil, err
			}
		}
	default:
	}
	return node, err
}

func (f roleFiller) fillValue(mv *ast.MappingValueNode) error {
	if key, ok := mv.Key.(*ast.StringNode); ok {
		s, err := f.interpolate(key, key.Value)
		if err != nil {
			return err
		}
		if s != key.Value {
			setQuoted(key, s)
		}
	}
	v, err := f.fill(mv.Value)
	mv.Value = v
	return err
}

// fillString replaces at, a string whose value is s, with a quoted string
// if it holds placeholders.
func (f roleFiller) fillString(at ast.Node, s string) (ast.Node, error) {
	out, err := f.interpolate(at, s)
	if err != nil || out == s {
		return at, err
	}
	return quoted(at, out), nil
}

func (f roleFiller) interpolate(at ast.Node, s string) (string, error) {
	var err error
	out := rolePlaceholder.ReplaceAllStringFunc(
		s,
		func(m string) string {
			if strings.HasPrefix(m, "{{") {
				return m[1 : len(m)-1]
			}
			switch m[1 : len(m)-1] {
			case stackPlaceholder:
				return f.stack
			default:
				if f.fixed != "" && err == nil {
					err = nodeError(
						at,
						fmt.Sprintf("{%s} is the host's name, which differs between hosts, but %s can't", hostPlaceholder, f.fixed),
					)
				}
				return f.host
			}
		},
	)
	return out, err
}

// resolveTags replaces each of node's tags named tag with the string
// resolve gives for it. It modifies node, whose root mustn't be such a tag.
func resolveTags(node ast.Node, tag string, resolve func(*ast.TagNode) (string, error)) error {
	replace := func(n ast.Node) (ast.Node, error) {
		t, ok := n.(*ast.TagNode)
		if !ok || t.Start.Value != tag {
			return n, resolveTags(n, tag, resolve)
		}
		s, err := resolve(t)
		if err != nil {
			return nil, err
		}
		return flowNode(s)
	}
	var err error
	switch n := node.(type) {
	case *ast.TagNode:
		n.Value, err = replace(n.Value)
	case *ast.AnchorNode:
		n.Value, err = replace(n.Value)
	case *ast.MappingNode:
		for _, mv := range n.Values {
			if mv.Value, err = replace(mv.Value); err != nil {
				return err
			}
		}
	case *ast.SequenceNode:
		for i, item := range n.Values {
			if n.Values[i], err = replace(item); err != nil {
				return err
			}
		}
	default:
	}
	return err
}

func isTag(node ast.Node, tag string) bool {
	t, ok := node.(*ast.TagNode)
	return ok && t.Start.Value == tag
}

func isNull(node ast.Node) bool {
	return node == nil || node.Type() == ast.NullType
}

type setBy struct {
	source string
	value  string
}

// checkConflicts rejects sources setting a value differently, so merge order
// never matters. Nulls and non-atomic lists never conflict.
func checkConflicts(source string, node ast.Node, set map[string]setBy) error {
	return conflicts(source, node, nil, set)
}

func conflicts(source string, node ast.Node, path []string, set map[string]setBy) error {
	key := strings.Join(path, ".")
	var value string
	switch n := node.(type) {
	case *ast.MappingNode:
		value = "\x00mapping"
		for _, v := range n.Values {
			if err := conflicts(source, v.Value, append(slices.Clip(path), keyString(v.Key)), set); err != nil {
				return err
			}
		}
	case *ast.SequenceNode:
		items := []string{"\x00sequence"}
		if isAtomic(path) {
			for _, item := range n.Values {
				items = append(items, itemString(item))
			}
		}
		value = strings.Join(items, "\x00")
	default:
		if isNull(node) {
			// Still recorded, so the key can be traced to a source.
			if _, ok := set[key]; !ok {
				set[key] = setBy{source: source}
			}
			return nil
		}
		value = itemString(n)
	}
	if prev, ok := set[key]; ok && prev.value != "" && prev.value != value {
		return errors.New(prev.source + " and " + source + " set " + key + " differently")
	}
	set[key] = setBy{source, value}
	return nil
}

func joinPath(elem ...string) string {
	return strings.Join(slices.DeleteFunc(elem, func(e string) bool { return e == "" }), ".")
}

// readRoleVhosts records the !vhost tags in the role's files and the
// parameters it declares. A !vhost in a parameter's default only counts for
// hosts that don't set the parameter, and placeholders are filled for each
// host, so their names are left to mapVhosts. Files that don't parse are
// skipped, as HostConfig reports them with the host and role.
func (r *Repo) readRoleVhosts(role string, entries []os.DirEntry) error {
	var base ast.Node
	var variants []ast.Node
	for _, e := range entries {
		file := filepath.Join("roles", role, e.Name())
		nodes, p, err := r.vhostSources(file, e.Name())
		if err != nil {
			return err
		}
		for _, tag := range findTags(p, vhostTag) {
			r.vhostFiles[tag] = file
		}
		if e.Name() == "role.yml" {
			base = p
		} else if p != nil {
			variants = append(variants, p)
		}
		for _, node := range nodes {
			for _, tag := range findTags(node, vhostTag) {
				r.vhostFiles[tag] = file
				r.roleVhosts[role] = append(r.roleVhosts[role], tag)
			}
		}
	}
	for _, use := range r.rolePartials[role] {
		if use.parent < 0 {
			for _, tag := range findTags(use.args, vhostTag) {
				r.vhostFiles[tag] = filepath.Join("roles", role, "role.yml")
			}
		}
	}
	// As any variant may apply, like the vhosts outside params.
	r.params[role] = []ast.Node{merge(nil, base)}
	for _, v := range variants {
		r.params[role] = append(r.params[role], merge(base, v))
	}
	return nil
}

// vhostSources returns the parts of a role's file that may hold a !vhost:
// the file outside its parameters, and its parameters.
func (r *Repo) vhostSources(file, name string) ([]ast.Node, ast.Node, error) {
	switch {
	case name == "role.yml" || isVariantFile(name):
		node, err := r.readLayer(file, false)
		if err != nil || node == nil {
			return nil, nil, nil
		}
		body, params, err := splitParams(node, name == "role.yml")
		if err != nil {
			return nil, nil, nil
		}
		return []ast.Node{body}, params, nil
	case name == host.ComposeFile:
		src, err := os.ReadFile(r.path(file))
		if err != nil {
			return nil, nil, err
		}
		f, err := parser.ParseBytes(src, 0)
		if err != nil {
			return nil, nil, nil
		}
		var nodes []ast.Node
		for _, doc := range f.Docs {
			nodes = append(nodes, doc.Body)
		}
		return nodes, nil, nil
	default:
		return nil, nil, nil
	}
}

// mapVhosts works out which hosts serve each vhost. A vhost can't also be
// a host's dns_name, as both would set its address records. Parameters
// that don't resolve are left for HostConfig to report.
func (r *Repo) mapVhosts() error {
	r.vhosts = map[string][]string{}
	dnsNames := map[string]string{}
	for name, e := range r.inventory.Hosts {
		if e.DNSName != "" {
			dnsNames[normaliseName(e.DNSName)] = name
		}
	}
	for _, name := range slices.Sorted(maps.Keys(r.inventory.Hosts)) {
		roles := r.hostRoles(name)
		for _, role := range slices.Sorted(maps.Keys(roles)) {
			vhosts, err := r.hostRoleVhosts(name, role, roles[role])
			if err != nil {
				return fmt.Errorf("%s: role %s: %w", name, role, err)
			}
			for _, vhost := range vhosts {
				if other, ok := dnsNames[vhost]; ok {
					return fmt.Errorf("%s: role %s: vhost %s is %s's dns_name", name, role, vhost, other)
				}
				if !slices.Contains(r.vhosts[vhost], name) {
					r.vhosts[vhost] = append(r.vhosts[vhost], name)
				}
			}
		}
	}
	return nil
}

// hostRoleVhosts are the vhosts a role serves on a host that sets params
// for it.
func (r *Repo) hostRoleVhosts(host, role string, params RoleParams) ([]string, error) {
	tags := slices.Clone(r.roleVhosts[role])
	for _, declared := range r.params[role] {
		values, _ := resolveParams(declared, params)
		for _, name := range slices.Sorted(maps.Keys(values)) {
			tags = append(tags, findTags(values[name], vhostTag)...)
		}
	}
	var vhosts []string
	for _, use := range r.rolePartials[role] {
		vhosts = append(vhosts, use.def.vhosts...)
		tags = append(tags, partialVhostTags(use)...)
	}
	placeholders := roleFiller{host: host, stack: stackName(role)}
	for _, tag := range tags {
		names, err := r.hostVhostNames(placeholders, tag)
		if err != nil {
			return nil, err
		}
		vhosts = append(vhosts, names...)
	}
	return vhosts, nil
}

// hostVhostNames are the domain names in a !vhost on a host. One written in
// a role has its placeholders filled; one from a host is used as written.
func (r *Repo) hostVhostNames(placeholders roleFiller, tag *ast.TagNode) ([]string, error) {
	file, ok := r.vhostFiles[tag]
	if !ok {
		return vhostNames(tag)
	}
	text, err := vhostText(tag)
	if err == nil {
		text, err = placeholders.interpolate(tag, text)
	}
	var names []string
	if err == nil {
		names, err = splitVhostNames(tag, text)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.path(file), err)
	}
	return names, nil
}

// checkHostVhosts allows a !vhost in a hosts.d file only within a role's
// parameters.
func checkHostVhosts(node ast.Node) error {
	allowed := map[*ast.TagNode]bool{}
	for _, entry := range mappingValues(node) {
		for _, setting := range mappingValues(entry.Value) {
			if keyString(setting.Key) != "roles" {
				continue
			}
			for _, role := range mappingValues(setting.Value) {
				for _, tag := range findTags(role.Value, vhostTag) {
					if _, err := vhostNames(tag); err != nil {
						return err
					}
					allowed[tag] = true
				}
			}
		}
	}
	for _, tag := range findTags(node, vhostTag) {
		if !allowed[tag] {
			return nodeError(tag, "!vhost only works in roles and role parameters")
		}
	}
	return nil
}

// mappingValues returns the values of a mapping, looking through !replace
// tags and anchors.
func mappingValues(node ast.Node) []*ast.MappingValueNode {
	for {
		switch n := node.(type) {
		case *ast.TagNode:
			if n.Start.Value != replaceTag {
				return nil
			}
			node = n.Value
		case *ast.AnchorNode:
			node = n.Value
		case *ast.MappingNode:
			return n.Values
		default:
			return nil
		}
	}
}

var domainLabel = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9])?$`)

// vhostNames are the domain names in a !vhost, separated by commas or
// spaces, in lower case without a trailing dot.
func vhostNames(tag *ast.TagNode) ([]string, error) {
	text, err := vhostText(tag)
	if err != nil {
		return nil, err
	}
	return splitVhostNames(tag, text)
}

func splitVhostNames(tag *ast.TagNode, text string) ([]string, error) {
	var names []string
	for part := range strings.SplitSeq(text, ",") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			return nil, nodeError(tag, fmt.Sprintf("%q has an empty domain name", text))
		}
		for _, field := range fields {
			name := normaliseName(field)
			labels := strings.Split(name, ".")
			if len(labels) < 2 || slices.ContainsFunc(labels, func(l string) bool { return !domainLabel.MatchString(l) }) {
				return nil, nodeError(tag, fmt.Sprintf("%q isn't a domain name", field))
			}
			names = append(names, name)
		}
	}
	return names, nil
}

// vhostText is what a !vhost is replaced with: its value as written.
func vhostText(tag *ast.TagNode) (string, error) {
	v, ok := tag.Value.(*ast.StringNode)
	if !ok {
		return "", nodeError(tag, "!vhost needs a domain name")
	}
	return v.Value, nil
}

func normaliseName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
