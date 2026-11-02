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
	var stacks []Stack
	set := map[string]setBy{}
	for _, role := range slices.Sorted(maps.Keys(roles)) {
		e, err := r.expandRole(name, role, osFamily, roles[role])
		if err != nil {
			return Config{}, fmt.Errorf("%s: role %s: %w", name, role, err)
		}
		node := e.node
		if _, ok := r.stacks[role]; ok {
			s, err := r.renderStack(role, e)
			if err != nil {
				return Config{}, fmt.Errorf("%s: role %s: %w", name, role, err)
			}
			stacks = append(stacks, s)
		}
		if err := checkConflicts("role "+role, node, set); err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
		merged = merge(merged, node)
	}

	slices.SortFunc(stacks, func(a, b Stack) int { return strings.Compare(a.Name, b.Name) })
	volumes := r.hostVolumes(slices.Collect(maps.Keys(roles)))
	c := Config{Stacks: stacks, Volumes: volumes}
	if merged == nil {
		return c, nil
	}
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
	c.Stacks, c.Volumes = stacks, volumes
	if c.Restic != nil {
		if err := c.Restic.reveal(); err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
	}
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
		body, p, err := splitParams(node, i == 0)
		if err != nil {
			return expansion{}, fmt.Errorf("%s: %w", r.path(file), err)
		}
		// Before the host's parameters are merged in, so a !volume always
		// resolves against the role that wrote it.
		volumePath := func(tag *ast.TagNode) (string, error) { return r.volumePath(role, tag) }
		if err := resolveTags(body, volumeTag, volumePath); err != nil {
			return expansion{}, fmt.Errorf("%s: %w", r.path(file), err)
		}
		if err := resolveTags(p, volumeTag, volumePath); err != nil {
			return expansion{}, fmt.Errorf("%s: %w", r.path(file), err)
		}
		declared = merge(declared, p)
		layers = append(layers, layer{file, i == 0, body})
	}

	values, perr := resolveParams(declared, params)
	if perr != nil {
		return expansion{}, fmt.Errorf("%s: %w", r.sources[joinPath(host, "roles", role, perr.key)].source, perr)
	}

	merged, partials, set, err := r.expandPartials(role, values)
	if err != nil {
		return expansion{}, err
	}
	for _, l := range layers {
		node, err := substitute(l.node, values)
		if err != nil {
			return expansion{}, fmt.Errorf("%s: %w", r.path(l.file), err)
		}
		// Each file is checked alone first, so errors name the file at fault.
		if err := decode(r.keys.context(), merge(nil, node), &Config{}); err != nil {
			return expansion{}, fmt.Errorf("%s: %w", r.path(l.file), err)
		}
		// After substitution, as a host's parameters may hold a !vhost.
		if err := resolveTags(node, vhostTag, vhostText); err != nil {
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
	return expansion{node: merged, params: values, partials: partials}, nil
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

// readRoleVhosts records the vhosts named in the role's files and the
// parameters it declares. A !vhost in a parameter's default only counts for
// hosts that don't set the parameter, so those are left to mapVhosts. Files
// that don't parse are skipped, as HostConfig reports them with the host
// and role.
func (r *Repo) readRoleVhosts(role string, entries []os.DirEntry) error {
	var base ast.Node
	var variants []ast.Node
	var vhosts []string
	for _, e := range entries {
		file := filepath.Join("roles", role, e.Name())
		nodes, p, err := r.vhostSources(file, e.Name())
		if err != nil {
			return err
		}
		for _, tag := range findTags(p, vhostTag) {
			if _, err := vhostNames(tag); err != nil {
				return fmt.Errorf("%s: %w", r.path(file), err)
			}
		}
		if e.Name() == "role.yml" {
			base = p
		} else if p != nil {
			variants = append(variants, p)
		}
		for _, node := range nodes {
			for _, tag := range findTags(node, vhostTag) {
				names, err := vhostNames(tag)
				if err != nil {
					return fmt.Errorf("%s: %w", r.path(file), err)
				}
				vhosts = append(vhosts, names...)
			}
		}
	}
	fromPartials, err := r.partialVhosts(role)
	if err != nil {
		return err
	}
	vhosts = append(vhosts, fromPartials...)
	if len(vhosts) > 0 {
		r.roleVhosts[role] = vhosts
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
			vhosts, err := r.hostRoleVhosts(role, roles[role])
			if err != nil {
				return err
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
func (r *Repo) hostRoleVhosts(role string, params RoleParams) ([]string, error) {
	vhosts := slices.Clone(r.roleVhosts[role])
	for _, declared := range r.params[role] {
		values, _ := resolveParams(declared, params)
		for _, v := range values {
			for _, tag := range findTags(v, vhostTag) {
				names, err := vhostNames(tag)
				if err != nil {
					return nil, err
				}
				vhosts = append(vhosts, names...)
			}
		}
	}
	return vhosts, nil
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
