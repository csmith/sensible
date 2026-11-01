package config

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goccy/go-yaml/ast"

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

	// Children of a host's roles come in without parameters.
	roles := maps.Clone(r.inventory.Hosts[name].Roles)
	for role := range r.inventory.Hosts[name].Roles {
		for _, child := range r.roles[role] {
			roles[child] = RoleParams{}
		}
	}

	var merged ast.Node
	var stacks []Stack
	set := map[string]setBy{}
	for _, role := range slices.Sorted(maps.Keys(roles)) {
		node, params, err := r.expandRole(name, role, osFamily, roles[role])
		if err != nil {
			return Config{}, fmt.Errorf("%s: role %s: %w", name, role, err)
		}
		if _, ok := r.stacks[role]; ok {
			s, err := r.renderStack(role, params)
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
	return c, nil
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

// expandRole returns the role's settings for the host, and the values of its
// parameters.
func (r *Repo) expandRole(host, role, osFamily string, params RoleParams) (ast.Node, map[string]ast.Node, error) {
	files := []string{filepath.Join("roles", role, "role.yml")}
	if osFamily != "" {
		files = append(files, filepath.Join("roles", role, "role."+osFamily+".yml"))
	}

	type layer struct {
		file string
		node *ast.MappingNode
	}
	var layers []layer
	var declared ast.Node
	for i, file := range files {
		// The layout check has made sure role.yml exists unless the role is
		// a parent that doesn't need one.
		node, err := r.readLayer(file, true)
		if err != nil {
			return nil, nil, err
		}
		if node == nil {
			continue
		}
		// The base has nothing beneath it to replace, but its variant does, so
		// only the base's !replace tags are removed here.
		if i == 0 {
			node = merge(nil, node)
		}
		body, p, err := splitParams(node, i == 0)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.path(file), err)
		}
		// Before the host's parameters are merged in, so a !volume always
		// resolves against the role that wrote it.
		if err := r.resolveVolumes(role, body); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.path(file), err)
		}
		if err := r.resolveVolumes(role, p); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.path(file), err)
		}
		declared = merge(declared, p)
		layers = append(layers, layer{file, body})
	}

	values, perr := resolveParams(declared, params)
	if perr != nil {
		return nil, nil, fmt.Errorf("%s: %w", r.sources[joinPath(host, "roles", role, perr.key)].source, perr)
	}

	var merged ast.Node
	for _, l := range layers {
		node, err := substitute(l.node, values)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.path(l.file), err)
		}
		// Each file is checked alone first, so errors name the file at fault.
		if err := decode(r.keys.context(), merge(nil, node), &Config{}); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.path(l.file), err)
		}
		merged = merge(merged, node)
	}
	return merged, values, nil
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

// resolveVolumes replaces each !volume in node with its path. It modifies
// node, whose root mustn't be a !volume.
func (r *Repo) resolveVolumes(role string, node ast.Node) error {
	resolve := func(n ast.Node) (ast.Node, error) {
		tag, ok := n.(*ast.TagNode)
		if !ok || tag.Start.Value != volumeTag {
			return n, r.resolveVolumes(role, n)
		}
		path, err := r.volumePath(role, tag)
		if err != nil {
			return nil, err
		}
		return flowNode(path)
	}
	var err error
	switch n := node.(type) {
	case *ast.TagNode:
		n.Value, err = resolve(n.Value)
	case *ast.MappingNode:
		for _, mv := range n.Values {
			if mv.Value, err = resolve(mv.Value); err != nil {
				return err
			}
		}
	case *ast.SequenceNode:
		for i, item := range n.Values {
			if n.Values[i], err = resolve(item); err != nil {
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
