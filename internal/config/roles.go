package config

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"

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

	entry := r.inventory.Hosts[name]
	var merged ast.Node
	set := map[string]setBy{}
	for _, role := range slices.Sorted(maps.Keys(entry.Roles)) {
		node, err := r.expandRole(role, osFamily, entry.Roles[role])
		if err != nil {
			return Config{}, fmt.Errorf("%s: role %s: %w", name, role, err)
		}
		if err := checkConflicts(role, node, "", set); err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
		merged = merge(merged, node)
	}

	var c Config
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

func (r *Repo) expandRole(role, osFamily string, params RoleParams) (ast.Node, error) {
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
		node, err := r.readLayer(file, i > 0)
		if err != nil {
			return nil, err
		}
		if node == nil {
			continue
		}
		// The base has nothing beneath it to replace, but its variant does, so
		// only the base's !replace tags are removed here.
		if i == 0 {
			node = merge(nil, node)
		}
		body, p, err := splitParams(node)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.path(file), err)
		}
		declared = merge(declared, p)
		layers = append(layers, layer{file, body})
	}

	values, err := resolveParams(declared, params)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.path("hosts.yml"), err)
	}

	var merged ast.Node
	for _, l := range layers {
		node, err := substitute(l.node, values)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.path(l.file), err)
		}
		// Each file is checked alone first, so errors name the file at fault.
		if err := decode(r.keys.context(), merge(nil, node), &Config{}); err != nil {
			return nil, fmt.Errorf("%s: %w", r.path(l.file), err)
		}
		merged = merge(merged, node)
	}
	return merged, nil
}

func splitParams(node ast.Node) (*ast.MappingNode, ast.Node, error) {
	if tag, ok := node.(*ast.TagNode); ok && tag.Start.Value == replaceTag {
		node = tag.Value
	}
	m := node.(*ast.MappingNode)
	body := ast.Mapping(m.Start, m.IsFlowStyle)
	var params ast.Node
	for _, v := range m.Values {
		if keyString(v.Key) != "params" {
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
func resolveParams(declared ast.Node, params RoleParams) (map[string]ast.Node, error) {
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
				return nil, nodeError(v.Key, fmt.Sprintf("unknown parameter %q", key))
			}
			values[key] = merge(withoutSetSequences(def, v.Value), v.Value)
		}
	}
	return values, nil
}

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

func isTag(node ast.Node, tag string) bool {
	t, ok := node.(*ast.TagNode)
	return ok && t.Start.Value == tag
}

func isNull(node ast.Node) bool {
	return node == nil || node.Type() == ast.NullType
}

type setBy struct {
	role  string
	value string
}

// checkConflicts rejects a role setting a value another role already set
// differently, so the order roles are merged in never matters. Lists union,
// so they never conflict.
func checkConflicts(role string, node ast.Node, path string, set map[string]setBy) error {
	var value string
	switch n := node.(type) {
	case nil:
		return nil
	case *ast.MappingNode:
		value = "\x00mapping"
		for _, v := range n.Values {
			if err := checkConflicts(role, v.Value, joinPath(path, keyString(v.Key)), set); err != nil {
				return err
			}
		}
	case *ast.SequenceNode:
		value = "\x00sequence"
	default:
		if isNull(n) {
			return nil
		}
		value = itemString(n)
	}
	if prev, ok := set[path]; ok && prev.value != value {
		return errors.New("roles " + prev.role + " and " + role + " set " + path + " differently")
	}
	set[path] = setBy{role, value}
	return nil
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
