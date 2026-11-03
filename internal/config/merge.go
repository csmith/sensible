package config

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

const replaceTag = "!replace"

// merge layers upper over lower without modifying either, applying and
// removing !replace tags.
func merge(lower, upper ast.Node) ast.Node {
	return mergeNodes(lower, upper, nil, true)
}

// mergeFragments merges like merge, but leaves !replace tags in place, so
// host fragments keep them for their role parameters.
func mergeFragments(lower, upper ast.Node) ast.Node {
	return mergeNodes(lower, upper, nil, false)
}

func mergeNodes(lower, upper ast.Node, path []string, replace bool) ast.Node {
	if tag, ok := upper.(*ast.TagNode); ok && replace && tag.Start.Value == replaceTag {
		return mergeNodes(nil, tag.Value, path, replace)
	}
	if upper == nil || upper.Type() == ast.NullType {
		if lower == nil {
			return upper
		}
		return lower
	}

	switch u := upper.(type) {
	case *ast.MappingNode:
		l, _ := lower.(*ast.MappingNode)
		return mergeMapping(l, u, path, replace)
	case *ast.SequenceNode:
		l, _ := lower.(*ast.SequenceNode)
		// Lists concatenate, but upper replaces an atomic list like a scalar.
		if isAtomic(path) {
			l = nil
		}
		return mergeSequence(l, u, replace)
	default:
		return upper
	}
}

func mergeMapping(lower, upper *ast.MappingNode, path []string, replace bool) ast.Node {
	result := ast.Mapping(upper.Start, upper.IsFlowStyle)
	index := map[string]int{}
	if lower != nil {
		for _, v := range lower.Values {
			index[keyString(v.Key)] = len(result.Values)
			result.Values = append(result.Values, v)
		}
	}
	for _, v := range upper.Values {
		key := keyString(v.Key)
		inner := append(slices.Clip(path), key)
		if i, ok := index[key]; ok {
			result.Values[i] = ast.MappingValue(v.Start, v.Key, mergeNodes(result.Values[i].Value, v.Value, inner, replace))
		} else {
			index[key] = len(result.Values)
			result.Values = append(result.Values, ast.MappingValue(v.Start, v.Key, mergeNodes(nil, v.Value, inner, replace)))
		}
	}
	return result
}

// mergeSequence keeps duplicates, as only the field a list decodes into
// knows whether they matter. See Set.
func mergeSequence(lower, upper *ast.SequenceNode, replace bool) ast.Node {
	result := ast.Sequence(upper.Start, upper.IsFlowStyle)
	if lower != nil {
		result.Values = append(result.Values, lower.Values...)
	}
	for _, v := range upper.Values {
		// Lists in lists have no path of their own.
		result.Values = append(result.Values, mergeNodes(nil, v, nil, replace))
	}
	return result
}

// atomicLists are the paths in Config of the lists that are single values,
// with "*" for any map key.
var atomicLists = append(
	commandPaths(reflect.TypeFor[Config](), nil),
	commandPaths(reflect.TypeFor[map[string]migrationConfig](), []string{migrationsKey})...,
)

func commandPaths(t reflect.Type, path []string) [][]string {
	if t == reflect.TypeFor[Command]() {
		return [][]string{path}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return commandPaths(t.Elem(), path)
	case reflect.Map:
		return commandPaths(t.Elem(), append(slices.Clip(path), "*"))
	case reflect.Struct:
		var paths [][]string
		for f := range t.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "" || name == "-" {
				continue
			}
			paths = append(paths, commandPaths(f.Type, append(slices.Clip(path), name))...)
		}
		return paths
	default:
		return nil
	}
}

func isAtomic(path []string) bool {
	return slices.ContainsFunc(
		atomicLists,
		func(pattern []string) bool {
			return slices.EqualFunc(pattern, path, func(p, k string) bool { return p == "*" || p == k })
		},
	)
}

func keyString(n ast.MapKeyNode) string {
	if s, ok := n.(ast.ScalarNode); ok {
		return fmt.Sprint(s.GetValue())
	}
	return n.String()
}

func itemString(n ast.Node) string {
	if s, ok := n.(ast.ScalarNode); ok && n.Type() != ast.TagType {
		return fmt.Sprint(s.GetValue())
	}
	return n.String()
}

// parseLayer parses a single-document YAML file whose root, if present, is a
// mapping. It returns nil for an empty document.
func parseLayer(name string, src []byte) (ast.Node, error) {
	f, err := parser.ParseBytes(src, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(f.Docs) > 1 {
		return nil, fmt.Errorf("%s: expected a single YAML document, found %d", name, len(f.Docs))
	}
	if len(f.Docs) == 0 || f.Docs[0].Body == nil || f.Docs[0].Body.Type() == ast.NullType {
		return nil, nil
	}
	body := f.Docs[0].Body
	if root, ok := body.(*ast.TagNode); ok && root.Start.Value == replaceTag {
		body = root.Value
	}
	if body.Type() != ast.MappingType {
		return nil, fmt.Errorf("%s: expected a mapping at the top level", name)
	}
	return f.Docs[0].Body, nil
}

// withoutSetSequences returns lower without the sequences that upper sets,
// so merging upper over the result replaces those lists rather than adding to
// them.
func withoutSetSequences(lower, upper ast.Node) ast.Node {
	if upper != nil && upper.Type() == ast.SequenceType {
		return nil
	}
	l, ok := lower.(*ast.MappingNode)
	if !ok {
		return lower
	}
	u, ok := upper.(*ast.MappingNode)
	if !ok {
		return lower
	}
	set := map[string]ast.Node{}
	for _, v := range u.Values {
		set[keyString(v.Key)] = v.Value
	}
	result := ast.Mapping(l.Start, l.IsFlowStyle)
	for _, v := range l.Values {
		value, isSet := set[keyString(v.Key)]
		switch {
		case !isSet:
			result.Values = append(result.Values, v)
		case value.Type() == ast.SequenceType:
		default:
			result.Values = append(
				result.Values,
				ast.MappingValue(v.Start, v.Key, withoutSetSequences(v.Value, value)),
			)
		}
	}
	return result
}
