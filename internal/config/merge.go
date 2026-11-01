package config

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

const replaceTag = "!replace"

// merge layers upper over lower without modifying either, applying and
// removing !replace tags.
func merge(lower, upper ast.Node) ast.Node {
	return mergeNodes(lower, upper, true)
}

// mergeFragments merges like merge, but leaves !replace tags in place, so
// host fragments keep them for their role parameters.
func mergeFragments(lower, upper ast.Node) ast.Node {
	return mergeNodes(lower, upper, false)
}

func mergeNodes(lower, upper ast.Node, replace bool) ast.Node {
	if tag, ok := upper.(*ast.TagNode); ok && replace && tag.Start.Value == replaceTag {
		return mergeNodes(nil, tag.Value, replace)
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
		return mergeMapping(l, u, replace)
	case *ast.SequenceNode:
		l, _ := lower.(*ast.SequenceNode)
		return mergeSequence(l, u, replace)
	default:
		return upper
	}
}

func mergeMapping(lower, upper *ast.MappingNode, replace bool) ast.Node {
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
		if i, ok := index[key]; ok {
			result.Values[i] = ast.MappingValue(v.Start, v.Key, mergeNodes(result.Values[i].Value, v.Value, replace))
		} else {
			index[key] = len(result.Values)
			result.Values = append(result.Values, ast.MappingValue(v.Start, v.Key, mergeNodes(nil, v.Value, replace)))
		}
	}
	return result
}

func mergeSequence(lower, upper *ast.SequenceNode, replace bool) ast.Node {
	result := ast.Sequence(upper.Start, upper.IsFlowStyle)
	seen := map[string]bool{}
	add := func(n ast.Node) {
		key := itemString(n)
		if !seen[key] {
			seen[key] = true
			result.Values = append(result.Values, n)
		}
	}
	if lower != nil {
		for _, v := range lower.Values {
			add(v)
		}
	}
	for _, v := range upper.Values {
		add(mergeNodes(nil, v, replace))
	}
	return result
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
