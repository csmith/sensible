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
	"github.com/goccy/go-yaml/token"

	"chameth.com/sensible/internal/host"
)

const (
	partialFile = "partial.yml"
	// stackPlaceholder is provided to every role and partial: the role's
	// stack name.
	stackPlaceholder = "stack"
	// hostPlaceholder is likewise the name of the host the role is on.
	hostPlaceholder = "host"
)

// partialDef is a directory in partials/: parameterised role settings, and
// optionally a compose fragment, that roles include.
type partialDef struct {
	name       string
	params     ast.Node
	hasCompose bool
	hasEnv     bool
	// includes are the partials it includes, whose arguments can use its
	// placeholders.
	includes []partialRef
	// vhosts are those written in the partial's files.
	vhosts []string
}

func (d *partialDef) file(name string) string {
	return filepath.Join("partials", d.name, name)
}

func (r *Repo) readPartials() error {
	r.partials = map[string]*partialDef{}
	entries, err := readDir(r.path("partials"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			return fmt.Errorf("%s: unexpected file; expected a partial directory", r.path("partials", e.Name()))
		}
		def, err := r.readPartial(e.Name())
		if err != nil {
			return err
		}
		r.partials[def.name] = def
	}
	for _, name := range slices.Sorted(maps.Keys(r.partials)) {
		if err := r.checkIncludes(r.partials[name], nil); err != nil {
			return err
		}
	}
	return nil
}

// checkIncludes checks the partials def includes, and theirs in turn.
// chain is the partials that include def, outermost first.
func (r *Repo) checkIncludes(def *partialDef, chain []string) error {
	chain = append(slices.Clip(chain), def.name)
	file := r.path(def.file(partialFile))
	for _, ref := range def.includes {
		inc, ok := r.partials[ref.name]
		if !ok {
			return fmt.Errorf(
				"%s: %w",
				file,
				nodeError(ref.node, fmt.Sprintf("partial %q isn't in %s", ref.name, r.path("partials"))),
			)
		}
		if i := slices.Index(chain, ref.name); i >= 0 {
			return fmt.Errorf(
				"%s: partials include each other: %s",
				file,
				strings.Join(append(slices.Clone(chain[i:]), ref.name), " > "),
			)
		}
		if _, perr := resolveParams(inc.params, RoleParams{node: ref.args}); perr != nil {
			return fmt.Errorf("%s: partial %s: %w", file, ref.name, perr)
		}
		if err := r.checkIncludes(inc, chain); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repo) readPartial(name string) (*partialDef, error) {
	def := &partialDef{name: name}
	entries, err := readDir(r.path("partials", name))
	if err != nil {
		return nil, err
	}
	hasFile := false
	for _, e := range entries {
		switch e.Name() {
		case partialFile:
			hasFile = true
		case host.ComposeFile:
			def.hasCompose = true
		case sourcesDir:
			if !e.IsDir() {
				return nil, fmt.Errorf("%s: expected a directory of files' sources", r.path("partials", name, e.Name()))
			}
		default:
			return nil, fmt.Errorf(
				"%s: unexpected file; expected %s, %s or a %s directory",
				r.path("partials", name, e.Name()),
				partialFile,
				host.ComposeFile,
				sourcesDir,
			)
		}
	}
	if !hasFile {
		return nil, fmt.Errorf("%s: missing %s", r.path("partials", name), partialFile)
	}

	file := def.file(partialFile)
	node, err := r.readLayer(file, false)
	if err != nil {
		return nil, err
	}
	body, err := def.split(node)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.path(file), err)
	}
	if err := def.check(body); err != nil {
		return nil, fmt.Errorf("%s: %w", r.path(file), err)
	}

	if def.hasCompose {
		file := def.file(host.ComposeFile)
		f, err := r.parseCompose(file)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.path(file), err)
		}
		if err := def.check(f.Docs[0].Body); err != nil {
			return nil, fmt.Errorf("%s: %w", r.path(file), err)
		}
	}
	return def, nil
}

// split records the partial's parameters from its partial.yml, returning
// the rest of it.
func (d *partialDef) split(node ast.Node) (ast.Node, error) {
	if node == nil {
		return nil, nil
	}
	body := ast.Mapping(node.GetToken(), false)
	for _, v := range mappingValues(node) {
		switch key := keyString(v.Key); key {
		case "params":
			if !isNull(v.Value) && v.Value.Type() != ast.MappingType {
				return nil, nodeError(v.Value, "params must be a mapping")
			}
			if err := checkParamNames(v.Value); err != nil {
				return nil, err
			}
			d.params = v.Value
		case "compose":
			for _, c := range mappingValues(v.Value) {
				switch keyString(c.Key) {
				case "volumes":
				case "env":
					d.hasEnv = !isNull(c.Value)
				default:
					return nil, nodeError(c.Key, "a partial can't set compose."+keyString(c.Key))
				}
			}
			body.Values = append(body.Values, v)
		case "partials":
			if err := decode(context.Background(), v.Value, &d.includes); err != nil {
				return nil, err
			}
			// Kept for check, as its arguments can hold placeholders.
			body.Values = append(body.Values, v)
		case "children":
			return nil, nodeError(v.Key, "a partial can't set "+key)
		default:
			body.Values = append(body.Values, v)
		}
	}
	return body, nil
}

// checkParamNames rejects parameters named as the placeholders every role
// and partial is given.
func checkParamNames(params ast.Node) error {
	for _, p := range mappingValues(params) {
		switch keyString(p.Key) {
		case stackPlaceholder:
			return nodeError(p.Key, "{"+stackPlaceholder+"} is the role's stack name, so can't be a parameter")
		case hostPlaceholder:
			return nodeError(p.Key, "{"+hostPlaceholder+"} is the host's name, so can't be a parameter")
		}
	}
	return nil
}

// check rejects placeholders the partial doesn't provide, and records its
// vhosts.
func (d *partialDef) check(node ast.Node) error {
	if tag := findTag(node, paramTag); tag != nil {
		return nodeError(tag, "a partial's files take values from {placeholders}, not !param")
	}
	known := []string{stackPlaceholder, hostPlaceholder}
	for _, p := range mappingValues(d.params) {
		known = append(known, keyString(p.Key))
	}
	if err := checkPlaceholders(node, known); err != nil {
		return err
	}
	for _, tag := range findTags(node, vhostTag) {
		if v, ok := tag.Value.(*ast.StringNode); ok && placeholderPattern.MatchString(v.Value) {
			return nodeError(tag, "a !vhost can't hold a placeholder; pass the !vhost as an argument instead")
		}
		names, err := vhostNames(tag)
		if err != nil {
			return err
		}
		d.vhosts = append(d.vhosts, names...)
	}
	return nil
}

func checkPlaceholders(node ast.Node, known []string) error {
	return walkStrings(
		node,
		func(n ast.Node, s string) error {
			for _, m := range placeholderPattern.FindAllStringSubmatch(s, -1) {
				if m[1] != "" && !slices.Contains(known, m[1]) {
					return nodeError(n, fmt.Sprintf("unknown placeholder {%s}", m[1]))
				}
			}
			return nil
		},
	)
}

// walkStrings calls fn with each string in node, keys included. A flow
// mapping that looks like an unquoted placeholder is an error.
func walkStrings(node ast.Node, fn func(ast.Node, string) error) error {
	switch n := node.(type) {
	case *ast.StringNode:
		return fn(n, n.Value)
	case *ast.LiteralNode:
		return fn(n, n.Value.Value)
	case *ast.TagNode:
		return walkStrings(n.Value, fn)
	case *ast.AnchorNode:
		return walkStrings(n.Value, fn)
	case *ast.MappingNode:
		if n.IsFlowStyle && len(n.Values) == 1 && isNull(n.Values[0].Value) {
			if _, ok := exactPlaceholder("{" + keyString(n.Values[0].Key) + "}"); ok {
				return nodeError(n, "quote placeholders, e.g. \"{name}\", or YAML reads them as mappings")
			}
		}
		for _, mv := range n.Values {
			if err := walkStrings(mv.Key, fn); err != nil {
				return err
			}
			if err := walkStrings(mv.Value, fn); err != nil {
				return err
			}
		}
	case *ast.MappingValueNode:
		if err := walkStrings(n.Key, fn); err != nil {
			return err
		}
		return walkStrings(n.Value, fn)
	case *ast.SequenceNode:
		for _, item := range n.Values {
			if err := walkStrings(item, fn); err != nil {
				return err
			}
		}
	default:
	}
	return nil
}

// partialUse is a partial a role includes, directly or through another
// partial, and the arguments it's given.
type partialUse struct {
	def  *partialDef
	args *ast.MappingNode
	// parent is the index in the role's partials of the partial including
	// this one, whose placeholders its arguments can use, or -1 if the role
	// includes it.
	parent int
	source string
}

// fillArgs returns the use's arguments with their placeholders filled: from
// all, the values of the role's partials before it, if a partial includes
// it, or from provided if the role does. varying is as for filler.
func (u partialUse) fillArgs(
	provided map[string]ast.Node,
	all []map[string]ast.Node,
	varying bool,
) (*ast.MappingNode, error) {
	values := provided
	if u.parent >= 0 {
		values = all[u.parent]
	}
	f := filler{values: values, varying: varying, exact: copyValue}
	args, _, err := f.fill(merge(nil, u.args))
	if err != nil {
		return nil, err
	}
	m, _ := args.(*ast.MappingNode)
	return m, nil
}

// providedPlaceholders are the values a partial's files and a role's
// arguments to them can use without declaring them. host is nil where the
// host isn't known, which a fixed filler rejects.
func providedPlaceholders(role string, host *string) (map[string]ast.Node, error) {
	stack, err := flowNode(stackName(role))
	if err != nil {
		return nil, err
	}
	values := map[string]ast.Node{stackPlaceholder: stack}
	if host == nil {
		// As any role parameter, which differs between hosts.
		f, err := parser.ParseBytes([]byte(paramTag+" "+hostPlaceholder), 0)
		if err != nil {
			return nil, err
		}
		values[hostPlaceholder] = f.Docs[0].Body
	} else if values[hostPlaceholder], err = flowNode(*host); err != nil {
		return nil, err
	}
	return values, nil
}

// partialRef is an item in a role's partials, as written.
type partialRef struct {
	node *ast.MappingNode
	name string
	args *ast.MappingNode
}

func (p *partialRef) UnmarshalYAML(_ context.Context, node ast.Node) error {
	m, ok := node.(*ast.MappingNode)
	if !ok {
		return nodeError(node, "a partial must be a mapping, with the partial's name in partial")
	}
	p.node = m
	p.args = ast.Mapping(m.Start, m.IsFlowStyle)
	for _, v := range m.Values {
		if keyString(v.Key) != "partial" {
			p.args.Values = append(p.args.Values, v)
			continue
		}
		s, ok := v.Value.(*ast.StringNode)
		if !ok || s.Value == "" {
			return nodeError(v, "partial must be a partial's name")
		}
		p.name = s.Value
	}
	if p.name == "" {
		return nodeError(node, "a partial needs partial, its name")
	}
	return nil
}

// checkPartials records the partials the role includes.
func (r *Repo) checkPartials(role string, refs []partialRef) error {
	roleFile := r.path("roles", role, "role.yml")
	for _, ref := range refs {
		def, ok := r.partials[ref.name]
		if !ok {
			return fmt.Errorf(
				"%s: %w",
				roleFile,
				nodeError(ref.node, fmt.Sprintf("partial %q isn't in %s", ref.name, r.path("partials"))),
			)
		}
		if _, perr := resolveParams(def.params, RoleParams{node: ref.args}); perr != nil {
			return fmt.Errorf("%s: partial %s: %w", roleFile, ref.name, perr)
		}
		if err := checkPlaceholders(ref.args, []string{stackPlaceholder, hostPlaceholder}); err != nil {
			return fmt.Errorf("%s: partial %s: %w", roleFile, ref.name, err)
		}
		r.addPartial(role, partialUse{def: def, args: ref.args, parent: -1, source: "partial " + def.name})
	}
	return nil
}

// addPartial records use, then the partials it includes.
func (r *Repo) addPartial(role string, use partialUse) {
	r.rolePartials[role] = append(r.rolePartials[role], use)
	parent := len(r.rolePartials[role]) - 1
	for _, ref := range use.def.includes {
		def := r.partials[ref.name]
		r.addPartial(role, partialUse{def: def, args: ref.args, parent: parent, source: use.source + " > " + def.name})
	}
}

// partialVolumes are the compose.volumes the role's partials declare. They
// are the same on every host, so their arguments can't be role parameters.
func (r *Repo) partialVolumes(role string, volumes map[string]Perms) (map[string]Perms, error) {
	sources := map[string]string{}
	for name := range volumes {
		sources[name] = "role.yml"
	}
	provided, err := providedPlaceholders(role, nil)
	if err != nil {
		return nil, err
	}
	uses := r.rolePartials[role]
	all := make([]map[string]ast.Node, len(uses))
	for i, use := range uses {
		file := use.def.file(partialFile)
		args, err := use.fillArgs(provided, all, true)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %s: %w", r.path("roles", role, "role.yml"), use.source, r.path(file), err)
		}
		all[i], _ = resolveParams(use.def.params, RoleParams{node: args})
		maps.Copy(all[i], provided)

		node, err := r.readLayer(file, false)
		if err != nil {
			return nil, err
		}
		setting := composeSetting(node, "volumes")
		if setting == nil {
			continue
		}
		section := ast.Mapping(setting.GetToken(), false, setting)
		f := filler{values: all[i], fixed: true, exact: copyValue}
		filled, _, err := f.fill(section)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %s: %w", r.path("roles", role, "role.yml"), use.source, r.path(file), err)
		}
		var s struct {
			Volumes map[string]Perms `yaml:"volumes"`
		}
		if err := decode(r.keys.context(), filled, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", r.path(file), err)
		}
		for _, name := range slices.Sorted(maps.Keys(s.Volumes)) {
			perms := s.Volumes[name]
			if prev, ok := sources[name]; ok && volumes[name] != perms {
				return nil, fmt.Errorf(
					"%s: %s and %s set volume %s differently",
					r.path("roles", role),
					prev,
					use.source,
					name,
				)
			}
			if volumes == nil {
				volumes = map[string]Perms{}
			}
			volumes[name] = perms
			sources[name] = use.source
		}
	}
	return volumes, nil
}

// partialVhostTags are the !vhost tags in a partial's arguments and the
// defaults they don't set.
func partialVhostTags(use partialUse) []*ast.TagNode {
	values, _ := resolveParams(use.def.params, RoleParams{node: use.args})
	tags := make([]*ast.TagNode, 0, len(values))
	for _, name := range slices.Sorted(maps.Keys(values)) {
		tags = append(tags, findTags(values[name], vhostTag)...)
	}
	return tags
}

// expandPartials returns the settings the role's partials give a host, the
// values of each partial's placeholders, and what set each setting, for
// the role's own settings to be checked against.
func (r *Repo) expandPartials(
	host, role string,
	roleValues map[string]ast.Node,
) (ast.Node, []map[string]ast.Node, map[string]setBy, error) {
	uses := r.rolePartials[role]
	if len(uses) == 0 {
		return nil, nil, nil, nil
	}
	provided, err := providedPlaceholders(role, &host)
	if err != nil {
		return nil, nil, nil, err
	}
	var merged ast.Node
	all := make([]map[string]ast.Node, len(uses))
	set := map[string]setBy{}
	for i, use := range uses {
		values, err := r.partialValues(role, use, roleValues, provided, all)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %s: %w", r.path("roles", role, "role.yml"), use.source, err)
		}
		all[i] = values

		file := use.def.file(partialFile)
		node, err := r.partialSettings(role, file, values)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", r.path(file), err)
		}
		if err := checkConflicts(use.source, node, set); err != nil {
			return nil, nil, nil, err
		}
		merged = merge(merged, node)
	}
	return merged, all, set, nil
}

// partialValues are the values of a partial's placeholders for a host. all
// are those of the role's partials before it.
func (r *Repo) partialValues(
	role string,
	use partialUse,
	roleValues, provided map[string]ast.Node,
	all []map[string]ast.Node,
) (map[string]ast.Node, error) {
	volumePath := func(tag *ast.TagNode) (string, error) { return r.volumePath(role, tag) }
	declared := merge(nil, use.def.params)
	if err := resolveTags(declared, volumeTag, volumePath); err != nil {
		return nil, err
	}
	args, err := use.fillArgs(provided, all, false)
	if err != nil {
		return nil, err
	}
	if _, err := substitute(args, roleValues); err != nil {
		return nil, err
	}
	if err := resolveTags(args, volumeTag, volumePath); err != nil {
		return nil, err
	}
	values, perr := resolveParams(declared, RoleParams{node: args})
	if perr != nil {
		return nil, perr
	}
	maps.Copy(values, provided)
	return values, nil
}

// partialSettings are the settings a partial's partial.yml gives a host.
func (r *Repo) partialSettings(role, file string, values map[string]ast.Node) (ast.Node, error) {
	node, err := r.readLayer(file, false)
	if err != nil {
		return nil, err
	}
	if node == nil {
		return nil, nil
	}
	body := ast.Mapping(node.GetToken(), false)
	for _, v := range mappingValues(node) {
		if key := keyString(v.Key); key != "params" && key != "compose" && key != "partials" {
			body.Values = append(body.Values, v)
		}
	}
	f := filler{values: values, exact: copyValue}
	filled, _, err := f.fill(body)
	if err != nil {
		return nil, err
	}
	settings, _ := splitMigrations(filled)
	if err := checkStackTags(settings); err != nil {
		return nil, err
	}
	volumePath := func(tag *ast.TagNode) (string, error) { return r.volumePath(role, tag) }
	if err := resolveTags(filled, volumeTag, volumePath); err != nil {
		return nil, err
	}
	if err := resolveSources(filled, r.path(filepath.Dir(file), sourcesDir)); err != nil {
		return nil, err
	}
	if err := decode(r.keys.context(), merge(nil, settings), &Config{}); err != nil {
		return nil, err
	}
	if err := resolveTags(filled, vhostTag, vhostText); err != nil {
		return nil, err
	}
	return filled, nil
}

// partialCompose is a partial's compose fragment for a host, with its
// placeholders and tags replaced.
func (c *composeRenderer) partialCompose(use partialUse, values map[string]ast.Node) (*ast.File, error) {
	f, err := c.repo.parseCompose(use.def.file(host.ComposeFile))
	if err != nil {
		return nil, err
	}
	fl := filler{
		values: values,
		exact: func(v, at ast.Node) (ast.Node, error) {
			value, err := c.value(v)
			if err != nil {
				return nil, err
			}
			n, err := flowNode(value)
			if err != nil {
				return nil, err
			}
			// So overlay can move it like the nodes around it.
			n.AddColumn(column(at) - column(n))
			return n, nil
		},
	}
	body, _, err := fl.fill(f.Docs[0].Body)
	if err != nil {
		return nil, err
	}
	if body, _, err = c.replace(body); err != nil {
		return nil, err
	}
	f.Docs[0].Body = body
	return f, nil
}

// placeholderPattern matches {name}, and {{ and }}, which stand for single
// braces.
var placeholderPattern = regexp.MustCompile(`\{\{|\}\}|\{([A-Za-z_][A-Za-z0-9_-]*)\}`)

// exactPlaceholder returns the name of the placeholder s consists of.
func exactPlaceholder(s string) (string, bool) {
	m := placeholderPattern.FindStringSubmatchIndex(s)
	if m == nil || m[0] != 0 || m[1] != len(s) || m[2] < 0 {
		return "", false
	}
	return s[m[2]:m[3]], true
}

// filler replaces the placeholders in a partial's files.
type filler struct {
	values map[string]ast.Node
	// exact is the node that replaces at, a value consisting of a
	// placeholder whose value is v.
	exact func(v, at ast.Node) (ast.Node, error)
	// fixed rejects values from role parameters, which differ between
	// hosts.
	fixed bool
	// varying replaces a string using a role parameter with the parameter,
	// for a fixed filler to reject should the string be used.
	varying bool
}

func copyValue(v, _ ast.Node) (ast.Node, error) {
	return merge(nil, v), nil
}

// fill returns node with its placeholders replaced, and whether it was a
// placeholder whose value is null, which drops it from its mapping or
// list. It modifies node.
func (f filler) fill(node ast.Node) (ast.Node, bool, error) {
	switch n := node.(type) {
	case *ast.StringNode:
		return f.fillString(n)
	case *ast.LiteralNode:
		// Written quoted, as a block scalar keeps the indentation it had in
		// the partial wherever it's moved to.
		if v := f.varyingValue(n.Value.Value); v != nil {
			return v, false, nil
		}
		s, err := f.interpolate(n, n.Value.Value)
		return quoted(n, s), false, err
	case *ast.TagNode:
		v, drop, err := f.fill(n.Value)
		if err != nil || drop {
			return nil, drop, err
		}
		// A copy, as merge doesn't copy tags, so a role's arguments to its
		// partials are filled afresh for each host.
		tag := *n
		tag.Value = v
		return &tag, false, nil
	case *ast.AnchorNode:
		v, _, err := f.fill(n.Value)
		if err != nil {
			return nil, false, err
		}
		n.Value = v
	case *ast.MappingNode:
		return n, false, f.fillMapping(n)
	case *ast.MappingValueNode:
		if _, err := f.fillKey(n); err != nil {
			return nil, false, err
		}
		v, _, err := f.fill(n.Value)
		if err != nil {
			return nil, false, err
		}
		n.Value = v
	case *ast.SequenceNode:
		kept := n.Values[:0]
		for _, item := range n.Values {
			v, drop, err := f.fill(item)
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

func (f filler) fillString(n *ast.StringNode) (ast.Node, bool, error) {
	if v := f.varyingValue(n.Value); v != nil {
		return v, false, nil
	}
	if name, ok := exactPlaceholder(n.Value); ok {
		v, err := f.value(n, name)
		if err != nil || isNull(v) {
			return nil, err == nil, err
		}
		out, err := f.exact(v, n)
		return out, false, err
	}
	s, err := f.interpolate(n, n.Value)
	if err != nil || (s == n.Value && !hasLineBreak(s)) {
		return n, false, err
	}
	return quoted(n, s), false, nil
}

func (f filler) fillMapping(n *ast.MappingNode) error {
	kept := n.Values[:0]
	for _, mv := range n.Values {
		drop, err := f.fillKey(mv)
		if err != nil {
			return err
		}
		if drop {
			continue
		}
		v, drop, err := f.fill(mv.Value)
		if err != nil {
			return err
		}
		if !drop {
			mv.Value = v
			kept = append(kept, mv)
		}
	}
	n.Values = kept
	return nil
}

// fillKey replaces the placeholders in a mapping's key, returning whether
// the key is a placeholder whose value is null.
func (f filler) fillKey(mv *ast.MappingValueNode) (bool, error) {
	key, ok := mv.Key.(*ast.StringNode)
	if !ok {
		return false, nil
	}
	if name, ok := exactPlaceholder(key.Value); ok {
		v, err := f.value(key, name)
		if err != nil || isNull(v) {
			return err == nil, err
		}
		s, err := scalarText(key, name, v)
		if err != nil {
			return false, err
		}
		setQuoted(key, s)
		return false, nil
	}
	s, err := f.interpolate(key, key.Value)
	if err == nil && s != key.Value {
		setQuoted(key, s)
	}
	return false, err
}

// varyingValue is the role parameter s uses, if f is varying.
func (f filler) varyingValue(s string) ast.Node {
	if !f.varying {
		return nil
	}
	for _, m := range placeholderPattern.FindAllStringSubmatch(s, -1) {
		if v := f.values[m[1]]; m[1] != "" && findTag(v, paramTag) != nil {
			return merge(nil, v)
		}
	}
	return nil
}

func (f filler) value(at ast.Node, name string) (ast.Node, error) {
	v, ok := f.values[name]
	if !ok {
		return nil, nodeError(at, fmt.Sprintf("unknown placeholder {%s}", name))
	}
	if f.fixed && findTag(v, paramTag) != nil {
		return nil, nodeError(
			at,
			fmt.Sprintf(
				"{%s} is a role parameter or the host's name here, which differ between hosts, but volumes can't",
				name,
			),
		)
	}
	return v, nil
}

func (f filler) interpolate(at ast.Node, s string) (string, error) {
	var errs []error
	out := placeholderPattern.ReplaceAllStringFunc(
		s,
		func(m string) string {
			switch m {
			case "{{":
				return "{"
			case "}}":
				return "}"
			}
			name := m[1 : len(m)-1]
			v, err := f.value(at, name)
			if err != nil {
				errs = append(errs, err)
				return ""
			}
			text, err := scalarText(at, name, v)
			if err != nil {
				errs = append(errs, err)
			}
			return text
		},
	)
	return out, errors.Join(errs...)
}

// scalarText is a placeholder's value as part of a longer string.
func scalarText(at ast.Node, name string, v ast.Node) (string, error) {
	s, ok := v.(ast.ScalarNode)
	if !ok || isNull(v) || v.Type() == ast.TagType {
		return "", nodeError(
			at,
			fmt.Sprintf("{%s} must be a string, number or bool to be part of a longer value", name),
		)
	}
	return scalarValue(s), nil
}

func hasLineBreak(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// quoted is a double-quoted string in place of at.
func quoted(at ast.Node, s string) ast.Node {
	tk := *at.GetToken()
	n := ast.String(&tk)
	setQuoted(n, s)
	return n
}

func setQuoted(n *ast.StringNode, s string) {
	tk := *n.Token
	tk.Value = s
	tk.Origin = s
	tk.Type = token.DoubleQuoteType
	n.Token = &tk
	n.Value = s
}

// overlay merges upper over lower as merge does, but keeps upper's nodes,
// and so the comments in them, moving lower's into place. shift is how many
// columns to the right lower's nodes move, and flow is whether upper is
// within a flow collection, where lower's nodes are written in flow style.
// It modifies both.
func (c *composeRenderer) overlay(lower, upper ast.Node, shift int, flow bool) (ast.Node, error) {
	if lower == nil || isTag(upper, replaceTag) {
		return upper, nil
	}
	if isNull(upper) {
		return c.place(lower, shift, flow)
	}
	var err error
	switch u := upper.(type) {
	case *ast.MappingNode:
		if l, ok := lower.(*ast.MappingNode); ok {
			err = c.overlayMapping(l, u, flow || u.IsFlowStyle)
		}
	case *ast.SequenceNode:
		if l, ok := lower.(*ast.SequenceNode); ok {
			err = c.overlaySequence(l, u, flow || u.IsFlowStyle)
		}
	default:
	}
	return upper, err
}

func (c *composeRenderer) overlayMapping(lower, upper *ast.MappingNode, flow bool) error {
	index := map[string]*ast.MappingValueNode{}
	for _, v := range upper.Values {
		index[keyString(v.Key)] = v
	}
	var added []*ast.MappingValueNode
	for _, lv := range lower.Values {
		if uv, ok := index[keyString(lv.Key)]; ok {
			v, err := c.overlay(lv.Value, uv.Value, column(uv.Key)-column(lv.Key), flow)
			if err != nil {
				return err
			}
			uv.Value = v
			continue
		}
		if flow {
			v, err := c.place(lv.Value, 0, true)
			if err != nil {
				return err
			}
			lv.Value = v
		} else if len(upper.Values) > 0 {
			lv.AddColumn(column(upper.Values[0].Key) - column(lv.Key))
		}
		added = append(added, lv)
	}
	upper.Values = append(added, upper.Values...)
	return nil
}

func (c *composeRenderer) overlaySequence(lower, upper *ast.SequenceNode, flow bool) error {
	var added []ast.Node
	for _, item := range lower.Values {
		v, err := c.place(item, column(upper)-column(lower), flow)
		if err != nil {
			return err
		}
		added = append(added, v)
	}
	if len(upper.ValueHeadComments) == len(upper.Values) {
		upper.ValueHeadComments = append(make([]*ast.CommentGroupNode, len(added)), upper.ValueHeadComments...)
	}
	upper.Values = append(added, upper.Values...)
	return nil
}

// place moves node shift columns right, or writes it in flow style.
func (c *composeRenderer) place(node ast.Node, shift int, flow bool) (ast.Node, error) {
	if !flow {
		node.AddColumn(shift)
		return node, nil
	}
	v, err := c.value(node)
	if err != nil {
		return nil, err
	}
	return flowNode(v)
}

func column(n ast.Node) int {
	return n.GetToken().Position.Column
}

// withoutReplaced returns node without the values tagged !replace, which
// override what's beneath them rather than conflicting with it.
func withoutReplaced(node ast.Node) ast.Node {
	m, ok := node.(*ast.MappingNode)
	if !ok {
		return node
	}
	result := ast.Mapping(m.Start, m.IsFlowStyle)
	for _, v := range m.Values {
		if !isTag(v.Value, replaceTag) {
			result.Values = append(result.Values, ast.MappingValue(v.Start, v.Key, withoutReplaced(v.Value)))
		}
	}
	return result
}

// withoutReplaceTags removes the !replace tags in node, which overlay has
// applied. It modifies node.
func withoutReplaceTags(node ast.Node) ast.Node {
	switch n := node.(type) {
	case *ast.TagNode:
		if n.Start.Value == replaceTag {
			return withoutReplaceTags(n.Value)
		}
		n.Value = withoutReplaceTags(n.Value)
	case *ast.AnchorNode:
		n.Value = withoutReplaceTags(n.Value)
	case *ast.MappingNode:
		for _, mv := range n.Values {
			mv.Value = withoutReplaceTags(mv.Value)
		}
	case *ast.SequenceNode:
		for i, item := range n.Values {
			n.Values[i] = withoutReplaceTags(item)
		}
	default:
	}
	return node
}

// parseCompose parses a compose file, keeping its comments.
func (r *Repo) parseCompose(file string) (*ast.File, error) {
	src, err := os.ReadFile(r.path(file))
	if err != nil {
		return nil, err
	}
	f, err := parser.ParseBytes(src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	if len(f.Docs) != 1 {
		return nil, fmt.Errorf("expected a single YAML document, found %d", len(f.Docs))
	}
	return f, nil
}
