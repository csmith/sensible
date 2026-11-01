package run

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"

	"chameth.com/sensible/internal/host"
)

const minLabelWidth = 12

// Debug enables output from debugf.
var Debug bool

// debugf writes a line to stderr if Debug is set.
func debugf(format string, args ...any) {
	if Debug {
		_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

// palette styles output with ANSI colours when true.
type palette bool

func paletteFor(w io.Writer) palette {
	f, ok := w.(*os.File)
	return palette(ok && os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(f.Fd())))
}

func (p palette) paint(code, s string) string {
	if !p || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p palette) ok(s string) string      { return p.paint("32", s) }
func (p palette) fail(s string) string    { return p.paint("31", s) }
func (p palette) change(s string) string  { return p.paint("33", s) }
func (p palette) handler(s string) string { return p.paint("36", s) }
func (p palette) dim(s string) string     { return p.paint("2", s) }
func (p palette) bold(s string) string    { return p.paint("1", s) }

// diff indents a change description, colouring the unified diff parts of it.
func (p palette) diff(text, prefix string) []string {
	lines := indent(text, "")
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "--- "):
			l = p.bold(l)
		case strings.HasPrefix(l, "@@ "):
			l = p.handler(l)
		case strings.HasPrefix(l, "+"):
			l = p.ok(l)
		case strings.HasPrefix(l, "-"):
			l = p.fail(l)
		case strings.HasPrefix(l, "\\ "):
			l = p.dim(l)
		default:
		}
		lines[i] = prefix + l
	}
	return lines
}

// renderer writes the compact plan and apply output: a label column of host
// names, then one line per change.
type renderer struct {
	w     io.Writer
	p     palette
	width int

	mu       sync.Mutex
	position map[string]int
	skipped  map[string]int
}

func newRenderer(w io.Writer, targets []target) *renderer {
	width := minLabelWidth
	for _, t := range targets {
		width = max(width, len(t.name)+1)
	}
	return &renderer{w: w, p: paletteFor(w), width: width, position: map[string]int{}, skipped: map[string]int{}}
}

func (r *renderer) line(label, text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lineLocked(label, text)
}

func (r *renderer) lineLocked(label, text string) {
	if label != "" {
		label = r.p.bold(fmt.Sprintf("%-*s", r.width, label))
	} else {
		label = strings.Repeat(" ", r.width)
	}
	_, _ = fmt.Fprintf(r.w, "%s%s\n", label, text)
}

// block writes lines with the label on the first only.
func (r *renderer) block(label string, lines []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, l := range lines {
		if i > 0 {
			label = ""
		}
		r.lineLocked(label, l)
	}
}

func (r *renderer) agents(runs []*hostRun) {
	var parts []string
	var failures []*hostRun
	for _, h := range runs {
		switch {
		case h.err != nil:
			parts = append(parts, h.name+" "+r.p.fail("✗"))
			failures = append(failures, h)
		case h.upgraded:
			parts = append(parts, h.name+" "+r.p.handler("↑ upgraded"))
		default:
			parts = append(parts, h.name+" "+r.p.ok("✓"))
		}
	}
	r.line("agents", strings.Join(parts, "  "))
	for _, h := range failures {
		r.hostError(h.name, h.err)
	}
}

func (r *renderer) hostError(name string, err error) {
	r.line(name, r.p.fail("✗ "+err.Error()))
}

func (r *renderer) plan(runs []*hostRun, dns dnsPlan) {
	for _, h := range runs {
		if h.agent == nil {
			continue
		}
		r.block(h.name, hostPlanLines(h, r.p))
	}
	lines := make([]string, 0, len(dns.changes)+len(dns.warnings)+len(dns.errs))
	for _, c := range dns.changes {
		mark, rest, _ := strings.Cut(c.String(), " ")
		switch mark {
		case "+":
			mark = r.p.ok(mark)
		case "-":
			mark = r.p.fail(mark)
		default:
			mark = r.p.change(mark)
		}
		lines = append(lines, mark+" "+rest)
	}
	for _, w := range dns.warnings {
		lines = append(lines, r.p.change("! "+w))
	}
	for _, err := range dns.errs {
		lines = append(lines, r.p.fail("✗ "+err.Error()))
	}
	if dns.unchanged > 0 {
		lines = append(lines, r.p.dim(fmt.Sprintf("✓ %d unchanged", dns.unchanged)))
	}
	r.block("dns", lines)
}

func hostPlanLines(h *hostRun, p palette) []string {
	if h.err != nil {
		return []string{p.fail("✗ " + h.err.Error())}
	}
	var lines []string
	unchanged := 0
	for i, c := range h.checked {
		name := displayID(c.ID)
		switch c.Status {
		case host.StatusInSync:
			unchanged++
		case host.StatusDrifted:
			lines = append(lines, p.change("~")+" "+name)
			lines = append(lines, p.diff(c.Diff, "  ")...)
			if n, ok := h.resources[i].(host.Notifier); ok {
				for _, handler := range n.Notifies() {
					lines = append(lines, "  "+p.handler("↻")+" then "+displayID(handler.ID()))
				}
			}
		case host.StatusDeferred:
			lines = append(lines, p.change("?")+" "+name+p.dim("  deferred"))
		case host.StatusSkipped:
			lines = append(lines, p.dim("- "+name+"  skipped"))
		default:
			lines = append(lines, p.fail("✗ "+name+": "+c.Error))
		}
	}
	if len(lines) == 0 {
		lines = append(lines, p.dim(fmt.Sprintf("✓ %d unchanged", unchanged)))
	}
	return lines
}

// applied shows one streamed result. Results for resources arrive in the
// order they were checked, so their position tells which were deferred.
func (r *renderer) applied(h *hostRun, a host.Applied) {
	r.mu.Lock()
	defer r.mu.Unlock()
	deferred := false
	if !a.Handler {
		i := r.position[h.name]
		r.position[h.name]++
		deferred = i < len(h.checked) && h.checked[i].Status == host.StatusDeferred
	}
	name := displayID(a.ID)
	switch a.Status {
	case host.StatusChanged:
		if a.Handler {
			r.lineLocked(h.name, r.p.handler("↻")+" "+name)
		} else {
			r.lineLocked(h.name, r.p.ok("✓")+" "+name)
		}
	case host.StatusInSync:
		if deferred {
			r.lineLocked(h.name, r.p.dim("✓ "+name+"  unchanged"))
		}
	case host.StatusSkipped:
		r.skipped[h.name]++
	case host.StatusFailed:
		r.lineLocked(h.name, r.p.fail("✗ "+name+": "+a.Error))
		for _, l := range indent(a.Output, "  ") {
			r.lineLocked("", l)
		}
	default:
	}
}

func (r *renderer) skippedSummary(h *hostRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := r.skipped[h.name]; n > 0 {
		r.lineLocked(h.name, r.p.dim(fmt.Sprintf("- %d skipped", n)))
	}
}

func (r *renderer) dnsResult(c *dnsChange, err error) {
	if err != nil {
		r.line("dns", r.p.fail(fmt.Sprintf("✗ %s %s: %v", c.rtype, c.fqdn, err)))
		return
	}
	r.line("dns", r.p.ok("✓")+fmt.Sprintf(" %s %s", c.rtype, c.fqdn))
}

// displayID turns "file:/etc/x" into "file /etc/x".
func displayID(id string) string {
	return strings.Replace(id, ":", " ", 1)
}

func indent(text, prefix string) []string {
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return lines
}

var errNoTerminal = errors.New("no terminal to ask on")

func confirmOnTerminal(prompt string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, errNoTerminal
	}
	defer func() { _ = tty.Close() }()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func passwordFromTerminal(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errNoTerminal
	}
	defer func() { _ = tty.Close() }()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	password, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	return string(password), err
}
