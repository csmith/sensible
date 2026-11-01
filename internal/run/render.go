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

// renderer writes output in sections: a header naming what's being done,
// then a line per outcome.
type renderer struct {
	w io.Writer
	p palette

	mu sync.Mutex
	// While applying, the host holding the floor streams its section live
	// and the others' sections are held until it finishes.
	floor    *hostRun
	held     []*heldSection
	started  map[*hostRun]bool
	position map[*hostRun]int
	skipped  map[*hostRun]int
}

type heldSection struct {
	h        *hostRun
	lines    []string
	finished bool
}

func newRenderer(w io.Writer) *renderer {
	return &renderer{
		w:        w,
		p:        paletteFor(w),
		started:  map[*hostRun]bool{},
		position: map[*hostRun]int{},
		skipped:  map[*hostRun]int{},
	}
}

func (r *renderer) header(title string) string {
	return r.p.paint("1;34", ">") + " " + r.p.bold(title)
}

func (r *renderer) section(title string, lines []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writeLocked(r.header(title))
	for _, l := range lines {
		r.writeLocked(itemIndent + l)
	}
}

const itemIndent = "  "

// item writes a line under the current section's header.
func (r *renderer) item(text string) {
	r.line(itemIndent + text)
}

func (r *renderer) line(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writeLocked(text)
}

func (r *renderer) writeLocked(text string) {
	_, _ = fmt.Fprintln(r.w, text)
}

func (r *renderer) agents(runs []*hostRun) {
	lines := make([]string, 0, len(runs))
	for _, h := range runs {
		switch {
		case h.err != nil:
			lines = append(lines, r.p.fail("✗ "+h.name+": "+h.err.Error()))
		case h.upgraded:
			lines = append(lines, r.p.handler("↑")+" "+h.name+r.p.dim("  upgraded"))
		default:
			lines = append(lines, r.p.ok("✓")+" "+h.name)
		}
	}
	r.section("Connecting to agents", lines)
}

func (r *renderer) plan(runs []*hostRun, dns dnsPlan) {
	for _, h := range runs {
		if h.agent == nil {
			continue
		}
		r.section("Resolving changes on "+h.name, hostPlanLines(h, r.p))
	}
	lines := make([]string, 0, len(dns.changes)+len(dns.warnings)+len(dns.errs)+1)
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
	if len(lines) > 0 {
		r.section("Resolving DNS changes", lines)
	}
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
	if unchanged > 0 {
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
		i := r.position[h]
		r.position[h]++
		deferred = i < len(h.checked) && h.checked[i].Status == host.StatusDeferred
	}
	name := displayID(a.ID)
	switch a.Status {
	case host.StatusChanged:
		if a.Handler {
			r.applyLineLocked(h, r.p.handler("↻")+" "+name)
		} else {
			r.applyLineLocked(h, r.p.ok("✓")+" "+name)
		}
	case host.StatusInSync:
		if deferred {
			r.applyLineLocked(h, r.p.dim("✓ "+name+"  unchanged"))
		}
	case host.StatusSkipped:
		r.skipped[h]++
	case host.StatusFailed:
		r.applyLineLocked(h, r.p.fail("✗ "+name+": "+a.Error))
		for _, l := range indent(a.Output, "  ") {
			r.applyLineLocked(h, l)
		}
	default:
	}
}

func (r *renderer) applyError(h *hostRun, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyLineLocked(h, r.p.fail("✗ "+err.Error()))
}

// applyLineLocked adds a line to h's apply section, which streams if h holds
// the floor and is held otherwise.
func (r *renderer) applyLineLocked(h *hostRun, text string) {
	if !r.started[h] {
		r.started[h] = true
		header := r.header("Applying changes on " + h.name)
		if r.floor == nil {
			r.floor = h
			r.writeLocked(header)
		} else {
			r.held = append(r.held, &heldSection{h: h, lines: []string{header}})
		}
	}
	text = itemIndent + text
	if r.floor == h {
		r.writeLocked(text)
		return
	}
	for _, s := range r.held {
		if s.h == h {
			s.lines = append(s.lines, text)
		}
	}
}

// applyDone ends h's apply section, passing the floor on if h held it.
func (r *renderer) applyDone(h *hostRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := r.skipped[h]; n > 0 {
		r.applyLineLocked(h, r.p.dim(fmt.Sprintf("- %d skipped", n)))
	}
	if !r.started[h] {
		r.applyLineLocked(h, r.p.dim("✓ nothing changed"))
	}
	if r.floor != h {
		for _, s := range r.held {
			if s.h == h {
				s.finished = true
			}
		}
		return
	}
	r.floor = nil
	for len(r.held) > 0 {
		next := r.held[0]
		r.held = r.held[1:]
		for _, l := range next.lines {
			r.writeLocked(l)
		}
		if !next.finished {
			r.floor = next.h
			return
		}
	}
}

func (r *renderer) dnsResult(c *dnsChange, err error) {
	if err != nil {
		r.item(r.p.fail(fmt.Sprintf("✗ %s %s: %v", c.rtype, c.fqdn, err)))
		return
	}
	r.item(r.p.ok("✓") + fmt.Sprintf(" %s %s", c.rtype, c.fqdn))
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
