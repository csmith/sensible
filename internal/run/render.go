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

// renderer writes the compact plan and apply output: a label column of host
// names, then one line per change.
type renderer struct {
	w     io.Writer
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
	return &renderer{w: w, width: width, position: map[string]int{}, skipped: map[string]int{}}
}

func (r *renderer) line(label, text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lineLocked(label, text)
}

func (r *renderer) lineLocked(label, text string) {
	_, _ = fmt.Fprintf(r.w, "%-*s%s\n", r.width, label, text)
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
			parts = append(parts, h.name+" ✗")
			failures = append(failures, h)
		case h.upgraded:
			parts = append(parts, h.name+" ↑ upgraded")
		default:
			parts = append(parts, h.name+" ✓")
		}
	}
	r.line("agents", strings.Join(parts, "  "))
	for _, h := range failures {
		r.hostError(h.name, h.err)
	}
}

func (r *renderer) hostError(name string, err error) {
	r.line(name, "✗ "+err.Error())
}

func (r *renderer) plan(runs []*hostRun, changes []*dnsChange, dnsUnchanged int, dnsErrs []error) {
	for _, h := range runs {
		if h.agent == nil {
			continue
		}
		r.block(h.name, hostPlanLines(h))
	}
	lines := make([]string, 0, len(changes)+len(dnsErrs))
	for _, c := range changes {
		lines = append(lines, c.String())
	}
	for _, err := range dnsErrs {
		lines = append(lines, "✗ "+err.Error())
	}
	if dnsUnchanged > 0 {
		lines = append(lines, fmt.Sprintf("✓ %d unchanged", dnsUnchanged))
	}
	r.block("dns", lines)
}

func hostPlanLines(h *hostRun) []string {
	if h.err != nil {
		return []string{"✗ " + h.err.Error()}
	}
	var lines []string
	unchanged := 0
	for i, c := range h.checked {
		name := displayID(c.ID)
		switch c.Status {
		case host.StatusInSync:
			unchanged++
		case host.StatusDrifted:
			lines = append(lines, "~ "+name)
			lines = append(lines, indent(c.Diff, "  ")...)
			if n, ok := h.resources[i].(host.Notifier); ok {
				for _, handler := range n.Notifies() {
					lines = append(lines, "  ↻ then "+displayID(handler.ID()))
				}
			}
		case host.StatusDeferred:
			lines = append(lines, "? "+name+"  deferred")
		case host.StatusSkipped:
			lines = append(lines, "- "+name+"  skipped")
		default:
			lines = append(lines, "✗ "+name+": "+c.Error)
		}
	}
	if len(lines) == 0 {
		lines = append(lines, fmt.Sprintf("✓ %d unchanged", unchanged))
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
			r.lineLocked(h.name, "↻ "+name)
		} else {
			r.lineLocked(h.name, "✓ "+name)
		}
	case host.StatusInSync:
		if deferred {
			r.lineLocked(h.name, "✓ "+name+"  unchanged")
		}
	case host.StatusSkipped:
		r.skipped[h.name]++
	case host.StatusFailed:
		r.lineLocked(h.name, "✗ "+name+": "+a.Error)
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
		r.lineLocked(h.name, fmt.Sprintf("- %d skipped", n))
	}
}

func (r *renderer) dnsResult(c *dnsChange, err error) {
	if err != nil {
		r.line("dns", fmt.Sprintf("✗ %s %s: %v", c.rtype, c.fqdn, err))
		return
	}
	r.line("dns", fmt.Sprintf("✓ %s %s", c.rtype, c.fqdn))
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
