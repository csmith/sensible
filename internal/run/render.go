package run

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

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

// failure marks an error with ✗, indenting any lines after the first under it
// so text from a host can't pass for lines of sensible's own.
func (p palette) failure(text string) []string {
	return marked("✗", text, p.fail)
}

// warning marks a warning with !, indenting it like failure.
func (p palette) warning(text string) []string {
	return marked("!", text, p.change)
}

func marked(mark, text string, paint func(string) string) []string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, l := range lines {
		if i == 0 {
			l = mark + " " + l
		} else {
			l = "  " + l
		}
		lines[i] = paint(l)
	}
	return lines
}

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

	// live is set on a terminal, where unfinished tasks are drawn below
	// everything else and redrawn as they change.
	live  bool
	tasks []*task
	// inProgress is what each host is changing now, drawn after the tasks.
	inProgress []applyingItem
	drawn      int
	frame      int
	ticking    bool
	// pending is what's been written under the lock, sent in one write when
	// it's released so the terminal never shows a partial update.
	pending strings.Builder
	// moved is set when the cursor has gone up over drawn tasks, which are
	// then overwritten or cleared before the lock is released.
	moved bool
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
		live:     liveFor(w),
		started:  map[*hostRun]bool{},
		position: map[*hostRun]int{},
		skipped:  map[*hostRun]int{},
	}
}

func (r *renderer) header(title string) string {
	return r.p.paint("1;34", ">") + " " + r.p.bold(title)
}

func (r *renderer) section(title string) {
	r.line(r.header(title))
}

const itemIndent = "  "

// item writes lines under the current section's header.
func (r *renderer) item(lines ...string) {
	r.line(indentItems(lines)...)
}

func (r *renderer) line(lines ...string) {
	r.lock()
	defer r.unlock()
	for _, l := range lines {
		r.writeLocked(l)
	}
}

func (r *renderer) lock() {
	r.mu.Lock()
}

// unlock draws the unfinished tasks below whatever was written, then sends
// it all at once. On a terminal it's wrapped in synchronised output mode,
// which terminals without it ignore.
func (r *renderer) unlock() {
	defer r.mu.Unlock()
	if r.live && (len(r.tasks) > 0 || len(r.inProgress) > 0 || r.moved) {
		r.drawLocked()
	}
	if r.pending.Len() == 0 {
		return
	}
	out := r.pending.String()
	r.pending.Reset()
	if r.live {
		out = "\x1b[?2026h" + out + "\x1b[?2026l"
	}
	_, _ = io.WriteString(r.w, out)
}

func (r *renderer) writeLocked(text string) {
	if !r.live {
		r.pending.WriteString(text + "\n")
		return
	}
	r.upLocked()
	// Lines overwrite whatever was drawn there, clearing what's left of it.
	r.pending.WriteString(text + "\x1b[K\n")
}

func (r *renderer) upLocked() {
	if r.drawn > 0 {
		fmt.Fprintf(&r.pending, "\x1b[%dF", r.drawn)
		r.drawn = 0
		r.moved = true
	}
}

func liveFor(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && !Debug && os.Getenv("TERM") != "dumb" && term.IsTerminal(int(f.Fd()))
}

// task is work whose outcome is written when it finishes, in the order tasks
// began. On a terminal it's drawn with a spinner until then; elsewhere its
// head is written as soon as the tasks before it have finished.
type task struct {
	label     func(frame string) string
	head      []string
	body      []string
	done      bool
	headShown bool
}

// beginSection starts a task that writes a whole section.
func (r *renderer) beginSection(title string) *task {
	return r.begin(
		func(frame string) string { return r.p.paint("1;34", frame) + " " + r.p.bold(title) },
		r.header(title),
	)
}

// beginItem starts a task that writes a line under the current header.
func (r *renderer) beginItem(text string) *task {
	return r.begin(func(frame string) string { return itemIndent + frame + " " + text })
}

func (r *renderer) begin(label func(frame string) string, head ...string) *task {
	r.lock()
	defer r.unlock()
	t := &task{label: label, head: head}
	r.tasks = append(r.tasks, t)
	r.flushLocked()
	r.tickLocked()
	return t
}

func (r *renderer) tickLocked() {
	if r.live && !r.ticking {
		r.ticking = true
		go r.tick()
	}
}

// finish ends a task, with the lines that follow its head.
func (r *renderer) finish(t *task, body ...string) {
	r.lock()
	defer r.unlock()
	t.body, t.done = body, true
	r.flushLocked()
}

func (r *renderer) flushLocked() {
	for len(r.tasks) > 0 {
		t := r.tasks[0]
		if !t.headShown && (!r.live || t.done) {
			t.headShown = true
			for _, l := range t.head {
				r.writeLocked(l)
			}
		}
		if !t.done {
			return
		}
		for _, l := range t.body {
			r.writeLocked(l)
		}
		r.tasks = r.tasks[1:]
	}
}

const spinnerFrames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

// drawLocked draws the unfinished tasks below everything written so far.
// Finished tasks still waiting their turn lose their spinner.
func (r *renderer) drawLocked() {
	r.upLocked()
	frames := []rune(spinnerFrames)
	frame := string(frames[r.frame%len(frames)])
	width := r.width()
	for _, t := range r.tasks {
		f := frame
		if t.done {
			f = " "
		}
		// Lines are cut short of the terminal's width, as a wrapped line
		// would throw off the count moving up relies on.
		r.pending.WriteString(truncate(t.label(f), width-1) + "\x1b[K\n")
	}
	for _, a := range r.inProgress {
		label := itemIndent + frame + " " + a.name
		if r.floor != a.h {
			label += r.p.dim("  " + a.h.name)
		}
		r.pending.WriteString(truncate(label, width-1) + "\x1b[K\n")
	}
	// Clears anything left below from a longer list.
	r.pending.WriteString("\x1b[J")
	r.drawn = len(r.tasks) + len(r.inProgress)
	r.moved = false
}

func (r *renderer) tick() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		r.lock()
		if len(r.tasks) == 0 && len(r.inProgress) == 0 {
			r.ticking = false
			r.unlock()
			return
		}
		r.frame++
		r.unlock()
	}
}

func (r *renderer) width() int {
	if f, ok := r.w.(*os.File); ok {
		if w, _, err := term.GetSize(int(f.Fd())); err == nil && w > 0 {
			return w
		}
	}
	return 80
}

// printable replaces control characters other than newlines and tabs, and
// bytes that aren't UTF-8, with Go escapes such as \x1b, so text from a host
// is shown rather than acted on by the terminal.
func printable(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, isUnprintable) {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		switch {
		case c == utf8.RuneError && !strings.HasPrefix(s[i:], string(utf8.RuneError)):
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case isUnprintable(c):
			q := strconv.QuoteRune(c)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

func isUnprintable(c rune) bool {
	return unicode.IsControl(c) && c != '\n' && c != '\t' || unicode.Is(unicode.Cf, c)
}

// truncate cuts s to width visible characters, skipping colour codes.
func truncate(s string, width int) string {
	var b strings.Builder
	visible, inEscape := 0, false
	for _, c := range s {
		switch {
		case inEscape:
			inEscape = c != 'm'
		case c == '\x1b':
			inEscape = true
		case visible == width:
			return b.String() + "\x1b[0m"
		default:
			visible++
		}
		b.WriteRune(c)
	}
	return b.String()
}

// agents shows each host's connection as it finishes.
func (r *renderer) agents(runs []*hostRun) {
	r.section("Connecting to agents")
	var wg sync.WaitGroup
	for _, h := range runs {
		t := r.beginItem(h.name)
		wg.Go(
			func() {
				<-h.done
				switch {
				case h.err != nil:
					r.finish(t, indentItems(r.p.failure(h.name+": "+h.err.Error()))...)
				case h.upgraded:
					r.finish(t, itemIndent+r.p.handler("↑")+" "+h.name+r.p.dim("  upgraded"))
				default:
					r.finish(t, itemIndent+r.p.ok("✓")+" "+h.name)
				}
			},
		)
	}
	wg.Wait()
}

// plan shows each connected host's plan as it finishes.
func (r *renderer) plan(runs []*hostRun) {
	var wg sync.WaitGroup
	for _, h := range runs {
		if h.agent == nil {
			continue
		}
		t := r.beginSection("Resolving changes on " + h.name)
		wg.Go(
			func() {
				<-h.done
				r.finish(t, indentItems(hostPlanLines(h, r.p))...)
			},
		)
	}
	wg.Wait()
}

func indentItems(lines []string) []string {
	for i, l := range lines {
		lines[i] = itemIndent + l
	}
	return lines
}

func (r *renderer) dnsLines(dns dnsPlan) []string {
	lines := make([]string, 0, len(dns.changes)+len(dns.warnings)+len(dns.errs)+1)
	for _, c := range dns.changes {
		for _, l := range c.lines() {
			mark, rest, _ := strings.Cut(l, " ")
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
	}
	for _, w := range dns.warnings {
		lines = append(lines, r.p.warning(w)...)
	}
	for _, err := range dns.errs {
		lines = append(lines, r.p.failure(err.Error())...)
	}
	if dns.unchanged > 0 {
		lines = append(lines, r.p.dim(fmt.Sprintf("✓ %d unchanged", dns.unchanged)))
	}
	return indentItems(lines)
}

func hostPlanLines(h *hostRun, p palette) []string {
	if h.err != nil {
		return p.failure(h.err.Error())
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
			lines = append(lines, p.failure(name+": "+c.Error)...)
		}
		if c.Warning != "" {
			lines = append(lines, p.change("!")+" "+name)
			lines = append(lines, indent(c.Warning, "  ")...)
		}
	}
	if unchanged > 0 {
		lines = append(lines, p.dim(fmt.Sprintf("✓ %d unchanged", unchanged)))
	}
	return lines
}

type applyingItem struct {
	h    *hostRun
	name string
}

// applying shows what h has started changing until its result arrives.
func (r *renderer) applying(h *hostRun, a host.Applying) {
	r.lock()
	defer r.unlock()
	r.startApplyLocked(h)
	if !r.live {
		return
	}
	r.stopApplyingLocked(h)
	r.inProgress = append(r.inProgress, applyingItem{h: h, name: displayID(a.ID)})
	r.tickLocked()
}

func (r *renderer) stopApplyingLocked(h *hostRun) {
	r.inProgress = slices.DeleteFunc(r.inProgress, func(a applyingItem) bool { return a.h == h })
}

// applied shows one streamed result. Results for resources arrive in the
// order they were checked, so their position tells which were deferred.
func (r *renderer) applied(h *hostRun, a host.Applied) {
	r.lock()
	defer r.unlock()
	r.stopApplyingLocked(h)
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
		if a.Warning != "" {
			r.applyLineLocked(h, r.p.change("!")+" "+name)
			for _, l := range indent(a.Warning, "  ") {
				r.applyLineLocked(h, l)
			}
		}
	case host.StatusInSync:
		if deferred {
			r.applyLineLocked(h, r.p.dim("✓ "+name+"  unchanged"))
		}
	case host.StatusSkipped:
		r.skipped[h]++
	case host.StatusFailed:
		for _, l := range append(r.p.failure(name+": "+a.Error), indent(a.Output, "  ")...) {
			r.applyLineLocked(h, l)
		}
	default:
	}
}

func (r *renderer) applyError(h *hostRun, err error) {
	r.lock()
	defer r.unlock()
	r.stopApplyingLocked(h)
	for _, l := range r.p.failure(err.Error()) {
		r.applyLineLocked(h, l)
	}
}

// applyLineLocked adds a line to h's apply section, which streams if h holds
// the floor and is held otherwise.
func (r *renderer) applyLineLocked(h *hostRun, text string) {
	r.startApplyLocked(h)
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

// startApplyLocked writes or holds h's apply section header, the first time
// it's called for h.
func (r *renderer) startApplyLocked(h *hostRun) {
	if r.started[h] {
		return
	}
	r.started[h] = true
	header := r.header("Applying changes on " + h.name)
	if r.floor == nil {
		r.floor = h
		r.writeLocked(header)
	} else {
		r.held = append(r.held, &heldSection{h: h, lines: []string{header}})
	}
}

// applyDone ends h's apply section, passing the floor on if h held it.
func (r *renderer) applyDone(h *hostRun) {
	r.lock()
	defer r.unlock()
	r.stopApplyingLocked(h)
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

// dnsApply shows a DNS change with a spinner while apply makes it.
func (r *renderer) dnsApply(c *dnsChange, apply func() error) error {
	name := c.types() + " " + c.fqdn
	t := r.beginItem(name)
	if err := apply(); err != nil {
		r.finish(t, indentItems(r.p.failure(name+": "+err.Error()))...)
		return err
	}
	r.finish(t, itemIndent+r.p.ok("✓")+" "+name)
	return nil
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
	answer, err := askOnTerminal(prompt)
	return answer == "y" || answer == "yes", err
}

func askOnTerminal(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errNoTerminal
	}
	defer func() { _ = tty.Close() }()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(line)), nil
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
