package host

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	diffContext = 3
	// diffMaxCells caps the LCS table; larger changes are shown as a
	// wholesale replacement.
	diffMaxCells = 16 << 20
)

// unifiedDiff returns hunks in unified diff format, without file headers, or
// "" if old and updated are equal.
func unifiedDiff(old, updated string) string {
	if old == updated {
		return ""
	}
	ops := diffLines(splitLines(old), splitLines(updated))

	var out strings.Builder
	for start := 0; start < len(ops); {
		first := nextChange(ops, start)
		if first < 0 {
			break
		}
		begin := max(first-diffContext, start)
		end := first
		for {
			// end is the last change in this hunk.
			for end+1 < len(ops) && ops[end+1].kind != ' ' {
				end++
			}
			next := nextChange(ops, end+1)
			if next < 0 || next-end-1 > 2*diffContext {
				break
			}
			end = next
		}
		stop := min(end+diffContext+1, len(ops))
		writeHunk(&out, ops, begin, stop)
		start = stop
	}
	return out.String()
}

type diffOp struct {
	kind byte // ' ', '-' or '+'
	line string
	// oldLine and newLine are the 1-based positions the op would have in
	// each file.
	oldLine, newLine int
}

func nextChange(ops []diffOp, from int) int {
	for i := from; i < len(ops); i++ {
		if ops[i].kind != ' ' {
			return i
		}
	}
	return -1
}

func writeHunk(out *strings.Builder, ops []diffOp, begin, end int) {
	oldCount, newCount := 0, 0
	for _, op := range ops[begin:end] {
		if op.kind != '+' {
			oldCount++
		}
		if op.kind != '-' {
			newCount++
		}
	}
	oldStart, newStart := ops[begin].oldLine, ops[begin].newLine
	if oldCount == 0 {
		oldStart--
	}
	if newCount == 0 {
		newStart--
	}
	_, _ = fmt.Fprintf(out, "@@ -%s +%s @@\n", hunkRange(oldStart, oldCount), hunkRange(newStart, newCount))
	for _, op := range ops[begin:end] {
		out.WriteByte(op.kind)
		if strings.HasSuffix(op.line, "\n") {
			out.WriteString(op.line)
		} else {
			out.WriteString(op.line + "\n\\ No newline at end of file\n")
		}
	}
}

func hunkRange(start, count int) string {
	if count == 1 {
		return strconv.Itoa(start)
	}
	return fmt.Sprintf("%d,%d", start, count)
}

// splitLines splits s into lines, keeping their newlines.
func splitLines(s string) []string {
	var lines []string
	for line := range strings.Lines(s) {
		lines = append(lines, line)
	}
	return lines
}

func diffLines(a, b []string) []diffOp {
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}

	kinds := repeat(' ', prefix)
	kinds = append(kinds, lcsKinds(a[prefix:len(a)-suffix], b[prefix:len(b)-suffix])...)
	kinds = append(kinds, repeat(' ', suffix)...)

	ops := make([]diffOp, len(kinds))
	i, j := 0, 0
	for n, k := range kinds {
		ops[n] = diffOp{kind: k, oldLine: i + 1, newLine: j + 1}
		switch k {
		case ' ':
			ops[n].line = a[i]
			i++
			j++
		case '-':
			ops[n].line = a[i]
			i++
		default:
			ops[n].line = b[j]
			j++
		}
	}
	return ops
}

// lcsKinds returns the edit script turning a into b, preferring removals
// before additions.
func lcsKinds(a, b []string) []byte {
	n, m := len(a), len(b)
	if n*m > diffMaxCells || n == 0 || m == 0 {
		return append(repeat('-', n), repeat('+', m)...)
	}

	// lcs[i][j] is the length of the LCS of a[i:] and b[j:].
	width := m + 1
	lcs := make([]int32, (n+1)*width)
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i*width+j] = lcs[(i+1)*width+j+1] + 1
			} else {
				lcs[i*width+j] = max(lcs[(i+1)*width+j], lcs[i*width+j+1])
			}
		}
	}

	kinds := make([]byte, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			kinds = append(kinds, ' ')
			i++
			j++
		case lcs[(i+1)*width+j] >= lcs[i*width+j+1]:
			kinds = append(kinds, '-')
			i++
		default:
			kinds = append(kinds, '+')
			j++
		}
	}
	kinds = append(kinds, repeat('-', n-i)...)
	return append(kinds, repeat('+', m-j)...)
}

func repeat(b byte, n int) []byte {
	return []byte(strings.Repeat(string(b), n))
}
