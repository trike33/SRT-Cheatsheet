package shell

import (
	"sort"
	"strings"
)

// Argument-level completion and highlighting. The first word is a command
// name (completeCommandName); the words after it get flag names (learned from
// `srt <cmd> -h`, see help.go), the fixed keywords a command takes, or a path.

// keywordArgs lists the fixed words a command accepts in its first argument.
// "help" completes to command names and is handled separately.
var keywordArgs = map[string][]string{
	"db":    {"path", "stats", "import", "rm"},
	"limit": {"rate", "bytes", "off"},
	"color": {"on", "off", "auto"},
	"save":  {"on", "off"},
}

// wordAtCursor describes the word under the cursor: where it starts, what has
// been typed of it, the command (first word), and the 1-based position among
// the arguments.
func (m shellModel) wordAtCursor() (start int, word, cmd string, argPos int, ok bool) {
	toks := tokenizeLineWithSpans(m.input)
	if len(toks) == 0 || m.cursor <= toks[0].end {
		return 0, "", "", 0, false
	}
	cmd = toks[0].text
	start, argPos = m.cursor, len(toks) // fresh empty word after the last token
	for i := 1; i < len(toks); i++ {
		if m.cursor > toks[i].start && m.cursor <= toks[i].end {
			start, argPos = toks[i].start, i
			break
		}
		if toks[i].end < m.cursor {
			continue
		}
		argPos = i // cursor sits in whitespace before toks[i]
		break
	}
	return start, string(m.input[start:m.cursor]), cmd, argPos, true
}

// completeArgWord completes the flag name or keyword under the cursor and
// reports whether it applied (even if ambiguous), so path completion is only
// tried for words that can be paths.
func (m *shellModel) completeArgWord() bool {
	start, word, cmd, argPos, ok := m.wordAtCursor()
	if !ok {
		return false
	}

	var cands []string
	switch {
	case strings.HasPrefix(word, "-"):
		h := m.helpCache[cmd]
		if h == nil || len(h.flags) == 0 || strings.Contains(word, "=") {
			return false
		}
		for _, f := range h.flags {
			cands = append(cands, "-"+f.Name)
		}
	case cmd == "help" && argPos == 1:
		cands = m.names
	case argPos == 1 && keywordArgs[cmd] != nil:
		cands = keywordArgs[cmd]
	default:
		return false
	}

	var matches []string
	for _, c := range cands {
		if strings.HasPrefix(c, word) {
			matches = append(matches, c)
		}
	}
	if len(matches) == 0 {
		return true
	}
	sort.Strings(matches)
	comp := commonPrefix(matches)
	if len(matches) == 1 {
		comp += " "
	} else if comp == word {
		return true
	}
	rest := m.input[m.cursor:]
	m.input = append(append([]rune{}, m.input[:start]...), []rune(comp)...)
	m.cursor = len(m.input)
	m.input = append(m.input, rest...)
	return true
}

// argClass classifies the argument token at index i (>= 1) for highlighting.
func (m shellModel) argClass(toks []lineToken, i int) tokClass {
	cmd, tok := toks[0].text, toks[i].text
	switch {
	case strings.HasPrefix(tok, "-") && !isNumber(tok):
		h := m.helpCache[cmd]
		if h == nil || len(h.flags) == 0 {
			return classFlag // flags not learned (yet): don't call anything wrong
		}
		name := strings.TrimLeft(tok, "-")
		if eq := strings.Index(name, "="); eq >= 0 {
			name = name[:eq]
		}
		for _, f := range h.flags {
			if f.Name == name {
				return classFlag
			}
		}
		if name == "h" || name == "help" {
			return classFlag
		}
		return classUnknown
	case strings.HasPrefix(tok, `"`) || strings.HasPrefix(tok, "'"):
		return classString
	case i == 1 && cmd == "help":
		if commandKnown(m.names, tok) {
			return classCommand
		}
		return classUnknown
	case i == 1 && keywordArgs[cmd] != nil:
		for _, k := range keywordArgs[cmd] {
			if k == tok {
				return classCommand
			}
		}
	}
	return classPlain
}

func isNumber(s string) bool {
	if len(s) < 2 {
		return false
	}
	for _, r := range s[1:] {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}
