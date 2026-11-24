package gptguard

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tidwall/gjson"
	"golang.org/x/text/unicode/norm"
)

const fieldSeparator = "\u2550\u2550\u2550"

var (
	zeroWidthRe = regexp.MustCompile(`[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{206F}\x{FEFF}]`)
)

func hasNonASCIIByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

// NormalizeText produces a canonical lowercase, NFKC-normalized, HTML/URL-unescaped,
// zero-width-stripped, punctuation-folded representation for deterministic inspection.
// It never mutates the caller's request payload.
func NormalizeText(text string) string {
	normalized := text
	nonASCII := hasNonASCIIByte(normalized)
	if nonASCII && !norm.NFKC.IsNormalString(normalized) {
		normalized = norm.NFKC.String(normalized)
	}
	if strings.IndexByte(normalized, '&') >= 0 {
		normalized = html.UnescapeString(normalized)
	}
	if nonASCII && hasZeroWidthUTF8LeadByte(normalized) {
		normalized = zeroWidthRe.ReplaceAllString(normalized, "")
	}
	normalized = strings.ToLower(normalized)

	for i := 0; i < 2 && strings.ContainsAny(normalized, "%+"); i++ {
		decoded, err := url.QueryUnescape(normalized)
		if err != nil || decoded == normalized {
			break
		}
		if strings.IndexByte(decoded, '&') >= 0 {
			decoded = html.UnescapeString(decoded)
		}
		normalized = decoded
	}

	normalized = strings.Map(func(r rune) rune {
		if isIgnorableRune(r) {
			return -1
		}
		switch r {
		case '`', '*', '_', '~', '>', '<', '[', ']', '(', ')', '{', '}', '"', '\'', '|', '«', '»', '·',
			'「', '」', '『', '』', '【', '】', '《', '》', '〈', '〉', '〔', '〕', '・',
			'\u2018', '\u2019', '\u201a', '\u201b', '\u201c', '\u201d', '\u201e', '\u201f', '\u2039', '\u203a', '\u2032', '\u2033',
			'\u115f', '\u1160', '\u2800', '\u3164', '\uffa0':
			return ' '
		default:
			if (r >= '\u2800' && r <= '\u28ff') || unicode.IsControl(r) || unicode.IsSpace(r) {
				return ' '
			}
			return r
		}
	}, normalized)

	normalized = collapseSeparatedKeywords(normalized)
	return collapseAndTrimSpaces(normalized)
}

func literalText(text string) string {
	return strings.ToLower(strings.Join(strings.Fields(text), " "))
}

func hasZeroWidthUTF8LeadByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0xe2 || s[i] == 0xef {
			return true
		}
	}
	return false
}

func collapseAndTrimSpaces(s string) string {
	n := len(s)
	if n == 0 {
		return ""
	}
	needsChange := false
	prevSpace := true
	for i := 0; i < n; {
		b := s[i]
		if b < 0x80 {
			isSp := b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
			if isSp {
				if b != ' ' || prevSpace {
					needsChange = true
					break
				}
				prevSpace = true
			} else {
				prevSpace = false
			}
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		if unicode.IsSpace(r) {
			needsChange = true
			break
		}
		prevSpace = false
		i += w
	}
	if !needsChange && !prevSpace {
		return s
	}

	var b strings.Builder
	b.Grow(n)
	inSpace := false
	started := false
	for i := 0; i < n; {
		c := s[i]
		if c < 0x80 {
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
				if started {
					inSpace = true
				}
			} else {
				if inSpace {
					b.WriteByte(' ')
					inSpace = false
				}
				b.WriteByte(c)
				started = true
			}
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		if unicode.IsSpace(r) {
			if started {
				inSpace = true
			}
		} else {
			if inSpace {
				b.WriteByte(' ')
				inSpace = false
			}
			b.WriteString(s[i : i+w])
			started = true
		}
		i += w
	}
	return b.String()
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func containsWordBounded(haystack, pattern string) bool {
	if haystack == "" || pattern == "" {
		return false
	}
	firstRune, _ := utf8.DecodeRuneInString(pattern)
	lastRune, _ := utf8.DecodeLastRuneInString(pattern)
	checkLeft := isWordRune(firstRune) && !unicode.Is(unicode.Han, firstRune)
	checkRight := isWordRune(lastRune) && !unicode.Is(unicode.Han, lastRune)
	if !checkLeft && !checkRight {
		return strings.Contains(haystack, pattern)
	}

	offset := 0
	for offset <= len(haystack)-len(pattern) {
		rel := strings.Index(haystack[offset:], pattern)
		if rel < 0 {
			return false
		}
		start := offset + rel
		end := start + len(pattern)
		leftOK := true
		if checkLeft && start > 0 {
			prevRune, _ := utf8.DecodeLastRuneInString(haystack[:start])
			if isWordRune(prevRune) {
				leftOK = false
			}
		}
		rightOK := true
		if checkRight && end < len(haystack) {
			nextRune, _ := utf8.DecodeRuneInString(haystack[end:])
			if isWordRune(nextRune) {
				rightOK = false
			}
		}
		if leftOK && rightOK {
			return true
		}
		offset = start + 1
	}
	return false
}

func containsAllSignals(normalized string, patterns []string) bool {
	for _, pattern := range patterns {
		if !strings.Contains(normalized, pattern) {
			return false
		}
	}
	return true
}

func expandRuneWindowToWordBounds(s string, matchStart, matchEnd, maxRunes int) (int, int) {
	if maxRunes <= 0 {
		return matchStart, matchEnd
	}
	start := matchStart
	for count := 0; count < maxRunes && start > 0; count++ {
		_, size := utf8.DecodeLastRuneInString(s[:start])
		start -= size
	}
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:start])
		if !isWordRune(r) {
			break
		}
		start -= size
	}
	end := matchEnd
	for count := 0; count < maxRunes && end < len(s); count++ {
		_, size := utf8.DecodeRuneInString(s[end:])
		end += size
	}
	for end < len(s) {
		r, size := utf8.DecodeRuneInString(s[end:])
		if !isWordRune(r) {
			break
		}
		end += size
	}
	return start, end
}

func matchesCompositeSignals(normalized string, patterns []string, maxWindowRunes int) bool {
	if len(patterns) == 0 {
		return false
	}
	if maxWindowRunes <= 0 || len(patterns) == 1 {
		return containsAllSignals(normalized, patterns)
	}
	anchor := patterns[0]
	if anchor == "" || len(normalized) < len(anchor) {
		return false
	}
	rest := patterns[1:]
	offset := 0
	for count := 0; count < 512 && offset <= len(normalized)-len(anchor); count++ {
		rel := strings.Index(normalized[offset:], anchor)
		if rel < 0 {
			break
		}
		pos := offset + rel
		winStart, winEnd := expandRuneWindowToWordBounds(normalized, pos, pos+len(anchor), maxWindowRunes)
		window := normalized[winStart:winEnd]
		anchorRel := pos - winStart
		if sepBefore := strings.LastIndex(window[:anchorRel], fieldSeparator); sepBefore >= 0 {
			shift := sepBefore + len(fieldSeparator)
			window = window[shift:]
			anchorRel -= shift
		}
		if sepAfter := strings.Index(window[anchorRel+len(anchor):], fieldSeparator); sepAfter >= 0 {
			window = window[:anchorRel+len(anchor)+sepAfter]
		}
		if containsAllSignals(window, rest) {
			return true
		}
		offset = pos + len(anchor)
	}
	return false
}

func sliceUTF8Safe(s string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	for start < end && !utf8.RuneStart(s[start]) {
		start++
	}
	for end > start && end < len(s) && !utf8.RuneStart(s[end]) {
		end--
	}
	if start >= end {
		return ""
	}
	return s[start:end]
}

// sampleLargeText extracts five UTF-8-safe windows (Head, Q1, Mid, Q3, Tail)
// across oversized strings so an attacker cannot hide a payload past a fixed
// prefix or inside the middle of a multi-megabyte request.
func sampleLargeText(s string, totalBudget int) string {
	if totalBudget <= 0 {
		return ""
	}
	if len(s) <= totalBudget {
		return s
	}
	if totalBudget < 2048 {
		half := totalBudget / 2
		return sliceUTF8Safe(s, 0, half) + "\n" + sliceUTF8Safe(s, len(s)-(totalBudget-half), len(s))
	}

	head := (totalBudget * 3) / 10
	tail := (totalBudget * 3) / 10
	interior := (totalBudget - head - tail) / 3
	if interior <= 0 {
		return sliceUTF8Safe(s, 0, head) + "\n" + sliceUTF8Safe(s, len(s)-tail, len(s))
	}

	n := len(s)
	q1Start := n/4 - interior/2
	midStart := n/2 - interior/2
	q3Start := (3*n)/4 - interior/2

	parts := []string{
		sliceUTF8Safe(s, 0, head),
		sliceUTF8Safe(s, q1Start, q1Start+interior),
		sliceUTF8Safe(s, midStart, midStart+interior),
		sliceUTF8Safe(s, q3Start, q3Start+interior),
		sliceUTF8Safe(s, n-tail, n),
	}
	return strings.Join(parts, "\n")
}

func isValidJSONEnvelope(body []byte) bool {
	if !gjson.ValidBytes(body) {
		return false
	}
	value := gjson.ParseBytes(body)
	return value.IsObject() || value.IsArray()
}

func isTurnArrayKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "messages", "input", "contents", "tools":
		return true
	default:
		return false
	}
}

func isOpaqueOrMediaJSONString(key, text string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "b64_json", "thoughtsignature", "thought_signature", "encrypted_content":
		return true
	case "signature":
		probe := text
		if len(probe) > 512 {
			probe = probe[:512]
		}
		if len(text) > 64 && !strings.ContainsAny(probe, " \t\r\n") {
			return true
		}
	case "audio":
		if len(text) > 512 && !strings.ContainsAny(text[:512], " \t\r\n") {
			return true
		}
	case "identifier", "role", "mimetype", "mime_type", "cache_control", "tool_call_id", "call_id":
		if len(text) <= 64 {
			return true
		}
	case "data":
		if len(text) > 4096 {
			probe := text
			if len(probe) > 512 {
				probe = probe[:512]
			}
			if !strings.ContainsAny(probe, " \t\r\n") {
				return true
			}
		}
	}
	if len(text) > 128 && (strings.HasPrefix(text, "data:") || strings.HasPrefix(text, "DATA:")) {
		headerEnd := len(text)
		if headerEnd > 96 {
			headerEnd = 96
		}
		header := strings.ToLower(text[:headerEnd])
		if strings.HasPrefix(header, "data:image/") ||
			strings.HasPrefix(header, "data:audio/") ||
			strings.HasPrefix(header, "data:video/") ||
			strings.HasPrefix(header, "data:application/pdf") ||
			strings.HasPrefix(header, "data:application/octet-stream") {
			return true
		}
		if len(text) > 8192 && strings.Contains(header, ";base64,") {
			return true
		}
	}
	return false
}

func collectJSONStrings(body []byte, stringWindowBytes int, values *[]string, budget *int) {
	root := gjson.ParseBytes(body)
	appendSeparatorIfAdded := func(prevLen int) {
		if prevLen > 0 && len(*values) > prevLen && (*values)[prevLen-1] != fieldSeparator {
			*values = append(*values, "")
			copy((*values)[prevLen+1:], (*values)[prevLen:])
			(*values)[prevLen] = fieldSeparator
		}
	}
	var walk func(depth int, key string, value gjson.Result)
	walk = func(depth int, key string, value gjson.Result) {
		if *budget <= 0 {
			return
		}
		switch {
		case value.Type == gjson.String:
			text := value.String()
			if text == "" || isOpaqueOrMediaJSONString(key, text) {
				return
			}
			if len(text) > stringWindowBytes {
				text = sampleLargeText(text, stringWindowBytes)
			}
			if len(text) > *budget {
				text = sampleLargeText(text, *budget)
			}
			if text == "" {
				return
			}
			*values = append(*values, text)
			*budget -= len(text)
		case value.IsArray():
			splitElements := isTurnArrayKey(key)
			value.ForEach(func(_, child gjson.Result) bool {
				prevLen := len(*values)
				walk(depth+1, key, child)
				if splitElements {
					appendSeparatorIfAdded(prevLen)
				}
				return *budget > 0
			})
		case value.IsObject():
			value.ForEach(func(childKey, child gjson.Result) bool {
				prevLen := len(*values)
				walk(depth+1, childKey.String(), child)
				if depth == 0 {
					appendSeparatorIfAdded(prevLen)
				}
				return *budget > 0
			})
		}
	}
	walk(0, "", root)
}
