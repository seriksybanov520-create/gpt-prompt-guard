package gptguard

import (
	"strings"
	"unicode/utf8"
)

// textVariant is an inspection-only alternate representation of input.
// The guard never mutates forwarded requests; variants exist solely for scoring.
type textVariant struct {
	Source string
	Text   string
}

var (
	englishKeyboardRunes   = []rune("`qwertyuiop[]asdfghjkl;'zxcvbnm,./")
	russianKeyboardRunes   = []rune("ёйцукенгшщзхъфывапролджэячсмитьбю.")
	ukrainianKeyboardRunes = []rune("`йцукенгшщзхїфівапролджєячсмитьбю.")
	russianKeyboardMap     = makeKeyboardLayoutMap(englishKeyboardRunes, russianKeyboardRunes)
	ukrainianKeyboardMap   = makeKeyboardLayoutMap(englishKeyboardRunes, ukrainianKeyboardRunes)
)

func makeKeyboardLayoutMap(from, to []rune) map[rune]rune {
	if len(from) != len(to) {
		panic("keyboard layout maps must have equal length")
	}
	result := make(map[rune]rune, len(from))
	for index, source := range from {
		if source == '/' || source == to[index] {
			continue
		}
		if !isASCIIKeyboardLetter(source) && !strings.ContainsRune("`[];',.", source) {
			continue
		}
		result[source] = to[index]
	}
	return result
}

func isASCIIKeyboardLetter(r rune) bool {
	return r >= 'a' && r <= 'z'
}

func isKeyboardLayoutWordKey(r rune) bool {
	if isASCIIKeyboardLetter(r) {
		return true
	}
	switch r {
	case '[', ']', ';', '\'', ',':
		return true
	default:
		return false
	}
}

func isCyrillicLetter(r rune) bool {
	return (r >= '\u0400' && r <= '\u052f') || (r >= '\u2de0' && r <= '\u2dff')
}

func mapKeyboardLayoutText(value string, mapping map[rune]rune) (string, int) {
	var b strings.Builder
	b.Grow(len(value) * 2)
	decodedCyrillic := 0
	var prevRune rune
	for i := 0; i < len(value); {
		r, w := utf8.DecodeRuneInString(value[i:])
		var nextRune rune
		if i+w < len(value) {
			nextRune, _ = utf8.DecodeRuneInString(value[i+w:])
		}
		out := r
		switch r {
		case ',', '.':
			if isKeyboardLayoutWordKey(nextRune) {
				if replacement, ok := mapping[r]; ok {
					out = replacement
				}
			}
		case '`', '~':
			if prevRune != '`' && nextRune != '`' && prevRune != '~' && nextRune != '~' &&
				(isKeyboardLayoutWordKey(prevRune) || isKeyboardLayoutWordKey(nextRune)) {
				if replacement, ok := mapping['`']; ok {
					out = replacement
				}
			}
		default:
			if replacement, ok := mapping[r]; ok {
				out = replacement
			}
		}
		if isCyrillicLetter(out) {
			decodedCyrillic++
		}
		b.WriteRune(out)
		prevRune = r
		i += w
	}
	return b.String(), decodedCyrillic
}

// looksLikeKeyboardLayoutCyrillicSegment uses letter-frequency distribution to
// identify Russian/Ukrainian text typed on an English QWERTY layout embedded
// inside mixed-script payloads, without mangling ordinary English prose or code.
func looksLikeKeyboardLayoutCyrillicSegment(seg string) bool {
	asciiLetters := 0
	aoiCount := 0
	commonCyrKeys := 0
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c >= 'a' && c <= 'z' {
			asciiLetters++
			switch c {
			case 'a', 'o', 'i':
				aoiCount++
			case 'j', 't', 'f', 'b', 'y', 'n', 'c', 'h', 'd':
				commonCyrKeys++
			}
		}
	}
	if asciiLetters < 12 {
		return false
	}
	return aoiCount*100 <= asciiLetters*14 && commonCyrKeys*100 >= asciiLetters*40
}

func decodeMixedScriptKeyboardLayout(value, name string, mapping map[rune]rune) (textVariant, bool) {
	type span struct {
		start int
		end   int
	}
	var decodeSpans []span
	segStart := -1
	flushSegment := func(segEnd int) {
		if segStart < 0 {
			return
		}
		if segEnd-segStart >= 12 && looksLikeKeyboardLayoutCyrillicSegment(value[segStart:segEnd]) {
			decodeSpans = append(decodeSpans, span{start: segStart, end: segEnd})
		}
		segStart = -1
	}

	for i := 0; i < len(value); {
		r, w := utf8.DecodeRuneInString(value[i:])
		if r == '\n' || r == '\r' || isCyrillicLetter(r) {
			flushSegment(i)
		} else if segStart < 0 {
			segStart = i
		}
		i += w
	}
	flushSegment(len(value))

	if len(decodeSpans) == 0 {
		return textVariant{}, false
	}

	var b strings.Builder
	b.Grow(len(value) + 128)
	cursor := 0
	decodedCyrillic := 0
	for _, sp := range decodeSpans {
		if sp.start > cursor {
			b.WriteString(value[cursor:sp.start])
		}
		decodedSeg, segCyr := mapKeyboardLayoutText(value[sp.start:sp.end], mapping)
		b.WriteString(decodedSeg)
		decodedCyrillic += segCyr
		cursor = sp.end
	}
	if cursor < len(value) {
		b.WriteString(value[cursor:])
	}
	if decodedCyrillic < 3 {
		return textVariant{}, false
	}
	return textVariant{Source: name, Text: b.String()}, true
}

func decodeKeyboardLayout(raw, name string, mapping map[rune]rune) (textVariant, bool) {
	value := strings.ToLower(raw)
	letters := 0
	asciiLetters := 0
	for _, r := range value {
		switch {
		case isASCIIKeyboardLetter(r):
			letters++
			asciiLetters++
		case isCyrillicLetter(r):
			letters++
		}
	}
	if asciiLetters < 4 || letters == 0 {
		return textVariant{}, false
	}
	if asciiLetters*100 < letters*80 {
		return decodeMixedScriptKeyboardLayout(value, name, mapping)
	}
	if asciiLetters >= 24 && !looksLikeKeyboardLayoutCyrillicSegment(value) {
		return decodeMixedScriptKeyboardLayout(value, name, mapping)
	}

	decoded, decodedCyrillic := mapKeyboardLayoutText(value, mapping)
	if decodedCyrillic < 3 {
		return textVariant{}, false
	}
	return textVariant{Source: name, Text: decoded}, true
}

func keyboardLayoutVariants(raw string) []textVariant {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	variants := make([]textVariant, 0, 2)
	if variant, ok := decodeKeyboardLayout(raw, "en-ru", russianKeyboardMap); ok {
		variants = append(variants, variant)
	}
	if variant, ok := decodeKeyboardLayout(raw, "en-uk", ukrainianKeyboardMap); ok {
		if len(variants) == 0 || variant.Text != variants[0].Text {
			variants = append(variants, variant)
		}
	}
	return variants
}

func normalizeCyrillicLayoutAliases(text string) string {
	return strings.NewReplacer(
		"і", "и", "ї", "и", "є", "е", "ґ", "г",
		"ы", "и", "э", "е", "ъ", "ь", "ё", "е",
	).Replace(text)
}
