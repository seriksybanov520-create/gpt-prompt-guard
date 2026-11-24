package gptguard

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxVariants            = 128
	maxEncodedTokenBytes   = 128 << 10
	maxDecodedBudgetBytes  = 256 << 10
)

var (
	longBase64Re           = regexp.MustCompile(`(?i)(?:[a-z0-9+/_-]{32,}={0,2})`)
	longHexRe              = regexp.MustCompile(`(?i)\b(?:0x)?[a-f0-9]{48,}\b`)
	urlEncodedRunRe        = regexp.MustCompile(`(?i)(?:%[0-9a-f]{2}){8,}`)
	base64TokenRe          = regexp.MustCompile(`(?i)[a-z0-9+/_-]{32,}={0,2}`)
	multilineBase64BlockRe = regexp.MustCompile(`(?i)(?:[a-z0-9+/_-]{40,}(?:\r?\n)){2,}[a-z0-9+/_-]{4,}={0,2}`)
	hexTokenRe             = regexp.MustCompile(`(?i)(?:0x)?[a-f0-9]{48,}`)
)

var separatedKeywordWords = []string{
	"ignore",
	"disregard",
	"previous",
	"instructions",
	"instruction",
	"reveal",
	"hidden",
	"system",
	"prompt",
	"developer",
	"mode",
	"bypass",
	"safety",
	"override",
	"unrestricted",
	"jailbreak",
	"verbatim",
	"sandbox",
	"fixture",
	"executor",
	"supersede",
	"superseded",
	"dan",
	"activated",
	"by",
}

var separatedKeywordsByFirstByte = buildSeparatedKeywordsByFirstByte(separatedKeywordWords)

func buildSeparatedKeywordsByFirstByte(words []string) [26][]string {
	sorted := append([]string(nil), words...)
	sort.SliceStable(sorted, func(left, right int) bool {
		return len(sorted[left]) > len(sorted[right])
	})
	var table [26][]string
	for _, w := range sorted {
		if len(w) == 0 {
			continue
		}
		if c := w[0]; c >= 'a' && c <= 'z' {
			table[c-'a'] = append(table[c-'a'], w)
		}
	}
	return table
}

func boundedTokens(re *regexp.Regexp, text string, limit int) []string {
	if limit <= 0 || text == "" {
		return nil
	}
	firstLimit := limit / 2
	lastLimit := limit - firstLimit
	first := make([]string, 0, firstLimit)
	last := make([]string, lastLimit)
	lastCount := 0
	lastIndex := 0
	for offset := 0; offset < len(text); {
		match := re.FindStringIndex(text[offset:])
		if match == nil {
			break
		}
		start := offset + match[0]
		end := offset + match[1]
		token := text[start:end]
		if len(first) < firstLimit {
			first = append(first, token)
		} else if lastLimit > 0 {
			last[lastIndex] = token
			lastIndex = (lastIndex + 1) % lastLimit
			if lastCount < lastLimit {
				lastCount++
			}
		}
		if end <= offset {
			offset++
		} else {
			offset = end
		}
	}

	result := make([]string, 0, len(first)+lastCount)
	result = append(result, first...)
	if lastCount < lastLimit {
		result = append(result, last[:lastCount]...)
		return result
	}
	for index := 0; index < lastCount; index++ {
		result = append(result, last[(lastIndex+index)%lastLimit])
	}
	return result
}

func mergeVariantSources(current, addition string) string {
	if current == "" {
		return addition
	}
	if addition == "" {
		return current
	}
	seen := make(map[string]struct{})
	parts := make([]string, 0, 4)
	for _, source := range strings.Split(current+"+"+addition, "+") {
		if source == "" {
			continue
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		parts = append(parts, source)
	}
	return strings.Join(parts, "+")
}

func (g *Guard) generateVariants(raw string) []textVariant {
	seen := map[string]int{}
	variants := make([]textVariant, 0, 12)
	addNormalized := func(normalized, source string) {
		if normalized == "" {
			return
		}
		if index, ok := seen[normalized]; ok {
			variants[index].Source = mergeVariantSources(variants[index].Source, source)
			return
		}
		if len(variants) >= maxVariants {
			return
		}
		seen[normalized] = len(variants)
		variants = append(variants, textVariant{Source: source, Text: normalized})
	}
	add := func(value, source string) {
		addNormalized(NormalizeText(value), source)
	}
	addWithCanonical := func(value, source string) {
		baseline := NormalizeText(value)
		addNormalized(baseline, source)
		if cjkFolded, changed := foldTraditionalChineseAndCompactHanSpaces(baseline); changed {
			addNormalized(cjkFolded, source)
		}
		normalized, derivedSource := canonicalText(value, baseline)
		mergedSource := mergeVariantSources(source, derivedSource)
		addNormalized(normalized, mergedSource)
		if cjkCanonical, changed := foldTraditionalChineseAndCompactHanSpaces(normalized); changed {
			addNormalized(cjkCanonical, mergedSource)
		}
		if cyrFolded, changed := foldLatinHomoglyphsInCyrillicWords(baseline); changed {
			cyrSource := mergeVariantSources(source, "unicode-confusable")
			addNormalized(cyrFolded, cyrSource)
			addNormalized(normalizeCyrillicLayoutAliases(cyrFolded), cyrSource)
		}
	}

	addWithCanonical(raw, "")
	for _, variant := range keyboardLayoutVariants(raw) {
		addWithCanonical(variant.Text, variant.Source)
		add(normalizeCyrillicLayoutAliases(variant.Text), variant.Source)
	}

	if looksLikeRot13(raw) {
		rotated := rot13Text(raw)
		baseline := NormalizeText(rotated)
		normalized, source := canonicalText(rotated, baseline)
		if g.containsKnownSignal(normalized) {
			addNormalized(normalized, mergeVariantSources("rot13", source))
		}
	}

	type encodedCandidate struct {
		Text   string
		Source string
		Depth  int
	}
	encodedQueue := []encodedCandidate{{Text: raw}}
	seenEncodedCandidates := map[string]struct{}{raw: {}}
	decodedBudget := maxDecodedBudgetBytes
	for queueIndex := 0; queueIndex < len(encodedQueue) && queueIndex < 32; queueIndex++ {
		candidate := encodedQueue[queueIndex]
		if candidate.Depth >= 2 || decodedBudget <= 0 {
			continue
		}
		queueDecoded := func(decoded, source string) {
			if decoded == "" {
				return
			}
			source = mergeVariantSources(candidate.Source, source)
			addWithCanonical(decoded, source)
			if _, ok := seenEncodedCandidates[decoded]; ok {
				return
			}
			seenEncodedCandidates[decoded] = struct{}{}
			encodedQueue = append(encodedQueue, encodedCandidate{
				Text:   decoded,
				Source: source,
				Depth:  candidate.Depth + 1,
			})
		}

		decodeBase64Token := func(token string) {
			if len(token) == 0 || len(token) > maxEncodedTokenBytes || decodedBudget <= 0 {
				return
			}
			for _, decoder := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				decoded, err := decoder.DecodeString(token)
				if err == nil && utf8.Valid(decoded) {
					decodedBudget -= len(decoded)
					queueDecoded(string(decoded), "base64")
					break
				}
			}
		}

		if strings.Contains(candidate.Text, "\n") {
			for _, block := range boundedTokens(multilineBase64BlockRe, candidate.Text, 8) {
				if len(block) > maxEncodedTokenBytes+4096 || decodedBudget <= 0 {
					continue
				}
				compact := strings.NewReplacer("\r", "", "\n", "").Replace(block)
				decodeBase64Token(compact)
			}
		}
		for _, token := range boundedTokens(base64TokenRe, candidate.Text, 32) {
			if decodedBudget <= 0 {
				break
			}
			decodeBase64Token(token)
		}
		for _, token := range boundedTokens(hexTokenRe, candidate.Text, 32) {
			if decodedBudget <= 0 {
				break
			}
			if strings.HasPrefix(strings.ToLower(token), "0x") {
				token = token[2:]
			}
			if len(token) > maxEncodedTokenBytes || len(token)%2 != 0 {
				continue
			}
			if decoded, err := hex.DecodeString(token); err == nil && utf8.Valid(decoded) {
				decodedBudget -= len(decoded)
				queueDecoded(string(decoded), "hex")
			}
		}
	}
	return variants
}

func canonicalText(text, normalized string) (string, string) {
	source := ""
	textChanged := false
	if hasCompatibilityRune(text) {
		source = mergeVariantSources(source, "unicode-compatibility")
	}
	if decoded, htmlEncoded, urlEncoded := decodeTransportEncoding(text); decoded != text {
		text = decoded
		textChanged = true
		if htmlEncoded {
			source = mergeVariantSources(source, "html-entity")
		}
		if urlEncoded {
			source = mergeVariantSources(source, "url-escape")
		}
	}
	if decoded, unicodeEscapes, hexEscapes := decodeEscapes(text); decoded != text {
		text = decoded
		textChanged = true
		if unicodeEscapes {
			source = mergeVariantSources(source, "unicode-escape")
		}
		if hexEscapes {
			source = mergeVariantSources(source, "hex-escape")
		}
	}
	if decoded, changed := decodeUnicodeTags(text); changed {
		text = decoded
		textChanged = true
		source = mergeVariantSources(source, "unicode-tags")
	}
	if hasInvisibleWordSplit(text) {
		source = mergeVariantSources(source, "unicode-invisible")
	}
	if hasSeparatedKeyword(text) {
		source = mergeVariantSources(source, "separator-compaction")
	}

	if textChanged || normalized == "" {
		normalized = NormalizeText(text)
	}
	if folded, changed := foldConfusables(normalized); changed {
		normalized = folded
		source = mergeVariantSources(source, "unicode-confusable")
	}
	if decoded, changed := foldLeetspeak(normalized); changed {
		normalized = decoded
		source = mergeVariantSources(source, "leetspeak")
	}
	normalized = collapseSeparatedKeywords(normalized)
	if separated, changed := normalizeWordSeparators(normalized); changed {
		normalized = separated
		source = mergeVariantSources(source, "separator-compaction")
	}
	if corrected, changed := correctTypoglycemia(normalized); changed {
		normalized = corrected
		source = mergeVariantSources(source, "typoglycemia")
	}
	return collapseAndTrimSpaces(normalized), source
}

func hasCompatibilityRune(text string) bool {
	for _, r := range text {
		switch {
		case r >= 0x2100 && r <= 0x214f:
			return true
		case r >= 0x2160 && r <= 0x2188:
			return true
		case r >= 0x2460 && r <= 0x24ff:
			return true
		case r >= 0xfb00 && r <= 0xfb06:
			return true
		case r >= 0xff00 && r <= 0xffef:
			return true
		case r >= 0x1d400 && r <= 0x1d7ff:
			return true
		}
	}
	return false
}

func decodeTransportEncoding(text string) (string, bool, bool) {
	decoded := text
	if strings.IndexByte(text, '&') >= 0 {
		decoded = html.UnescapeString(text)
	}
	htmlEncoded := decoded != text
	urlEncoded := false
	for index := 0; index < 2 && strings.Contains(decoded, "%"); index++ {
		value, err := url.QueryUnescape(decoded)
		if err != nil || value == decoded {
			break
		}
		if strings.IndexByte(value, '&') >= 0 {
			value = html.UnescapeString(value)
		}
		decoded = value
		urlEncoded = true
	}
	return decoded, htmlEncoded, urlEncoded
}

func isASCIIWordByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func foldASCIIOrSpecialRune(text string, pos int) (lower byte, width int, isWord bool) {
	b := text[pos]
	if b < 0x80 {
		if b >= 'A' && b <= 'Z' {
			return b + ('a' - 'A'), 1, true
		}
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
			return b, 1, true
		}
		return 0, 1, false
	}
	r, w := utf8.DecodeRuneInString(text[pos:])
	switch r {
	case '\u017f':
		return 's', w, false
	case '\u212a':
		return 'k', w, false
	default:
		return 0, w, false
	}
}

func isSeparatedKeywordAlnumPrev(text string, pos int) bool {
	if pos <= 0 {
		return false
	}
	b := text[pos-1]
	if b < 0x80 {
		return isASCIIWordByte(b)
	}
	r, _ := utf8.DecodeLastRuneInString(text[:pos])
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isSeparatedKeywordAlnumAt(text string, pos int) bool {
	if pos >= len(text) {
		return false
	}
	b := text[pos]
	if b < 0x80 {
		return isASCIIWordByte(b)
	}
	r, _ := utf8.DecodeRuneInString(text[pos:])
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func matchSeparatedKeywordAt(text string, start int) (end int, hasNonAlnum bool, ok bool) {
	if isSeparatedKeywordAlnumPrev(text, start) {
		return 0, false, false
	}
	firstLower, firstWidth, _ := foldASCIIOrSpecialRune(text, start)
	if firstLower < 'a' || firstLower > 'z' {
		return 0, false, false
	}
	candidates := separatedKeywordsByFirstByte[firstLower-'a']
	if len(candidates) == 0 {
		return 0, false, false
	}
	for _, word := range candidates {
		pos := start + firstWidth
		nonAlnum := false
		if firstWidth > 1 {
			r, _ := utf8.DecodeRuneInString(text[start:])
			nonAlnum = !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}
		matched := true
		for wi := 1; wi < len(word); wi++ {
			target := word[wi]
			for pos < len(text) {
				b := text[pos]
				if b < 0x80 {
					if isASCIIWordByte(b) {
						break
					}
					nonAlnum = true
					pos++
					continue
				}
				r, w := utf8.DecodeRuneInString(text[pos:])
				if (r == '\u017f' && target == 's') || (r == '\u212a' && target == 'k') {
					break
				}
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
					nonAlnum = true
				}
				pos += w
			}
			if pos >= len(text) {
				matched = false
				break
			}
			chLower, chWidth, _ := foldASCIIOrSpecialRune(text, pos)
			if chLower != target {
				matched = false
				break
			}
			if chWidth > 1 {
				r, _ := utf8.DecodeRuneInString(text[pos:])
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
					nonAlnum = true
				}
			}
			pos += chWidth
		}
		if matched {
			if nonAlnum && len(word) <= 4 && isSeparatedKeywordAlnumAt(text, pos) {
				continue
			}
			return pos, nonAlnum, true
		}
	}
	return 0, false, false
}

func collapseSeparatedKeywords(text string) string {
	var b strings.Builder
	copiedUntil := 0
	for i := 0; i < len(text); {
		if end, hasNonAlnum, ok := matchSeparatedKeywordAt(text, i); ok {
			if hasNonAlnum {
				if copiedUntil == 0 && b.Cap() == 0 {
					b.Grow(len(text))
				}
				b.WriteString(text[copiedUntil:i])
				for _, r := range text[i:end] {
					if unicode.IsLetter(r) || unicode.IsDigit(r) {
						b.WriteRune(r)
					}
				}
				copiedUntil = end
			}
			i = end
			continue
		}
		if text[i] < 0x80 {
			i++
		} else {
			_, w := utf8.DecodeRuneInString(text[i:])
			i += w
		}
	}
	if copiedUntil == 0 {
		return text
	}
	b.WriteString(text[copiedUntil:])
	return b.String()
}

func hasSeparatedKeyword(text string) bool {
	for i := 0; i < len(text); {
		if end, hasNonAlnum, ok := matchSeparatedKeywordAt(text, i); ok {
			if hasNonAlnum {
				return true
			}
			i = end
			continue
		}
		if text[i] < 0x80 {
			i++
		} else {
			_, w := utf8.DecodeRuneInString(text[i:])
			i += w
		}
	}
	return false
}

func decodeEscapes(text string) (string, bool, bool) {
	if !strings.Contains(text, `\`) {
		return text, false, false
	}
	var b strings.Builder
	b.Grow(len(text))
	unicodeEscapes := false
	hexEscapes := false
	for index := 0; index < len(text); {
		if text[index] != '\\' || index+1 >= len(text) {
			b.WriteByte(text[index])
			index++
			continue
		}
		escapeType := text[index+1]
		digits := 0
		switch escapeType {
		case 'u':
			digits = 4
		case 'U':
			digits = 8
		case 'x':
			digits = 2
		}
		if digits == 0 || index+2+digits > len(text) {
			b.WriteByte(text[index])
			index++
			continue
		}
		value, err := strconv.ParseUint(text[index+2:index+2+digits], 16, 32)
		if err != nil {
			b.WriteByte(text[index])
			index++
			continue
		}
		if escapeType == 'x' {
			b.WriteByte(byte(value))
			hexEscapes = true
		} else {
			r := rune(value)
			if !utf8.ValidRune(r) || (r >= 0xd800 && r <= 0xdfff) {
				b.WriteString(text[index : index+2+digits])
				index += 2 + digits
				continue
			}
			b.WriteRune(r)
			unicodeEscapes = true
		}
		index += 2 + digits
	}
	decoded := b.String()
	if (!unicodeEscapes && !hexEscapes) || !utf8.ValidString(decoded) {
		return text, false, false
	}
	return decoded, unicodeEscapes, hexEscapes
}

func decodeUnicodeTags(text string) (string, bool) {
	hasTags := false
	for _, r := range text {
		if r == 0xe0001 || (r >= 0xe0020 && r <= 0xe007f) {
			hasTags = true
			break
		}
	}
	if !hasTags {
		return text, false
	}
	changed := false
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		switch {
		case r == 0xe0001 || r == 0xe007f:
			changed = true
		case r >= 0xe0020 && r <= 0xe007e:
			b.WriteRune(r - 0xe0000)
			changed = true
		default:
			b.WriteRune(r)
		}
	}
	if !changed {
		return text, false
	}
	return b.String(), true
}

func isIgnorableRune(r rune) bool {
	return unicode.Is(unicode.Cf, r) ||
		r == 0x034f ||
		r == 0x0640 || // Arabic tatweel / kashida
		(r >= 0xfe00 && r <= 0xfe0f) ||
		(r >= 0xe0100 && r <= 0xe01ef) ||
		(r >= 0xe0000 && r <= 0xe007f)
}

// HasZeroWidthStegEnvelope detects framed base-4 / binary zero-width
// steganography envelopes (`U+2063 U+2063` + >=32 `{U+200B,U+200C,U+200D,U+2060}`
// + `U+2064 U+2064`) used to smuggle hidden payloads or watermarks.
func HasZeroWidthStegEnvelope(text string) bool {
	const openMarker = "\u2063\u2063"
	const closeMarker = "\u2064\u2064"
	offset := 0
	for offset < len(text) {
		rel := strings.Index(text[offset:], openMarker)
		if rel < 0 {
			return false
		}
		pos := offset + rel + len(openMarker)
		zwCount := 0
		for pos < len(text) {
			r, w := utf8.DecodeRuneInString(text[pos:])
			if r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\u2060' {
				zwCount++
				pos += w
				continue
			}
			break
		}
		if zwCount >= 32 && strings.HasPrefix(text[pos:], closeMarker) {
			return true
		}
		offset = pos
	}
	return false
}

func hasInvisibleWordSplit(text string) bool {
	hasNonASCII := false
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			hasNonASCII = true
			break
		}
	}
	if !hasNonASCII {
		return false
	}
	prevAlnum := false
	pendingIgnorableAfterAlnum := false
	for i := 0; i < len(text); {
		r, w := utf8.DecodeRuneInString(text[i:])
		i += w
		if isIgnorableRune(r) {
			if prevAlnum {
				pendingIgnorableAfterAlnum = true
			}
			prevAlnum = false
			continue
		}
		alnum := unicode.IsLetter(r) || unicode.IsDigit(r)
		if pendingIgnorableAfterAlnum && alnum {
			return true
		}
		pendingIgnorableAfterAlnum = false
		prevAlnum = alnum
	}
	return false
}

var confusableRunes = map[rune]rune{
	'а': 'a', 'е': 'e', 'ё': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
	'у': 'y', 'к': 'k', 'м': 'm', 'т': 't', 'в': 'b', 'н': 'h', 'і': 'i',
	'ї': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
	'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'μ': 'm', 'ν': 'v',
	'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'y', 'χ': 'x', 'ϲ': 'c', 'ı': 'i',
}

func foldConfusables(text string) (string, bool) {
	hasConfusable := false
	for _, r := range text {
		if _, ok := confusableRunes[r]; ok {
			hasConfusable = true
			break
		}
	}
	if !hasConfusable {
		return text, false
	}
	changed := false
	folded := strings.Map(func(r rune) rune {
		if replacement, ok := confusableRunes[r]; ok {
			changed = true
			return replacement
		}
		return r
	}, text)
	return folded, changed
}

func mapLatinHomoglyphToCyrillic(r rune) (rune, bool) {
	switch r {
	case 'a':
		return 'а', true
	case 'b':
		return 'в', true
	case 'c':
		return 'с', true
	case 'e':
		return 'е', true
	case 'h':
		return 'н', true
	case 'k':
		return 'к', true
	case 'm':
		return 'м', true
	case 'n':
		return 'п', true
	case 'o':
		return 'о', true
	case 'p':
		return 'р', true
	case 't':
		return 'т', true
	case 'u':
		return 'и', true
	case 'x':
		return 'х', true
	case 'y':
		return 'у', true
	case '6':
		return 'б', true
	case '0':
		return 'о', true
	default:
		return r, false
	}
}

func hasMixedCyrillicHomoglyphWord(text string) bool {
	hasNonASCII := false
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			hasNonASCII = true
			break
		}
	}
	if !hasNonASCII {
		return false
	}
	for i := 0; i < len(text); {
		r, w := utf8.DecodeRuneInString(text[i:])
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			i += w
			continue
		}
		hasCyr := false
		hasFoldable := false
		for i < len(text) {
			wr, ww := utf8.DecodeRuneInString(text[i:])
			if !unicode.IsLetter(wr) && !unicode.IsDigit(wr) {
				break
			}
			if unicode.Is(unicode.Cyrillic, wr) {
				hasCyr = true
			} else if _, ok := mapLatinHomoglyphToCyrillic(wr); ok {
				hasFoldable = true
			}
			if hasCyr && hasFoldable {
				return true
			}
			i += ww
		}
	}
	return false
}

func foldLatinHomoglyphsInCyrillicWords(text string) (string, bool) {
	if !hasMixedCyrillicHomoglyphWord(text) {
		return text, false
	}
	runes := []rune(text)
	changed := false
	for start := 0; start < len(runes); {
		if !unicode.IsLetter(runes[start]) && !unicode.IsDigit(runes[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(runes) && (unicode.IsLetter(runes[end]) || unicode.IsDigit(runes[end])) {
			end++
		}
		hasCyr := false
		hasFoldable := false
		for i := start; i < end; i++ {
			r := runes[i]
			if unicode.Is(unicode.Cyrillic, r) {
				hasCyr = true
			} else if _, ok := mapLatinHomoglyphToCyrillic(r); ok {
				hasFoldable = true
			}
		}
		if hasCyr && hasFoldable {
			for i := start; i < end; i++ {
				if repl, ok := mapLatinHomoglyphToCyrillic(runes[i]); ok {
					runes[i] = repl
					changed = true
				}
			}
		}
		start = end
	}
	if !changed {
		return text, false
	}
	return string(runes), true
}

func isLeetTriggerByte(b byte) bool {
	switch b {
	case '0', '1', '3', '4', '5', '7', '@', '$':
		return true
	default:
		return false
	}
}

func foldLeetspeak(text string) (string, bool) {
	hasTrigger := false
	for i := 0; i < len(text); i++ {
		if isLeetTriggerByte(text[i]) {
			hasTrigger = true
			break
		}
	}
	if !hasTrigger {
		return text, false
	}
	runes := []rune(text)
	changed := false
	for index, r := range runes {
		var replacement rune
		switch r {
		case '0':
			replacement = 'o'
		case '1':
			replacement = 'i'
		case '3':
			replacement = 'e'
		case '4', '@':
			replacement = 'a'
		case '5', '$':
			replacement = 's'
		case '7':
			replacement = 't'
		default:
			continue
		}
		leftLetter := index > 0 && unicode.IsLetter(runes[index-1])
		rightLetter := index+1 < len(runes) && unicode.IsLetter(runes[index+1])
		if leftLetter || rightLetter {
			runes[index] = replacement
			changed = true
		}
	}
	if !changed {
		return text, false
	}
	return string(runes), true
}

func hasInternalPunctOrSymbolInToken(text string) bool {
	for i := 0; i < len(text); {
		r, w := utf8.DecodeRuneInString(text[i:])
		if unicode.IsSpace(r) {
			i += w
			continue
		}
		seenAlnum := false
		seenMidPunct := false
		for i < len(text) {
			tr, tw := utf8.DecodeRuneInString(text[i:])
			if unicode.IsSpace(tr) {
				break
			}
			if unicode.IsLetter(tr) || unicode.IsDigit(tr) {
				if seenMidPunct {
					return true
				}
				seenAlnum = true
			} else if seenAlnum && (unicode.IsPunct(tr) || unicode.IsSymbol(tr)) {
				seenMidPunct = true
			}
			i += tw
		}
	}
	return false
}

func normalizeWordSeparators(text string) (string, bool) {
	if !hasInternalPunctOrSymbolInToken(text) {
		return collapseAndTrimSpaces(text), false
	}
	runes := []rune(text)
	changed := false
	for start := 0; start < len(runes); {
		for start < len(runes) && unicode.IsSpace(runes[start]) {
			start++
		}
		end := start
		for end < len(runes) && !unicode.IsSpace(runes[end]) {
			end++
		}
		firstWord := -1
		lastWord := -1
		for index := start; index < end; index++ {
			if unicode.IsLetter(runes[index]) || unicode.IsDigit(runes[index]) {
				if firstWord == -1 {
					firstWord = index
				}
				lastWord = index
			}
		}
		if firstWord >= 0 && lastWord > firstWord {
			for index := firstWord + 1; index < lastWord; index++ {
				if unicode.IsPunct(runes[index]) || unicode.IsSymbol(runes[index]) {
					runes[index] = ' '
					changed = true
				}
			}
		}
		start = end
	}
	if !changed {
		return collapseAndTrimSpaces(text), false
	}
	return collapseAndTrimSpaces(string(runes)), true
}

var typoglycemiaWords = []string{
	"ignore", "previous", "instruction", "instructions", "disregard",
	"developer", "system", "reveal", "hidden", "prompt", "bypass",
	"safety", "restrictions", "unrestricted", "jailbreak", "verbatim",
	"sandbox", "fixture", "executor", "supersede", "superseded",
	"override", "follow", "assistant", "policy", "policies",
	"refusal", "decode", "encoded", "execute",
}

var (
	typoglycemiaIndex     = buildTypoglycemiaIndex(typoglycemiaWords)
	typoglycemiaFastShape = buildTypoglycemiaFastShape(typoglycemiaWords)
)

func buildTypoglycemiaFastShape(words []string) [32][26][26]bool {
	var table [32][26][26]bool
	for _, w := range words {
		if len(w) >= 5 && len(w) < 32 && w[0] >= 'a' && w[0] <= 'z' && w[len(w)-1] >= 'a' && w[len(w)-1] <= 'z' {
			table[len(w)][w[0]-'a'][w[len(w)-1]-'a'] = true
		}
	}
	return table
}

func buildTypoglycemiaIndex(words []string) map[string]string {
	index := make(map[string]string, len(words))
	for _, word := range words {
		key := typoglycemiaKey(word)
		if existing, ok := index[key]; ok && existing != word {
			index[key] = ""
			continue
		}
		index[key] = word
	}
	return index
}

func typoglycemiaKey(word string) string {
	runes := []rune(word)
	if len(runes) < 5 {
		return ""
	}
	middle := append([]rune(nil), runes[1:len(runes)-1]...)
	sort.Slice(middle, func(i, j int) bool { return middle[i] < middle[j] })
	return strconv.Itoa(len(runes)) + ":" + string(runes[0]) + ":" + string(middle) + ":" + string(runes[len(runes)-1])
}

func correctTypoglycemia(text string) (string, bool) {
	var b strings.Builder
	copiedUntil := 0
	var midBuf [32]byte
	for i := 0; i < len(text); {
		r, w := utf8.DecodeRuneInString(text[i:])
		if !unicode.IsLetter(r) {
			i += w
			continue
		}
		wordStart := i
		asciiLower := true
		for i < len(text) {
			wr, ww := utf8.DecodeRuneInString(text[i:])
			if !unicode.IsLetter(wr) {
				break
			}
			if wr < 'a' || wr > 'z' {
				asciiLower = false
			}
			i += ww
		}
		wordEnd := i
		wordLen := wordEnd - wordStart
		if asciiLower && wordLen >= 5 && wordLen < 32 {
			first := text[wordStart]
			last := text[wordEnd-1]
			if typoglycemiaFastShape[wordLen][first-'a'][last-'a'] {
				candidate := text[wordStart:wordEnd]
				midLen := wordLen - 2
				copy(midBuf[:midLen], candidate[1:wordLen-1])
				midSlice := midBuf[:midLen]
				for a := 1; a < midLen; a++ {
					keyByte := midSlice[a]
					j := a - 1
					for j >= 0 && midSlice[j] > keyByte {
						midSlice[j+1] = midSlice[j]
						j--
					}
					midSlice[j+1] = keyByte
				}
				key := strconv.Itoa(wordLen) + ":" + string(first) + ":" + string(midSlice) + ":" + string(last)
				if replacement := typoglycemiaIndex[key]; replacement != "" && replacement != candidate {
					if copiedUntil == 0 && b.Cap() == 0 {
						b.Grow(len(text))
					}
					b.WriteString(text[copiedUntil:wordStart])
					b.WriteString(replacement)
					copiedUntil = wordEnd
				}
			}
		}
	}
	if copiedUntil == 0 {
		return text, false
	}
	b.WriteString(text[copiedUntil:])
	return b.String(), true
}

func rot13Text(text string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			return r
		}
	}, text)
}

func looksLikeRot13(text string) bool {
	lower := strings.ToLower(text)
	hits := 0
	for _, marker := range []string{
		"vtaber", "cerivbhf", "vafgehpg", "qrirybcre", "zbqr", "erirny",
		"flfgrz", "cebzcg", "olcnff", "bireevqr", "fnsrgl", "haerfgevpgrq",
		"fnaqobk", "wnvyoernx", "ireongvz", "vawrpgrq", "genafnpgvba",
		"svkgher", "ershfny", "genafpevcg", "jbexfcnpr", "obhaqnel",
		"cbyvpl", "ivpgvz",
	} {
		if strings.Contains(lower, marker) {
			hits++
			if hits >= 2 {
				return true
			}
		}
	}
	return false
}

func scoreObfuscationSignals(raw, normalized string, categorySet, reasonSet map[string]struct{}) int {
	score := 0
	add := func(points int, category, reason string) {
		score += points
		categorySet[category] = struct{}{}
		reasonSet[reason] = struct{}{}
	}
	if longBase64Re.MatchString(raw) || longBase64Re.MatchString(normalized) {
		add(2, "obfuscation_blob", "long_base64_like_blob")
	}
	if longHexRe.MatchString(raw) || longHexRe.MatchString(normalized) {
		add(2, "obfuscation_blob", "long_hex_like_blob")
	}
	if urlEncodedRunRe.MatchString(raw) {
		add(2, "obfuscation_blob", "url_encoded_run")
	}
	weakTerms := []string{"base64", "rot13", "hex encoded", "url encoded", "decode this", "eval(", "atob(", "fromcharcode"}
	weakHits := 0
	for _, term := range weakTerms {
		if strings.Contains(normalized, term) {
			weakHits++
		}
	}
	if weakHits >= 2 {
		add(2, "obfuscation_terms", "multiple_obfuscation_terms")
	}
	return score
}

func recordVariantSource(source string, categorySet, reasonSet map[string]struct{}) bool {
	if source == "" {
		return false
	}
	matched := false
	for _, variantSource := range strings.Split(source, "+") {
		if variantSource == "" {
			continue
		}
		matched = true
		categorySet["prompt_obfuscation"] = struct{}{}
		switch variantSource {
		case "en-ru", "en-uk":
			categorySet["keyboard_layout_obfuscation"] = struct{}{}
			reasonSet["keyboard_layout_variant:"+variantSource] = struct{}{}
		case "unicode-tags", "unicode-invisible":
			categorySet["unicode_smuggling"] = struct{}{}
			reasonSet["obfuscation_variant:"+variantSource] = struct{}{}
		case "unicode-confusable", "unicode-compatibility":
			categorySet["unicode_confusable_obfuscation"] = struct{}{}
			reasonSet["obfuscation_variant:"+variantSource] = struct{}{}
		case "typoglycemia":
			categorySet["typoglycemia_obfuscation"] = struct{}{}
			reasonSet["obfuscation_variant:"+variantSource] = struct{}{}
		case "separator-compaction":
			categorySet["separator_obfuscation"] = struct{}{}
			reasonSet["obfuscation_variant:"+variantSource] = struct{}{}
		case "leetspeak":
			categorySet["leetspeak_obfuscation"] = struct{}{}
			reasonSet["obfuscation_variant:"+variantSource] = struct{}{}
		case "base64", "hex", "rot13", "unicode-escape", "hex-escape", "html-entity", "url-escape":
			categorySet["encoded_payload_obfuscation"] = struct{}{}
			reasonSet["obfuscation_variant:"+variantSource] = struct{}{}
		default:
			reasonSet["obfuscation_variant:"+variantSource] = struct{}{}
		}
	}
	return matched
}

var traditionalToSimplifiedChineseReplacer = strings.NewReplacer(
	"與", "与", "業", "业", "兩", "两", "嚴", "严", "個", "个", "爲", "为", "為", "为",
	"舉", "举", "義", "义", "書", "书", "亂", "乱", "爭", "争", "於", "于", "產", "产",
	"僅", "仅", "從", "从", "倉", "仓", "儀", "仪", "價", "价", "衆", "众", "眾", "众",
	"會", "会", "傳", "传", "僞", "伪", "偽", "伪", "體", "体", "餘", "余", "來", "来",
	"備", "备", "內", "内", "冊", "册", "寫", "写", "農", "农", "衝", "冲", "決", "决",
	"憑", "凭", "擊", "击", "刪", "删", "別", "别", "創", "创", "劑", "剂", "則", "则",
	"務", "务", "動", "动", "區", "区", "協", "协", "單", "单", "佔", "占", "卻", "却",
	"廠", "厂", "參", "参", "雙", "双", "發", "发", "髮", "发", "變", "变", "敘", "叙",
	"敍", "叙", "號", "号", "隻", "只", "臺", "台", "啓", "启", "啟", "启", "員", "员",
	"問", "问", "嗎", "吗", "園", "园", "圍", "围", "圖", "图", "國", "国", "場", "场",
	"塊", "块", "執", "执", "報", "报", "壓", "压", "壞", "坏", "聲", "声", "處", "处",
	"複", "复", "復", "复", "夠", "够", "頭", "头", "夾", "夹", "學", "学", "實", "实",
	"審", "审", "將", "将", "專", "专", "對", "对", "導", "导", "層", "层", "屬", "属",
	"帶", "带", "並", "并", "廣", "广", "庫", "库", "應", "应", "廢", "废", "開", "开",
	"異", "异", "棄", "弃", "張", "张", "彈", "弹", "強", "强", "歸", "归", "當", "当",
	"錄", "录", "彙", "汇", "匯", "汇", "後", "后", "徵", "征", "徹", "彻", "態", "态",
	"戀", "恋", "惡", "恶", "戲", "戏", "戶", "户", "掃", "扫", "擬", "拟", "攔", "拦",
	"掛", "挂", "換", "换", "據", "据", "損", "损", "數", "数", "斷", "断", "無", "无",
	"舊", "旧", "時", "时", "暫", "暂", "術", "术", "機", "机", "殺", "杀", "權", "权",
	"條", "条", "構", "构", "極", "极", "標", "标", "樣", "样", "樁", "桩", "檢", "检",
	"檔", "档", "殼", "壳", "毀", "毁", "氣", "气", "沒", "没", "測", "测", "瀏", "浏",
	"準", "准", "滅", "灭", "溫", "温", "遊", "游", "漸", "渐", "滿", "满", "濾", "滤",
	"點", "点", "熱", "热", "愛", "爱", "狀", "状", "獨", "独", "獄", "狱", "獻", "献",
	"環", "环", "現", "现", "電", "电", "畫", "画", "癥", "症", "監", "监", "蓋", "盖",
	"盤", "盘", "盡", "尽", "碼", "码", "確", "确", "礙", "碍", "禮", "礼", "稱", "称",
	"種", "种", "穩", "稳", "簡", "简", "簽", "签", "節", "节", "範", "范", "類", "类",
	"係", "系", "繫", "系", "約", "约", "級", "级", "紀", "纪", "純", "纯", "綱", "纲",
	"紋", "纹", "線", "线", "綫", "线", "組", "组", "細", "细", "終", "终", "經", "经",
	"綁", "绑", "結", "结", "繞", "绕", "給", "给", "絡", "络", "絕", "绝", "統", "统",
	"繼", "继", "續", "续", "維", "维", "綜", "综", "緩", "缓", "編", "编", "縮", "缩",
	"總", "总", "網", "网", "緊", "紧", "罰", "罚", "習", "习", "職", "职", "聯", "联",
	"聽", "听", "脫", "脱", "臨", "临", "興", "兴", "藝", "艺", "萬", "万", "葉", "叶",
	"著", "着", "獲", "获", "營", "营", "虛", "虚", "補", "补", "裝", "装", "製", "制",
	"見", "见", "規", "规", "視", "视", "覺", "觉", "覽", "览", "觀", "观", "觸", "触",
	"計", "计", "訂", "订", "認", "认", "訊", "讯", "討", "讨", "訓", "训", "記", "记",
	"許", "许", "論", "论", "設", "设", "證", "证", "証", "证", "評", "评", "識", "识",
	"詞", "词", "試", "试", "詰", "诘", "話", "话", "誡", "诫", "該", "该", "詳", "详",
	"語", "语", "誤", "误", "說", "说", "請", "请", "諸", "诸", "讀", "读", "課", "课",
	"誰", "谁", "調", "调", "談", "谈", "諾", "诺", "謀", "谋", "謂", "谓", "講", "讲",
	"謝", "谢", "訴", "诉", "詢", "询", "譎", "谲", "詭", "诡", "議", "议", "譯", "译",
	"護", "护", "讓", "让", "責", "责", "敗", "败", "賬", "账", "帳", "帐", "貨", "货",
	"質", "质", "購", "购", "貼", "贴", "轉", "转", "輪", "轮", "軟", "软", "輕", "轻",
	"載", "载", "較", "较", "輔", "辅", "輯", "辑", "輸", "输", "辭", "辞", "辦", "办",
	"邊", "边", "達", "达", "過", "过", "運", "运", "還", "还", "這", "这", "進", "进",
	"遠", "远", "違", "违", "連", "连", "適", "适", "選", "选", "遺", "遗", "遙", "遥",
	"邏", "逻", "郵", "邮", "鄰", "邻", "採", "采", "釋", "释", "針", "针", "鐘", "钟",
	"鑰", "钥", "鉤", "钩", "鈎", "钩", "鏈", "链", "鎖", "锁", "錯", "错", "鍵", "键",
	"長", "长", "門", "门", "閃", "闪", "閉", "闭", "間", "间", "閱", "阅", "闡", "阐",
	"閾", "阈", "隊", "队", "陳", "陈", "險", "险", "隨", "随", "隱", "隐", "雖", "虽",
	"雜", "杂", "離", "离", "難", "难", "靜", "静", "響", "响", "頁", "页", "頂", "顶",
	"項", "项", "順", "顺", "須", "须", "預", "预", "領", "领", "額", "额", "頻", "频",
	"題", "题", "顏", "颜", "願", "愿", "顧", "顾", "顯", "显", "風", "风", "飛", "飞",
	"養", "养", "馬", "马", "驅", "驱", "驗", "验", "鷗", "鸥", "麵", "面", "黨", "党",
	"齊", "齐", "裏", "里", "裡", "里", "羣", "群", "註", "注",
)

func isHanRune(r rune) bool {
	return (r >= 0x3400 && r <= 0x9fff) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0x20000 && r <= 0x2ebef)
}

func hasHanRune(s string) bool {
	for i := 0; i < len(s); {
		if s[i] < 0x80 {
			i++
			continue
		}
		r, w := utf8.DecodeRuneInString(s[i:])
		if isHanRune(r) {
			return true
		}
		i += w
	}
	return false
}

func foldTraditionalChineseAndCompactHanSpaces(text string) (string, bool) {
	if !hasHanRune(text) {
		return text, false
	}
	folded := traditionalToSimplifiedChineseReplacer.Replace(text)
	var b strings.Builder
	b.Grow(len(folded))
	prevHan := false
	pendingSpace := false
	compacted := false
	for i := 0; i < len(folded); {
		r, w := utf8.DecodeRuneInString(folded[i:])
		i += w
		if r == ' ' {
			if prevHan {
				pendingSpace = true
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		curHan := isHanRune(r)
		if pendingSpace {
			if curHan {
				compacted = true
			} else {
				b.WriteByte(' ')
			}
			pendingSpace = false
		}
		b.WriteRune(r)
		prevHan = curHan
	}
	if pendingSpace {
		b.WriteByte(' ')
	}
	out := b.String()
	return out, compacted || out != text
}
