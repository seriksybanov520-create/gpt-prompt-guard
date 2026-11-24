package gptguard

// automaton implements a byte-oriented Aho-Corasick multi-pattern prefilter
// backed by dynamically-sized bitmasks so custom private rulepacks of arbitrary
// size never overflow a fixed slot count while maintaining O(N) scan time.
type automaton struct {
	next      [][256]int32
	masks     []uint64 // flat matrix: len(next) * words
	hasHit    []bool
	patternID map[string]int
	words     int
}

func buildAutomaton(rules []Rule, compositeRules []CompositeRule, mandatoryRules []CompositeRule) *automaton {
	ac := &automaton{
		patternID: make(map[string]int, 256),
	}
	var needles []string
	register := func(pat string) {
		if pat == "" {
			return
		}
		if _, ok := ac.patternID[pat]; ok {
			return
		}
		ac.patternID[pat] = len(needles)
		needles = append(needles, pat)
	}
	for _, r := range rules {
		for _, p := range r.Patterns {
			register(p)
		}
	}
	for _, r := range compositeRules {
		for _, allOf := range r.AnyOf {
			if len(allOf) > 0 {
				register(allOf[0])
			}
		}
	}
	for _, r := range mandatoryRules {
		for _, allOf := range r.AnyOf {
			if len(allOf) > 0 {
				register(allOf[0])
			}
		}
	}

	ac.words = (len(needles) + 63) / 64
	if ac.words == 0 {
		ac.words = 1
	}

	newState := func() int32 {
		var row [256]int32
		for i := range row {
			row[i] = -1
		}
		idx := int32(len(ac.next))
		ac.next = append(ac.next, row)
		ac.masks = append(ac.masks, make([]uint64, ac.words)...)
		ac.hasHit = append(ac.hasHit, false)
		return idx
	}

	_ = newState() // root state 0
	for id, needle := range needles {
		cur := int32(0)
		for i := 0; i < len(needle); i++ {
			b := needle[i]
			nxt := ac.next[cur][b]
			if nxt == -1 {
				nxt = newState()
				ac.next[cur][b] = nxt
			}
			cur = nxt
		}
		base := int(cur) * ac.words
		ac.masks[base+(id>>6)] |= 1 << uint(id&63)
		ac.hasHit[cur] = true
	}

	fail := make([]int32, len(ac.next))
	queue := make([]int32, 0, len(ac.next))
	for b := 0; b < 256; b++ {
		if nxt := ac.next[0][b]; nxt != -1 {
			fail[nxt] = 0
			queue = append(queue, nxt)
		} else {
			ac.next[0][b] = 0
		}
	}
	for head := 0; head < len(queue); head++ {
		u := queue[head]
		fu := fail[u]
		for b := 0; b < 256; b++ {
			if v := ac.next[u][b]; v != -1 {
				f := ac.next[fu][b]
				fail[v] = f
				if ac.hasHit[f] {
					vBase := int(v) * ac.words
					fBase := int(f) * ac.words
					for w := 0; w < ac.words; w++ {
						ac.masks[vBase+w] |= ac.masks[fBase+w]
					}
					ac.hasHit[v] = true
				}
				queue = append(queue, v)
			} else {
				ac.next[u][b] = ac.next[fu][b]
			}
		}
	}
	return ac
}

// PatternCount returns the number of unique anchor patterns compiled into the
// Aho-Corasick automaton.
func (ac *automaton) patternCount() int {
	if ac == nil {
		return 0
	}
	return len(ac.patternID)
}

func (ac *automaton) scan(text string, present []uint64) bool {
	if ac == nil || len(ac.next) == 0 || text == "" {
		return false
	}
	for i := range present {
		present[i] = 0
	}
	anyHit := false
	state := int32(0)
	words := ac.words
	for i := 0; i < len(text); i++ {
		state = ac.next[state][text[i]]
		if ac.hasHit[state] {
			base := int(state) * words
			for w := 0; w < words; w++ {
				present[w] |= ac.masks[base+w]
			}
			anyHit = true
		}
	}
	return anyHit
}

func (ac *automaton) mayContain(present []uint64, pattern string) bool {
	if ac == nil {
		return true
	}
	id, ok := ac.patternID[pattern]
	if !ok {
		return true
	}
	word := id >> 6
	if word >= len(present) {
		return false
	}
	return (present[word] & (1 << uint(id&63))) != 0
}
