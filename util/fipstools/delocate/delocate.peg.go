package main

import (
	"fmt"
	"math"
	"sort"
	"strconv"
)

const endSymbol rune = 1114112

/* The rule types inferred from the grammar are below. */
type pegRule uint8

const (
	ruleUnknown pegRule = iota
	ruleAsmFile
	ruleStatement
	ruleGlobalDirective
	ruleDirective
	ruleDirectiveName
	ruleLocationDirective
	ruleFileDirective
	ruleLocDirective
	ruleArgs
	ruleArg
	ruleQuotedArg
	ruleQuotedText
	ruleLabelContainingDirective
	ruleLabelContainingDirectiveName
	ruleSymbolArgs
	ruleSymbolArg
	ruleSymbolType
	ruleDot
	ruleTCMarker
	ruleEscapedChar
	ruleWS
	ruleComment
	ruleLabel
	ruleSymbolName
	ruleLocalSymbol
	ruleLocalLabel
	ruleLocalLabelRef
	ruleInstruction
	ruleInstructionName
	ruleInstructionArg
	ruleGOTLocation
	ruleGOTSymbolOffset
	ruleAVX512Token
	ruleTOCRefHigh
	ruleTOCRefLow
	ruleIndirectionIndicator
	ruleRegisterOrConstant
	ruleARMConstantTweak
	ruleARMRegister
	ruleARMVectorRegister
	ruleMemoryRef
	ruleSymbolRef
	ruleLow12BitsSymbolRef
	ruleARMBaseIndexScale
	ruleARMGOTLow12
	ruleARMCapReference
	ruleARMPostincrement
	ruleBaseIndexScale
	ruleOperator
	ruleOffset
	ruleSection
	ruleSegmentRegister

	rulePre
	ruleIn
	ruleSuf
)

var rul3s = [...]string{
	"Unknown",
	"AsmFile",
	"Statement",
	"GlobalDirective",
	"Directive",
	"DirectiveName",
	"LocationDirective",
	"FileDirective",
	"LocDirective",
	"Args",
	"Arg",
	"QuotedArg",
	"QuotedText",
	"LabelContainingDirective",
	"LabelContainingDirectiveName",
	"SymbolArgs",
	"SymbolArg",
	"SymbolType",
	"Dot",
	"TCMarker",
	"EscapedChar",
	"WS",
	"Comment",
	"Label",
	"SymbolName",
	"LocalSymbol",
	"LocalLabel",
	"LocalLabelRef",
	"Instruction",
	"InstructionName",
	"InstructionArg",
	"GOTLocation",
	"GOTSymbolOffset",
	"AVX512Token",
	"TOCRefHigh",
	"TOCRefLow",
	"IndirectionIndicator",
	"RegisterOrConstant",
	"ARMConstantTweak",
	"ARMRegister",
	"ARMVectorRegister",
	"MemoryRef",
	"SymbolRef",
	"Low12BitsSymbolRef",
	"ARMBaseIndexScale",
	"ARMGOTLow12",
	"ARMCapReference",
	"ARMPostincrement",
	"BaseIndexScale",
	"Operator",
	"Offset",
	"Section",
	"SegmentRegister",

	"Pre_",
	"_In_",
	"_Suf",
}

type node32 struct {
	token32
	up, next *node32
}

func (node *node32) print(depth int, buffer string) {
	for node != nil {
		for c := 0; c < depth; c++ {
			fmt.Printf(" ")
		}
		fmt.Printf("\x1B[34m%v\x1B[m %v\n", rul3s[node.pegRule], strconv.Quote(string(([]rune(buffer)[node.begin:node.end]))))
		if node.up != nil {
			node.up.print(depth+1, buffer)
		}
		node = node.next
	}
}

func (node *node32) Print(buffer string) {
	node.print(0, buffer)
}

type element struct {
	node *node32
	down *element
}

/* ${@} bit structure for abstract syntax tree */
type token32 struct {
	pegRule
	begin, end, next uint32
}

func (t *token32) isZero() bool {
	return t.pegRule == ruleUnknown && t.begin == 0 && t.end == 0 && t.next == 0
}

func (t *token32) isParentOf(u token32) bool {
	return t.begin <= u.begin && t.end >= u.end && t.next > u.next
}

func (t *token32) getToken32() token32 {
	return token32{pegRule: t.pegRule, begin: uint32(t.begin), end: uint32(t.end), next: uint32(t.next)}
}

func (t *token32) String() string {
	return fmt.Sprintf("\x1B[34m%v\x1B[m %v %v %v", rul3s[t.pegRule], t.begin, t.end, t.next)
}

type tokens32 struct {
	tree    []token32
	ordered [][]token32
}

func (t *tokens32) trim(length int) {
	t.tree = t.tree[0:length]
}

func (t *tokens32) Print() {
	for _, token := range t.tree {
		fmt.Println(token.String())
	}
}

func (t *tokens32) Order() [][]token32 {
	if t.ordered != nil {
		return t.ordered
	}

	depths := make([]int32, 1, math.MaxInt16)
	for i, token := range t.tree {
		if token.pegRule == ruleUnknown {
			t.tree = t.tree[:i]
			break
		}
		depth := int(token.next)
		if length := len(depths); depth >= length {
			depths = depths[:depth+1]
		}
		depths[depth]++
	}
	depths = append(depths, 0)

	ordered, pool := make([][]token32, len(depths)), make([]token32, len(t.tree)+len(depths))
	for i, depth := range depths {
		depth++
		ordered[i], pool, depths[i] = pool[:depth], pool[depth:], 0
	}

	for i, token := range t.tree {
		depth := token.next
		token.next = uint32(i)
		ordered[depth][depths[depth]] = token
		depths[depth]++
	}
	t.ordered = ordered
	return ordered
}

type state32 struct {
	token32
	depths []int32
	leaf   bool
}

func (t *tokens32) AST() *node32 {
	tokens := t.Tokens()
	stack := &element{node: &node32{token32: <-tokens}}
	for token := range tokens {
		if token.begin == token.end {
			continue
		}
		node := &node32{token32: token}
		for stack != nil && stack.node.begin >= token.begin && stack.node.end <= token.end {
			stack.node.next = node.up
			node.up = stack.node
			stack = stack.down
		}
		stack = &element{node: node, down: stack}
	}
	return stack.node
}

func (t *tokens32) PreOrder() (<-chan state32, [][]token32) {
	s, ordered := make(chan state32, 6), t.Order()
	go func() {
		var states [8]state32
		for i := range states {
			states[i].depths = make([]int32, len(ordered))
		}
		depths, state, depth := make([]int32, len(ordered)), 0, 1
		write := func(t token32, leaf bool) {
			S := states[state]
			state, S.pegRule, S.begin, S.end, S.next, S.leaf = (state+1)%8, t.pegRule, t.begin, t.end, uint32(depth), leaf
			copy(S.depths, depths)
			s <- S
		}

		states[state].token32 = ordered[0][0]
		depths[0]++
		state++
		a, b := ordered[depth-1][depths[depth-1]-1], ordered[depth][depths[depth]]
	depthFirstSearch:
		for {
			for {
				if i := depths[depth]; i > 0 {
					if c, j := ordered[depth][i-1], depths[depth-1]; a.isParentOf(c) &&
						(j < 2 || !ordered[depth-1][j-2].isParentOf(c)) {
						if c.end != b.begin {
							write(token32{pegRule: ruleIn, begin: c.end, end: b.begin}, true)
						}
						break
					}
				}

				if a.begin < b.begin {
					write(token32{pegRule: rulePre, begin: a.begin, end: b.begin}, true)
				}
				break
			}

			next := depth + 1
			if c := ordered[next][depths[next]]; c.pegRule != ruleUnknown && b.isParentOf(c) {
				write(b, false)
				depths[depth]++
				depth, a, b = next, b, c
				continue
			}

			write(b, true)
			depths[depth]++
			c, parent := ordered[depth][depths[depth]], true
			for {
				if c.pegRule != ruleUnknown && a.isParentOf(c) {
					b = c
					continue depthFirstSearch
				} else if parent && b.end != a.end {
					write(token32{pegRule: ruleSuf, begin: b.end, end: a.end}, true)
				}

				depth--
				if depth > 0 {
					a, b, c = ordered[depth-1][depths[depth-1]-1], a, ordered[depth][depths[depth]]
					parent = a.isParentOf(b)
					continue
				}

				break depthFirstSearch
			}
		}

		close(s)
	}()
	return s, ordered
}

func (t *tokens32) PrintSyntax() {
	tokens, ordered := t.PreOrder()
	max := -1
	for token := range tokens {
		if !token.leaf {
			fmt.Printf("%v", token.begin)
			for i, leaf, depths := 0, int(token.next), token.depths; i < leaf; i++ {
				fmt.Printf(" \x1B[36m%v\x1B[m", rul3s[ordered[i][depths[i]-1].pegRule])
			}
			fmt.Printf(" \x1B[36m%v\x1B[m\n", rul3s[token.pegRule])
		} else if token.begin == token.end {
			fmt.Printf("%v", token.begin)
			for i, leaf, depths := 0, int(token.next), token.depths; i < leaf; i++ {
				fmt.Printf(" \x1B[31m%v\x1B[m", rul3s[ordered[i][depths[i]-1].pegRule])
			}
			fmt.Printf(" \x1B[31m%v\x1B[m\n", rul3s[token.pegRule])
		} else {
			for c, end := token.begin, token.end; c < end; c++ {
				if i := int(c); max+1 < i {
					for j := max; j < i; j++ {
						fmt.Printf("skip %v %v\n", j, token.String())
					}
					max = i
				} else if i := int(c); i <= max {
					for j := i; j <= max; j++ {
						fmt.Printf("dupe %v %v\n", j, token.String())
					}
				} else {
					max = int(c)
				}
				fmt.Printf("%v", c)
				for i, leaf, depths := 0, int(token.next), token.depths; i < leaf; i++ {
					fmt.Printf(" \x1B[34m%v\x1B[m", rul3s[ordered[i][depths[i]-1].pegRule])
				}
				fmt.Printf(" \x1B[34m%v\x1B[m\n", rul3s[token.pegRule])
			}
			fmt.Printf("\n")
		}
	}
}

func (t *tokens32) PrintSyntaxTree(buffer string) {
	tokens, _ := t.PreOrder()
	for token := range tokens {
		for c := 0; c < int(token.next); c++ {
			fmt.Printf(" ")
		}
		fmt.Printf("\x1B[34m%v\x1B[m %v\n", rul3s[token.pegRule], strconv.Quote(string(([]rune(buffer)[token.begin:token.end]))))
	}
}

func (t *tokens32) Add(rule pegRule, begin, end, depth uint32, index int) {
	t.tree[index] = token32{pegRule: rule, begin: uint32(begin), end: uint32(end), next: uint32(depth)}
}

func (t *tokens32) Tokens() <-chan token32 {
	s := make(chan token32, 16)
	go func() {
		for _, v := range t.tree {
			s <- v.getToken32()
		}
		close(s)
	}()
	return s
}

func (t *tokens32) Error() []token32 {
	ordered := t.Order()
	length := len(ordered)
	tokens, length := make([]token32, length), length-1
	for i := range tokens {
		o := ordered[length-i]
		if len(o) > 1 {
			tokens[i] = o[len(o)-2].getToken32()
		}
	}
	return tokens
}

func (t *tokens32) Expand(index int) {
	tree := t.tree
	if index >= len(tree) {
		expanded := make([]token32, 2*len(tree))
		copy(expanded, tree)
		t.tree = expanded
	}
}

type Asm struct {
	Buffer string
	buffer []rune
	rules  [53]func() bool
	Parse  func(rule ...int) error
	Reset  func()
	Pretty bool
	tokens32
}

type textPosition struct {
	line, symbol int
}

type textPositionMap map[int]textPosition

func translatePositions(buffer []rune, positions []int) textPositionMap {
	length, translations, j, line, symbol := len(positions), make(textPositionMap, len(positions)), 0, 1, 0
	sort.Ints(positions)

search:
	for i, c := range buffer {
		if c == '\n' {
			line, symbol = line+1, 0
		} else {
			symbol++
		}
		if i == positions[j] {
			translations[positions[j]] = textPosition{line, symbol}
			for j++; j < length; j++ {
				if i != positions[j] {
					continue search
				}
			}
			break search
		}
	}

	return translations
}

type parseError struct {
	p   *Asm
	max token32
}

func (e *parseError) Error() string {
	tokens, error := []token32{e.max}, "\n"
	positions, p := make([]int, 2*len(tokens)), 0
	for _, token := range tokens {
		positions[p], p = int(token.begin), p+1
		positions[p], p = int(token.end), p+1
	}
	translations := translatePositions(e.p.buffer, positions)
	format := "parse error near %v (line %v symbol %v - line %v symbol %v):\n%v\n"
	if e.p.Pretty {
		format = "parse error near \x1B[34m%v\x1B[m (line %v symbol %v - line %v symbol %v):\n%v\n"
	}
	for _, token := range tokens {
		begin, end := int(token.begin), int(token.end)
		error += fmt.Sprintf(format,
			rul3s[token.pegRule],
			translations[begin].line, translations[begin].symbol,
			translations[end].line, translations[end].symbol,
			strconv.Quote(string(e.p.buffer[begin:end])))
	}

	return error
}

func (p *Asm) PrintSyntaxTree() {
	p.tokens32.PrintSyntaxTree(p.Buffer)
}

func (p *Asm) Highlighter() {
	p.PrintSyntax()
}

func (p *Asm) Init() {
	p.buffer = []rune(p.Buffer)
	if len(p.buffer) == 0 || p.buffer[len(p.buffer)-1] != endSymbol {
		p.buffer = append(p.buffer, endSymbol)
	}

	tree := tokens32{tree: make([]token32, math.MaxInt16)}
	var max token32
	position, depth, tokenIndex, buffer, _rules := uint32(0), uint32(0), 0, p.buffer, p.rules

	p.Parse = func(rule ...int) error {
		r := 1
		if len(rule) > 0 {
			r = rule[0]
		}
		matches := p.rules[r]()
		p.tokens32 = tree
		if matches {
			p.trim(tokenIndex)
			return nil
		}
		return &parseError{p, max}
	}

	p.Reset = func() {
		position, tokenIndex, depth = 0, 0, 0
	}

	add := func(rule pegRule, begin uint32) {
		tree.Expand(tokenIndex)
		tree.Add(rule, begin, position, depth, tokenIndex)
		tokenIndex++
		if begin != position && position > max.end {
			max = token32{rule, begin, position, depth}
		}
	}

	matchDot := func() bool {
		if buffer[position] != endSymbol {
			position++
			return true
		}
		return false
	}

	/*matchChar := func(c byte) bool {
		if buffer[position] == c {
			position++
			return true
		}
		return false
	}*/

	/*matchRange := func(lower byte, upper byte) bool {
		if c := buffer[position]; c >= lower && c <= upper {
			position++
			return true
		}
		return false
	}*/

	_rules = [...]func() bool{
		nil,
		/* 0 AsmFile <- <(Statement* !.)> */
		func() bool {
			position0, tokenIndex0, depth0 := position, tokenIndex, depth
			{
				position1 := position
				depth++
			l2:
				{
					position3, tokenIndex3, depth3 := position, tokenIndex, depth
					if !_rules[ruleStatement]() {
						goto l3
					}
					goto l2
				l3:
					position, tokenIndex, depth = position3, tokenIndex3, depth3
				}
				{
					position4, tokenIndex4, depth4 := position, tokenIndex, depth
					if !matchDot() {
						goto l4
					}
					goto l0
				l4:
					position, tokenIndex, depth = position4, tokenIndex4, depth4
				}
				depth--
				add(ruleAsmFile, position1)
			}
			return true
		l0:
			position, tokenIndex, depth = position0, tokenIndex0, depth0
			return false
		},
		/* 1 Statement <- <(WS? (Label / ((GlobalDirective / LocationDirective / LabelContainingDirective / Instruction / Directive / Comment / ) WS? ((Comment? '\n') / ';'))))> */
		func() bool {
			position5, tokenIndex5, depth5 := position, tokenIndex, depth
			{
				position6 := position
				depth++
				{
					position7, tokenIndex7, depth7 := position, tokenIndex, depth
					if !_rules[ruleWS]() {
						goto l7
					}
					goto l8
				l7:
					position, tokenIndex, depth = position7, tokenIndex7, depth7
				}
			l8:
				{
					position9, tokenIndex9, depth9 := position, tokenIndex, depth
					if !_rules[ruleLabel]() {
						goto l10
					}
					goto l9
				l10:
					position, tokenIndex, depth = position9, tokenIndex9, depth9
					{
						position11, tokenIndex11, depth11 := position, tokenIndex, depth
						if !_rules[ruleGlobalDirective]() {
							goto l12
						}
						goto l11
					l12:
						position, tokenIndex, depth = position11, tokenIndex11, depth11
						if !_rules[ruleLocationDirective]() {
							goto l13
						}
						goto l11
					l13:
						position, tokenIndex, depth = position11, tokenIndex11, depth11
						if !_rules[ruleLabelContainingDirective]() {
							goto l14
						}
						goto l11
					l14:
						position, tokenIndex, depth = position11, tokenIndex11, depth11
						if !_rules[ruleInstruction]() {
							goto l15
						}
						goto l11
					l15:
						position, tokenIndex, depth = position11, tokenIndex11, depth11
						if !_rules[ruleDirective]() {
							goto l16
						}
						goto l11
					l16:
						position, tokenIndex, depth = position11, tokenIndex11, depth11
						if !_rules[ruleComment]() {
							goto l17
						}
						goto l11
					l17:
						position, tokenIndex, depth = position11, tokenIndex11, depth11
					}
				l11:
					{
						position18, tokenIndex18, depth18 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l18
						}
						goto l19
					l18:
						position, tokenIndex, depth = position18, tokenIndex18, depth18
					}
				l19:
					{
						position20, tokenIndex20, depth20 := position, tokenIndex, depth
						{
							position22, tokenIndex22, depth22 := position, tokenIndex, depth
							if !_rules[ruleComment]() {
								goto l22
							}
							goto l23
						l22:
							position, tokenIndex, depth = position22, tokenIndex22, depth22
						}
					l23:
						if buffer[position] != rune('\n') {
							goto l21
						}
						position++
						goto l20
					l21:
						position, tokenIndex, depth = position20, tokenIndex20, depth20
						if buffer[position] != rune(';') {
							goto l5
						}
						position++
					}
				l20:
				}
			l9:
				depth--
				add(ruleStatement, position6)
			}
			return true
		l5:
			position, tokenIndex, depth = position5, tokenIndex5, depth5
			return false
		},
		/* 2 GlobalDirective <- <((('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('a' / 'A') ('l' / 'L')) / ('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('l' / 'L'))) WS SymbolName)> */
		func() bool {
			position24, tokenIndex24, depth24 := position, tokenIndex, depth
			{
				position25 := position
				depth++
				{
					position26, tokenIndex26, depth26 := position, tokenIndex, depth
					if buffer[position] != rune('.') {
						goto l27
					}
					position++
					{
						position28, tokenIndex28, depth28 := position, tokenIndex, depth
						if buffer[position] != rune('g') {
							goto l29
						}
						position++
						goto l28
					l29:
						position, tokenIndex, depth = position28, tokenIndex28, depth28
						if buffer[position] != rune('G') {
							goto l27
						}
						position++
					}
				l28:
					{
						position30, tokenIndex30, depth30 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l31
						}
						position++
						goto l30
					l31:
						position, tokenIndex, depth = position30, tokenIndex30, depth30
						if buffer[position] != rune('L') {
							goto l27
						}
						position++
					}
				l30:
					{
						position32, tokenIndex32, depth32 := position, tokenIndex, depth
						if buffer[position] != rune('o') {
							goto l33
						}
						position++
						goto l32
					l33:
						position, tokenIndex, depth = position32, tokenIndex32, depth32
						if buffer[position] != rune('O') {
							goto l27
						}
						position++
					}
				l32:
					{
						position34, tokenIndex34, depth34 := position, tokenIndex, depth
						if buffer[position] != rune('b') {
							goto l35
						}
						position++
						goto l34
					l35:
						position, tokenIndex, depth = position34, tokenIndex34, depth34
						if buffer[position] != rune('B') {
							goto l27
						}
						position++
					}
				l34:
					{
						position36, tokenIndex36, depth36 := position, tokenIndex, depth
						if buffer[position] != rune('a') {
							goto l37
						}
						position++
						goto l36
					l37:
						position, tokenIndex, depth = position36, tokenIndex36, depth36
						if buffer[position] != rune('A') {
							goto l27
						}
						position++
					}
				l36:
					{
						position38, tokenIndex38, depth38 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l39
						}
						position++
						goto l38
					l39:
						position, tokenIndex, depth = position38, tokenIndex38, depth38
						if buffer[position] != rune('L') {
							goto l27
						}
						position++
					}
				l38:
					goto l26
				l27:
					position, tokenIndex, depth = position26, tokenIndex26, depth26
					if buffer[position] != rune('.') {
						goto l24
					}
					position++
					{
						position40, tokenIndex40, depth40 := position, tokenIndex, depth
						if buffer[position] != rune('g') {
							goto l41
						}
						position++
						goto l40
					l41:
						position, tokenIndex, depth = position40, tokenIndex40, depth40
						if buffer[position] != rune('G') {
							goto l24
						}
						position++
					}
				l40:
					{
						position42, tokenIndex42, depth42 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l43
						}
						position++
						goto l42
					l43:
						position, tokenIndex, depth = position42, tokenIndex42, depth42
						if buffer[position] != rune('L') {
							goto l24
						}
						position++
					}
				l42:
					{
						position44, tokenIndex44, depth44 := position, tokenIndex, depth
						if buffer[position] != rune('o') {
							goto l45
						}
						position++
						goto l44
					l45:
						position, tokenIndex, depth = position44, tokenIndex44, depth44
						if buffer[position] != rune('O') {
							goto l24
						}
						position++
					}
				l44:
					{
						position46, tokenIndex46, depth46 := position, tokenIndex, depth
						if buffer[position] != rune('b') {
							goto l47
						}
						position++
						goto l46
					l47:
						position, tokenIndex, depth = position46, tokenIndex46, depth46
						if buffer[position] != rune('B') {
							goto l24
						}
						position++
					}
				l46:
					{
						position48, tokenIndex48, depth48 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l49
						}
						position++
						goto l48
					l49:
						position, tokenIndex, depth = position48, tokenIndex48, depth48
						if buffer[position] != rune('L') {
							goto l24
						}
						position++
					}
				l48:
				}
			l26:
				if !_rules[ruleWS]() {
					goto l24
				}
				if !_rules[ruleSymbolName]() {
					goto l24
				}
				depth--
				add(ruleGlobalDirective, position25)
			}
			return true
		l24:
			position, tokenIndex, depth = position24, tokenIndex24, depth24
			return false
		},
		/* 3 Directive <- <('.' DirectiveName (WS Args)?)> */
		func() bool {
			position50, tokenIndex50, depth50 := position, tokenIndex, depth
			{
				position51 := position
				depth++
				if buffer[position] != rune('.') {
					goto l50
				}
				position++
				if !_rules[ruleDirectiveName]() {
					goto l50
				}
				{
					position52, tokenIndex52, depth52 := position, tokenIndex, depth
					if !_rules[ruleWS]() {
						goto l52
					}
					if !_rules[ruleArgs]() {
						goto l52
					}
					goto l53
				l52:
					position, tokenIndex, depth = position52, tokenIndex52, depth52
				}
			l53:
				depth--
				add(ruleDirective, position51)
			}
			return true
		l50:
			position, tokenIndex, depth = position50, tokenIndex50, depth50
			return false
		},
		/* 4 DirectiveName <- <([a-z] / [A-Z] / ([0-9] / [0-9]) / '_')+> */
		func() bool {
			position54, tokenIndex54, depth54 := position, tokenIndex, depth
			{
				position55 := position
				depth++
				{
					position58, tokenIndex58, depth58 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l59
					}
					position++
					goto l58
				l59:
					position, tokenIndex, depth = position58, tokenIndex58, depth58
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l60
					}
					position++
					goto l58
				l60:
					position, tokenIndex, depth = position58, tokenIndex58, depth58
					{
						position62, tokenIndex62, depth62 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l63
						}
						position++
						goto l62
					l63:
						position, tokenIndex, depth = position62, tokenIndex62, depth62
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l61
						}
						position++
					}
				l62:
					goto l58
				l61:
					position, tokenIndex, depth = position58, tokenIndex58, depth58
					if buffer[position] != rune('_') {
						goto l54
					}
					position++
				}
			l58:
			l56:
				{
					position57, tokenIndex57, depth57 := position, tokenIndex, depth
					{
						position64, tokenIndex64, depth64 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l65
						}
						position++
						goto l64
					l65:
						position, tokenIndex, depth = position64, tokenIndex64, depth64
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l66
						}
						position++
						goto l64
					l66:
						position, tokenIndex, depth = position64, tokenIndex64, depth64
						{
							position68, tokenIndex68, depth68 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l69
							}
							position++
							goto l68
						l69:
							position, tokenIndex, depth = position68, tokenIndex68, depth68
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l67
							}
							position++
						}
					l68:
						goto l64
					l67:
						position, tokenIndex, depth = position64, tokenIndex64, depth64
						if buffer[position] != rune('_') {
							goto l57
						}
						position++
					}
				l64:
					goto l56
				l57:
					position, tokenIndex, depth = position57, tokenIndex57, depth57
				}
				depth--
				add(ruleDirectiveName, position55)
			}
			return true
		l54:
			position, tokenIndex, depth = position54, tokenIndex54, depth54
			return false
		},
		/* 5 LocationDirective <- <(FileDirective / LocDirective)> */
		func() bool {
			position70, tokenIndex70, depth70 := position, tokenIndex, depth
			{
				position71 := position
				depth++
				{
					position72, tokenIndex72, depth72 := position, tokenIndex, depth
					if !_rules[ruleFileDirective]() {
						goto l73
					}
					goto l72
				l73:
					position, tokenIndex, depth = position72, tokenIndex72, depth72
					if !_rules[ruleLocDirective]() {
						goto l70
					}
				}
			l72:
				depth--
				add(ruleLocationDirective, position71)
			}
			return true
		l70:
			position, tokenIndex, depth = position70, tokenIndex70, depth70
			return false
		},
		/* 6 FileDirective <- <('.' ('f' / 'F') ('i' / 'I') ('l' / 'L') ('e' / 'E') WS (!('#' / '\n') .)+)> */
		func() bool {
			position74, tokenIndex74, depth74 := position, tokenIndex, depth
			{
				position75 := position
				depth++
				if buffer[position] != rune('.') {
					goto l74
				}
				position++
				{
					position76, tokenIndex76, depth76 := position, tokenIndex, depth
					if buffer[position] != rune('f') {
						goto l77
					}
					position++
					goto l76
				l77:
					position, tokenIndex, depth = position76, tokenIndex76, depth76
					if buffer[position] != rune('F') {
						goto l74
					}
					position++
				}
			l76:
				{
					position78, tokenIndex78, depth78 := position, tokenIndex, depth
					if buffer[position] != rune('i') {
						goto l79
					}
					position++
					goto l78
				l79:
					position, tokenIndex, depth = position78, tokenIndex78, depth78
					if buffer[position] != rune('I') {
						goto l74
					}
					position++
				}
			l78:
				{
					position80, tokenIndex80, depth80 := position, tokenIndex, depth
					if buffer[position] != rune('l') {
						goto l81
					}
					position++
					goto l80
				l81:
					position, tokenIndex, depth = position80, tokenIndex80, depth80
					if buffer[position] != rune('L') {
						goto l74
					}
					position++
				}
			l80:
				{
					position82, tokenIndex82, depth82 := position, tokenIndex, depth
					if buffer[position] != rune('e') {
						goto l83
					}
					position++
					goto l82
				l83:
					position, tokenIndex, depth = position82, tokenIndex82, depth82
					if buffer[position] != rune('E') {
						goto l74
					}
					position++
				}
			l82:
				if !_rules[ruleWS]() {
					goto l74
				}
				{
					position86, tokenIndex86, depth86 := position, tokenIndex, depth
					{
						position87, tokenIndex87, depth87 := position, tokenIndex, depth
						if buffer[position] != rune('#') {
							goto l88
						}
						position++
						goto l87
					l88:
						position, tokenIndex, depth = position87, tokenIndex87, depth87
						if buffer[position] != rune('\n') {
							goto l86
						}
						position++
					}
				l87:
					goto l74
				l86:
					position, tokenIndex, depth = position86, tokenIndex86, depth86
				}
				if !matchDot() {
					goto l74
				}
			l84:
				{
					position85, tokenIndex85, depth85 := position, tokenIndex, depth
					{
						position89, tokenIndex89, depth89 := position, tokenIndex, depth
						{
							position90, tokenIndex90, depth90 := position, tokenIndex, depth
							if buffer[position] != rune('#') {
								goto l91
							}
							position++
							goto l90
						l91:
							position, tokenIndex, depth = position90, tokenIndex90, depth90
							if buffer[position] != rune('\n') {
								goto l89
							}
							position++
						}
					l90:
						goto l85
					l89:
						position, tokenIndex, depth = position89, tokenIndex89, depth89
					}
					if !matchDot() {
						goto l85
					}
					goto l84
				l85:
					position, tokenIndex, depth = position85, tokenIndex85, depth85
				}
				depth--
				add(ruleFileDirective, position75)
			}
			return true
		l74:
			position, tokenIndex, depth = position74, tokenIndex74, depth74
			return false
		},
		/* 7 LocDirective <- <('.' ('l' / 'L') ('o' / 'O') ('c' / 'C') WS (!('#' / '/' / '\n') .)+)> */
		func() bool {
			position92, tokenIndex92, depth92 := position, tokenIndex, depth
			{
				position93 := position
				depth++
				if buffer[position] != rune('.') {
					goto l92
				}
				position++
				{
					position94, tokenIndex94, depth94 := position, tokenIndex, depth
					if buffer[position] != rune('l') {
						goto l95
					}
					position++
					goto l94
				l95:
					position, tokenIndex, depth = position94, tokenIndex94, depth94
					if buffer[position] != rune('L') {
						goto l92
					}
					position++
				}
			l94:
				{
					position96, tokenIndex96, depth96 := position, tokenIndex, depth
					if buffer[position] != rune('o') {
						goto l97
					}
					position++
					goto l96
				l97:
					position, tokenIndex, depth = position96, tokenIndex96, depth96
					if buffer[position] != rune('O') {
						goto l92
					}
					position++
				}
			l96:
				{
					position98, tokenIndex98, depth98 := position, tokenIndex, depth
					if buffer[position] != rune('c') {
						goto l99
					}
					position++
					goto l98
				l99:
					position, tokenIndex, depth = position98, tokenIndex98, depth98
					if buffer[position] != rune('C') {
						goto l92
					}
					position++
				}
			l98:
				if !_rules[ruleWS]() {
					goto l92
				}
				{
					position102, tokenIndex102, depth102 := position, tokenIndex, depth
					{
						position103, tokenIndex103, depth103 := position, tokenIndex, depth
						if buffer[position] != rune('#') {
							goto l104
						}
						position++
						goto l103
					l104:
						position, tokenIndex, depth = position103, tokenIndex103, depth103
						if buffer[position] != rune('/') {
							goto l105
						}
						position++
						goto l103
					l105:
						position, tokenIndex, depth = position103, tokenIndex103, depth103
						if buffer[position] != rune('\n') {
							goto l102
						}
						position++
					}
				l103:
					goto l92
				l102:
					position, tokenIndex, depth = position102, tokenIndex102, depth102
				}
				if !matchDot() {
					goto l92
				}
			l100:
				{
					position101, tokenIndex101, depth101 := position, tokenIndex, depth
					{
						position106, tokenIndex106, depth106 := position, tokenIndex, depth
						{
							position107, tokenIndex107, depth107 := position, tokenIndex, depth
							if buffer[position] != rune('#') {
								goto l108
							}
							position++
							goto l107
						l108:
							position, tokenIndex, depth = position107, tokenIndex107, depth107
							if buffer[position] != rune('/') {
								goto l109
							}
							position++
							goto l107
						l109:
							position, tokenIndex, depth = position107, tokenIndex107, depth107
							if buffer[position] != rune('\n') {
								goto l106
							}
							position++
						}
					l107:
						goto l101
					l106:
						position, tokenIndex, depth = position106, tokenIndex106, depth106
					}
					if !matchDot() {
						goto l101
					}
					goto l100
				l101:
					position, tokenIndex, depth = position101, tokenIndex101, depth101
				}
				depth--
				add(ruleLocDirective, position93)
			}
			return true
		l92:
			position, tokenIndex, depth = position92, tokenIndex92, depth92
			return false
		},
		/* 8 Args <- <(Arg (WS? ',' WS? Arg)*)> */
		func() bool {
			position110, tokenIndex110, depth110 := position, tokenIndex, depth
			{
				position111 := position
				depth++
				if !_rules[ruleArg]() {
					goto l110
				}
			l112:
				{
					position113, tokenIndex113, depth113 := position, tokenIndex, depth
					{
						position114, tokenIndex114, depth114 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l114
						}
						goto l115
					l114:
						position, tokenIndex, depth = position114, tokenIndex114, depth114
					}
				l115:
					if buffer[position] != rune(',') {
						goto l113
					}
					position++
					{
						position116, tokenIndex116, depth116 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l116
						}
						goto l117
					l116:
						position, tokenIndex, depth = position116, tokenIndex116, depth116
					}
				l117:
					if !_rules[ruleArg]() {
						goto l113
					}
					goto l112
				l113:
					position, tokenIndex, depth = position113, tokenIndex113, depth113
				}
				depth--
				add(ruleArgs, position111)
			}
			return true
		l110:
			position, tokenIndex, depth = position110, tokenIndex110, depth110
			return false
		},
		/* 9 Arg <- <(QuotedArg / ([0-9] / [0-9] / ([a-z] / [A-Z]) / '%' / '+' / '-' / '*' / '_' / '@' / '.')*)> */
		func() bool {
			{
				position119 := position
				depth++
				{
					position120, tokenIndex120, depth120 := position, tokenIndex, depth
					if !_rules[ruleQuotedArg]() {
						goto l121
					}
					goto l120
				l121:
					position, tokenIndex, depth = position120, tokenIndex120, depth120
				l122:
					{
						position123, tokenIndex123, depth123 := position, tokenIndex, depth
						{
							position124, tokenIndex124, depth124 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l125
							}
							position++
							goto l124
						l125:
							position, tokenIndex, depth = position124, tokenIndex124, depth124
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l126
							}
							position++
							goto l124
						l126:
							position, tokenIndex, depth = position124, tokenIndex124, depth124
							{
								position128, tokenIndex128, depth128 := position, tokenIndex, depth
								if c := buffer[position]; c < rune('a') || c > rune('z') {
									goto l129
								}
								position++
								goto l128
							l129:
								position, tokenIndex, depth = position128, tokenIndex128, depth128
								if c := buffer[position]; c < rune('A') || c > rune('Z') {
									goto l127
								}
								position++
							}
						l128:
							goto l124
						l127:
							position, tokenIndex, depth = position124, tokenIndex124, depth124
							if buffer[position] != rune('%') {
								goto l130
							}
							position++
							goto l124
						l130:
							position, tokenIndex, depth = position124, tokenIndex124, depth124
							if buffer[position] != rune('+') {
								goto l131
							}
							position++
							goto l124
						l131:
							position, tokenIndex, depth = position124, tokenIndex124, depth124
							if buffer[position] != rune('-') {
								goto l132
							}
							position++
							goto l124
						l132:
							position, tokenIndex, depth = position124, tokenIndex124, depth124
							if buffer[position] != rune('*') {
								goto l133
							}
							position++
							goto l124
						l133:
							position, tokenIndex, depth = position124, tokenIndex124, depth124
							if buffer[position] != rune('_') {
								goto l134
							}
							position++
							goto l124
						l134:
							position, tokenIndex, depth = position124, tokenIndex124, depth124
							if buffer[position] != rune('@') {
								goto l135
							}
							position++
							goto l124
						l135:
							position, tokenIndex, depth = position124, tokenIndex124, depth124
							if buffer[position] != rune('.') {
								goto l123
							}
							position++
						}
					l124:
						goto l122
					l123:
						position, tokenIndex, depth = position123, tokenIndex123, depth123
					}
				}
			l120:
				depth--
				add(ruleArg, position119)
			}
			return true
		},
		/* 10 QuotedArg <- <('"' QuotedText '"')> */
		func() bool {
			position136, tokenIndex136, depth136 := position, tokenIndex, depth
			{
				position137 := position
				depth++
				if buffer[position] != rune('"') {
					goto l136
				}
				position++
				if !_rules[ruleQuotedText]() {
					goto l136
				}
				if buffer[position] != rune('"') {
					goto l136
				}
				position++
				depth--
				add(ruleQuotedArg, position137)
			}
			return true
		l136:
			position, tokenIndex, depth = position136, tokenIndex136, depth136
			return false
		},
		/* 11 QuotedText <- <(EscapedChar / (!'"' .))*> */
		func() bool {
			{
				position139 := position
				depth++
			l140:
				{
					position141, tokenIndex141, depth141 := position, tokenIndex, depth
					{
						position142, tokenIndex142, depth142 := position, tokenIndex, depth
						if !_rules[ruleEscapedChar]() {
							goto l143
						}
						goto l142
					l143:
						position, tokenIndex, depth = position142, tokenIndex142, depth142
						{
							position144, tokenIndex144, depth144 := position, tokenIndex, depth
							if buffer[position] != rune('"') {
								goto l144
							}
							position++
							goto l141
						l144:
							position, tokenIndex, depth = position144, tokenIndex144, depth144
						}
						if !matchDot() {
							goto l141
						}
					}
				l142:
					goto l140
				l141:
					position, tokenIndex, depth = position141, tokenIndex141, depth141
				}
				depth--
				add(ruleQuotedText, position139)
			}
			return true
		},
		/* 12 LabelContainingDirective <- <(LabelContainingDirectiveName WS SymbolArgs)> */
		func() bool {
			position145, tokenIndex145, depth145 := position, tokenIndex, depth
			{
				position146 := position
				depth++
				if !_rules[ruleLabelContainingDirectiveName]() {
					goto l145
				}
				if !_rules[ruleWS]() {
					goto l145
				}
				if !_rules[ruleSymbolArgs]() {
					goto l145
				}
				depth--
				add(ruleLabelContainingDirective, position146)
			}
			return true
		l145:
			position, tokenIndex, depth = position145, tokenIndex145, depth145
			return false
		},
		/* 13 LabelContainingDirectiveName <- <(('.' ('x' / 'X') ('w' / 'W') ('o' / 'O') ('r' / 'R') ('d' / 'D')) / ('.' ('w' / 'W') ('o' / 'O') ('r' / 'R') ('d' / 'D')) / ('.' ('l' / 'L') ('o' / 'O') ('n' / 'N') ('g' / 'G')) / ('.' ('s' / 'S') ('e' / 'E') ('t' / 'T')) / ('.' '8' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' '4' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' ('q' / 'Q') ('u' / 'U') ('a' / 'A') ('d' / 'D')) / ('.' ('t' / 'T') ('c' / 'C')) / ('.' ('l' / 'L') ('o' / 'O') ('c' / 'C') ('a' / 'A') ('l' / 'L') ('e' / 'E') ('n' / 'N') ('t' / 'T') ('r' / 'R') ('y' / 'Y')) / ('.' ('s' / 'S') ('i' / 'I') ('z' / 'Z') ('e' / 'E')) / ('.' ('t' / 'T') ('y' / 'Y') ('p' / 'P') ('e' / 'E')) / ('.' ('u' / 'U') ('l' / 'L') ('e' / 'E') ('b' / 'B') '1' '2' '8') / ('.' ('s' / 'S') ('l' / 'L') ('e' / 'E') ('b' / 'B') '1' '2' '8'))> */
		func() bool {
			position147, tokenIndex147, depth147 := position, tokenIndex, depth
			{
				position148 := position
				depth++
				{
					position149, tokenIndex149, depth149 := position, tokenIndex, depth
					if buffer[position] != rune('.') {
						goto l150
					}
					position++
					{
						position151, tokenIndex151, depth151 := position, tokenIndex, depth
						if buffer[position] != rune('x') {
							goto l152
						}
						position++
						goto l151
					l152:
						position, tokenIndex, depth = position151, tokenIndex151, depth151
						if buffer[position] != rune('X') {
							goto l150
						}
						position++
					}
				l151:
					{
						position153, tokenIndex153, depth153 := position, tokenIndex, depth
						if buffer[position] != rune('w') {
							goto l154
						}
						position++
						goto l153
					l154:
						position, tokenIndex, depth = position153, tokenIndex153, depth153
						if buffer[position] != rune('W') {
							goto l150
						}
						position++
					}
				l153:
					{
						position155, tokenIndex155, depth155 := position, tokenIndex, depth
						if buffer[position] != rune('o') {
							goto l156
						}
						position++
						goto l155
					l156:
						position, tokenIndex, depth = position155, tokenIndex155, depth155
						if buffer[position] != rune('O') {
							goto l150
						}
						position++
					}
				l155:
					{
						position157, tokenIndex157, depth157 := position, tokenIndex, depth
						if buffer[position] != rune('r') {
							goto l158
						}
						position++
						goto l157
					l158:
						position, tokenIndex, depth = position157, tokenIndex157, depth157
						if buffer[position] != rune('R') {
							goto l150
						}
						position++
					}
				l157:
					{
						position159, tokenIndex159, depth159 := position, tokenIndex, depth
						if buffer[position] != rune('d') {
							goto l160
						}
						position++
						goto l159
					l160:
						position, tokenIndex, depth = position159, tokenIndex159, depth159
						if buffer[position] != rune('D') {
							goto l150
						}
						position++
					}
				l159:
					goto l149
				l150:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l161
					}
					position++
					{
						position162, tokenIndex162, depth162 := position, tokenIndex, depth
						if buffer[position] != rune('w') {
							goto l163
						}
						position++
						goto l162
					l163:
						position, tokenIndex, depth = position162, tokenIndex162, depth162
						if buffer[position] != rune('W') {
							goto l161
						}
						position++
					}
				l162:
					{
						position164, tokenIndex164, depth164 := position, tokenIndex, depth
						if buffer[position] != rune('o') {
							goto l165
						}
						position++
						goto l164
					l165:
						position, tokenIndex, depth = position164, tokenIndex164, depth164
						if buffer[position] != rune('O') {
							goto l161
						}
						position++
					}
				l164:
					{
						position166, tokenIndex166, depth166 := position, tokenIndex, depth
						if buffer[position] != rune('r') {
							goto l167
						}
						position++
						goto l166
					l167:
						position, tokenIndex, depth = position166, tokenIndex166, depth166
						if buffer[position] != rune('R') {
							goto l161
						}
						position++
					}
				l166:
					{
						position168, tokenIndex168, depth168 := position, tokenIndex, depth
						if buffer[position] != rune('d') {
							goto l169
						}
						position++
						goto l168
					l169:
						position, tokenIndex, depth = position168, tokenIndex168, depth168
						if buffer[position] != rune('D') {
							goto l161
						}
						position++
					}
				l168:
					goto l149
				l161:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l170
					}
					position++
					{
						position171, tokenIndex171, depth171 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l172
						}
						position++
						goto l171
					l172:
						position, tokenIndex, depth = position171, tokenIndex171, depth171
						if buffer[position] != rune('L') {
							goto l170
						}
						position++
					}
				l171:
					{
						position173, tokenIndex173, depth173 := position, tokenIndex, depth
						if buffer[position] != rune('o') {
							goto l174
						}
						position++
						goto l173
					l174:
						position, tokenIndex, depth = position173, tokenIndex173, depth173
						if buffer[position] != rune('O') {
							goto l170
						}
						position++
					}
				l173:
					{
						position175, tokenIndex175, depth175 := position, tokenIndex, depth
						if buffer[position] != rune('n') {
							goto l176
						}
						position++
						goto l175
					l176:
						position, tokenIndex, depth = position175, tokenIndex175, depth175
						if buffer[position] != rune('N') {
							goto l170
						}
						position++
					}
				l175:
					{
						position177, tokenIndex177, depth177 := position, tokenIndex, depth
						if buffer[position] != rune('g') {
							goto l178
						}
						position++
						goto l177
					l178:
						position, tokenIndex, depth = position177, tokenIndex177, depth177
						if buffer[position] != rune('G') {
							goto l170
						}
						position++
					}
				l177:
					goto l149
				l170:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l179
					}
					position++
					{
						position180, tokenIndex180, depth180 := position, tokenIndex, depth
						if buffer[position] != rune('s') {
							goto l181
						}
						position++
						goto l180
					l181:
						position, tokenIndex, depth = position180, tokenIndex180, depth180
						if buffer[position] != rune('S') {
							goto l179
						}
						position++
					}
				l180:
					{
						position182, tokenIndex182, depth182 := position, tokenIndex, depth
						if buffer[position] != rune('e') {
							goto l183
						}
						position++
						goto l182
					l183:
						position, tokenIndex, depth = position182, tokenIndex182, depth182
						if buffer[position] != rune('E') {
							goto l179
						}
						position++
					}
				l182:
					{
						position184, tokenIndex184, depth184 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l185
						}
						position++
						goto l184
					l185:
						position, tokenIndex, depth = position184, tokenIndex184, depth184
						if buffer[position] != rune('T') {
							goto l179
						}
						position++
					}
				l184:
					goto l149
				l179:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l186
					}
					position++
					if buffer[position] != rune('8') {
						goto l186
					}
					position++
					{
						position187, tokenIndex187, depth187 := position, tokenIndex, depth
						if buffer[position] != rune('b') {
							goto l188
						}
						position++
						goto l187
					l188:
						position, tokenIndex, depth = position187, tokenIndex187, depth187
						if buffer[position] != rune('B') {
							goto l186
						}
						position++
					}
				l187:
					{
						position189, tokenIndex189, depth189 := position, tokenIndex, depth
						if buffer[position] != rune('y') {
							goto l190
						}
						position++
						goto l189
					l190:
						position, tokenIndex, depth = position189, tokenIndex189, depth189
						if buffer[position] != rune('Y') {
							goto l186
						}
						position++
					}
				l189:
					{
						position191, tokenIndex191, depth191 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l192
						}
						position++
						goto l191
					l192:
						position, tokenIndex, depth = position191, tokenIndex191, depth191
						if buffer[position] != rune('T') {
							goto l186
						}
						position++
					}
				l191:
					{
						position193, tokenIndex193, depth193 := position, tokenIndex, depth
						if buffer[position] != rune('e') {
							goto l194
						}
						position++
						goto l193
					l194:
						position, tokenIndex, depth = position193, tokenIndex193, depth193
						if buffer[position] != rune('E') {
							goto l186
						}
						position++
					}
				l193:
					goto l149
				l186:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l195
					}
					position++
					if buffer[position] != rune('4') {
						goto l195
					}
					position++
					{
						position196, tokenIndex196, depth196 := position, tokenIndex, depth
						if buffer[position] != rune('b') {
							goto l197
						}
						position++
						goto l196
					l197:
						position, tokenIndex, depth = position196, tokenIndex196, depth196
						if buffer[position] != rune('B') {
							goto l195
						}
						position++
					}
				l196:
					{
						position198, tokenIndex198, depth198 := position, tokenIndex, depth
						if buffer[position] != rune('y') {
							goto l199
						}
						position++
						goto l198
					l199:
						position, tokenIndex, depth = position198, tokenIndex198, depth198
						if buffer[position] != rune('Y') {
							goto l195
						}
						position++
					}
				l198:
					{
						position200, tokenIndex200, depth200 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l201
						}
						position++
						goto l200
					l201:
						position, tokenIndex, depth = position200, tokenIndex200, depth200
						if buffer[position] != rune('T') {
							goto l195
						}
						position++
					}
				l200:
					{
						position202, tokenIndex202, depth202 := position, tokenIndex, depth
						if buffer[position] != rune('e') {
							goto l203
						}
						position++
						goto l202
					l203:
						position, tokenIndex, depth = position202, tokenIndex202, depth202
						if buffer[position] != rune('E') {
							goto l195
						}
						position++
					}
				l202:
					goto l149
				l195:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l204
					}
					position++
					{
						position205, tokenIndex205, depth205 := position, tokenIndex, depth
						if buffer[position] != rune('q') {
							goto l206
						}
						position++
						goto l205
					l206:
						position, tokenIndex, depth = position205, tokenIndex205, depth205
						if buffer[position] != rune('Q') {
							goto l204
						}
						position++
					}
				l205:
					{
						position207, tokenIndex207, depth207 := position, tokenIndex, depth
						if buffer[position] != rune('u') {
							goto l208
						}
						position++
						goto l207
					l208:
						position, tokenIndex, depth = position207, tokenIndex207, depth207
						if buffer[position] != rune('U') {
							goto l204
						}
						position++
					}
				l207:
					{
						position209, tokenIndex209, depth209 := position, tokenIndex, depth
						if buffer[position] != rune('a') {
							goto l210
						}
						position++
						goto l209
					l210:
						position, tokenIndex, depth = position209, tokenIndex209, depth209
						if buffer[position] != rune('A') {
							goto l204
						}
						position++
					}
				l209:
					{
						position211, tokenIndex211, depth211 := position, tokenIndex, depth
						if buffer[position] != rune('d') {
							goto l212
						}
						position++
						goto l211
					l212:
						position, tokenIndex, depth = position211, tokenIndex211, depth211
						if buffer[position] != rune('D') {
							goto l204
						}
						position++
					}
				l211:
					goto l149
				l204:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l213
					}
					position++
					{
						position214, tokenIndex214, depth214 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l215
						}
						position++
						goto l214
					l215:
						position, tokenIndex, depth = position214, tokenIndex214, depth214
						if buffer[position] != rune('T') {
							goto l213
						}
						position++
					}
				l214:
					{
						position216, tokenIndex216, depth216 := position, tokenIndex, depth
						if buffer[position] != rune('c') {
							goto l217
						}
						position++
						goto l216
					l217:
						position, tokenIndex, depth = position216, tokenIndex216, depth216
						if buffer[position] != rune('C') {
							goto l213
						}
						position++
					}
				l216:
					goto l149
				l213:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l218
					}
					position++
					{
						position219, tokenIndex219, depth219 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l220
						}
						position++
						goto l219
					l220:
						position, tokenIndex, depth = position219, tokenIndex219, depth219
						if buffer[position] != rune('L') {
							goto l218
						}
						position++
					}
				l219:
					{
						position221, tokenIndex221, depth221 := position, tokenIndex, depth
						if buffer[position] != rune('o') {
							goto l222
						}
						position++
						goto l221
					l222:
						position, tokenIndex, depth = position221, tokenIndex221, depth221
						if buffer[position] != rune('O') {
							goto l218
						}
						position++
					}
				l221:
					{
						position223, tokenIndex223, depth223 := position, tokenIndex, depth
						if buffer[position] != rune('c') {
							goto l224
						}
						position++
						goto l223
					l224:
						position, tokenIndex, depth = position223, tokenIndex223, depth223
						if buffer[position] != rune('C') {
							goto l218
						}
						position++
					}
				l223:
					{
						position225, tokenIndex225, depth225 := position, tokenIndex, depth
						if buffer[position] != rune('a') {
							goto l226
						}
						position++
						goto l225
					l226:
						position, tokenIndex, depth = position225, tokenIndex225, depth225
						if buffer[position] != rune('A') {
							goto l218
						}
						position++
					}
				l225:
					{
						position227, tokenIndex227, depth227 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l228
						}
						position++
						goto l227
					l228:
						position, tokenIndex, depth = position227, tokenIndex227, depth227
						if buffer[position] != rune('L') {
							goto l218
						}
						position++
					}
				l227:
					{
						position229, tokenIndex229, depth229 := position, tokenIndex, depth
						if buffer[position] != rune('e') {
							goto l230
						}
						position++
						goto l229
					l230:
						position, tokenIndex, depth = position229, tokenIndex229, depth229
						if buffer[position] != rune('E') {
							goto l218
						}
						position++
					}
				l229:
					{
						position231, tokenIndex231, depth231 := position, tokenIndex, depth
						if buffer[position] != rune('n') {
							goto l232
						}
						position++
						goto l231
					l232:
						position, tokenIndex, depth = position231, tokenIndex231, depth231
						if buffer[position] != rune('N') {
							goto l218
						}
						position++
					}
				l231:
					{
						position233, tokenIndex233, depth233 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l234
						}
						position++
						goto l233
					l234:
						position, tokenIndex, depth = position233, tokenIndex233, depth233
						if buffer[position] != rune('T') {
							goto l218
						}
						position++
					}
				l233:
					{
						position235, tokenIndex235, depth235 := position, tokenIndex, depth
						if buffer[position] != rune('r') {
							goto l236
						}
						position++
						goto l235
					l236:
						position, tokenIndex, depth = position235, tokenIndex235, depth235
						if buffer[position] != rune('R') {
							goto l218
						}
						position++
					}
				l235:
					{
						position237, tokenIndex237, depth237 := position, tokenIndex, depth
						if buffer[position] != rune('y') {
							goto l238
						}
						position++
						goto l237
					l238:
						position, tokenIndex, depth = position237, tokenIndex237, depth237
						if buffer[position] != rune('Y') {
							goto l218
						}
						position++
					}
				l237:
					goto l149
				l218:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l239
					}
					position++
					{
						position240, tokenIndex240, depth240 := position, tokenIndex, depth
						if buffer[position] != rune('s') {
							goto l241
						}
						position++
						goto l240
					l241:
						position, tokenIndex, depth = position240, tokenIndex240, depth240
						if buffer[position] != rune('S') {
							goto l239
						}
						position++
					}
				l240:
					{
						position242, tokenIndex242, depth242 := position, tokenIndex, depth
						if buffer[position] != rune('i') {
							goto l243
						}
						position++
						goto l242
					l243:
						position, tokenIndex, depth = position242, tokenIndex242, depth242
						if buffer[position] != rune('I') {
							goto l239
						}
						position++
					}
				l242:
					{
						position244, tokenIndex244, depth244 := position, tokenIndex, depth
						if buffer[position] != rune('z') {
							goto l245
						}
						position++
						goto l244
					l245:
						position, tokenIndex, depth = position244, tokenIndex244, depth244
						if buffer[position] != rune('Z') {
							goto l239
						}
						position++
					}
				l244:
					{
						position246, tokenIndex246, depth246 := position, tokenIndex, depth
						if buffer[position] != rune('e') {
							goto l247
						}
						position++
						goto l246
					l247:
						position, tokenIndex, depth = position246, tokenIndex246, depth246
						if buffer[position] != rune('E') {
							goto l239
						}
						position++
					}
				l246:
					goto l149
				l239:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l248
					}
					position++
					{
						position249, tokenIndex249, depth249 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l250
						}
						position++
						goto l249
					l250:
						position, tokenIndex, depth = position249, tokenIndex249, depth249
						if buffer[position] != rune('T') {
							goto l248
						}
						position++
					}
				l249:
					{
						position251, tokenIndex251, depth251 := position, tokenIndex, depth
						if buffer[position] != rune('y') {
							goto l252
						}
						position++
						goto l251
					l252:
						position, tokenIndex, depth = position251, tokenIndex251, depth251
						if buffer[position] != rune('Y') {
							goto l248
						}
						position++
					}
				l251:
					{
						position253, tokenIndex253, depth253 := position, tokenIndex, depth
						if buffer[position] != rune('p') {
							goto l254
						}
						position++
						goto l253
					l254:
						position, tokenIndex, depth = position253, tokenIndex253, depth253
						if buffer[position] != rune('P') {
							goto l248
						}
						position++
					}
				l253:
					{
						position255, tokenIndex255, depth255 := position, tokenIndex, depth
						if buffer[position] != rune('e') {
							goto l256
						}
						position++
						goto l255
					l256:
						position, tokenIndex, depth = position255, tokenIndex255, depth255
						if buffer[position] != rune('E') {
							goto l248
						}
						position++
					}
				l255:
					goto l149
				l248:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l257
					}
					position++
					{
						position258, tokenIndex258, depth258 := position, tokenIndex, depth
						if buffer[position] != rune('u') {
							goto l259
						}
						position++
						goto l258
					l259:
						position, tokenIndex, depth = position258, tokenIndex258, depth258
						if buffer[position] != rune('U') {
							goto l257
						}
						position++
					}
				l258:
					{
						position260, tokenIndex260, depth260 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l261
						}
						position++
						goto l260
					l261:
						position, tokenIndex, depth = position260, tokenIndex260, depth260
						if buffer[position] != rune('L') {
							goto l257
						}
						position++
					}
				l260:
					{
						position262, tokenIndex262, depth262 := position, tokenIndex, depth
						if buffer[position] != rune('e') {
							goto l263
						}
						position++
						goto l262
					l263:
						position, tokenIndex, depth = position262, tokenIndex262, depth262
						if buffer[position] != rune('E') {
							goto l257
						}
						position++
					}
				l262:
					{
						position264, tokenIndex264, depth264 := position, tokenIndex, depth
						if buffer[position] != rune('b') {
							goto l265
						}
						position++
						goto l264
					l265:
						position, tokenIndex, depth = position264, tokenIndex264, depth264
						if buffer[position] != rune('B') {
							goto l257
						}
						position++
					}
				l264:
					if buffer[position] != rune('1') {
						goto l257
					}
					position++
					if buffer[position] != rune('2') {
						goto l257
					}
					position++
					if buffer[position] != rune('8') {
						goto l257
					}
					position++
					goto l149
				l257:
					position, tokenIndex, depth = position149, tokenIndex149, depth149
					if buffer[position] != rune('.') {
						goto l147
					}
					position++
					{
						position266, tokenIndex266, depth266 := position, tokenIndex, depth
						if buffer[position] != rune('s') {
							goto l267
						}
						position++
						goto l266
					l267:
						position, tokenIndex, depth = position266, tokenIndex266, depth266
						if buffer[position] != rune('S') {
							goto l147
						}
						position++
					}
				l266:
					{
						position268, tokenIndex268, depth268 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l269
						}
						position++
						goto l268
					l269:
						position, tokenIndex, depth = position268, tokenIndex268, depth268
						if buffer[position] != rune('L') {
							goto l147
						}
						position++
					}
				l268:
					{
						position270, tokenIndex270, depth270 := position, tokenIndex, depth
						if buffer[position] != rune('e') {
							goto l271
						}
						position++
						goto l270
					l271:
						position, tokenIndex, depth = position270, tokenIndex270, depth270
						if buffer[position] != rune('E') {
							goto l147
						}
						position++
					}
				l270:
					{
						position272, tokenIndex272, depth272 := position, tokenIndex, depth
						if buffer[position] != rune('b') {
							goto l273
						}
						position++
						goto l272
					l273:
						position, tokenIndex, depth = position272, tokenIndex272, depth272
						if buffer[position] != rune('B') {
							goto l147
						}
						position++
					}
				l272:
					if buffer[position] != rune('1') {
						goto l147
					}
					position++
					if buffer[position] != rune('2') {
						goto l147
					}
					position++
					if buffer[position] != rune('8') {
						goto l147
					}
					position++
				}
			l149:
				depth--
				add(ruleLabelContainingDirectiveName, position148)
			}
			return true
		l147:
			position, tokenIndex, depth = position147, tokenIndex147, depth147
			return false
		},
		/* 14 SymbolArgs <- <(SymbolArg (WS? ',' WS? SymbolArg)*)> */
		func() bool {
			position274, tokenIndex274, depth274 := position, tokenIndex, depth
			{
				position275 := position
				depth++
				if !_rules[ruleSymbolArg]() {
					goto l274
				}
			l276:
				{
					position277, tokenIndex277, depth277 := position, tokenIndex, depth
					{
						position278, tokenIndex278, depth278 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l278
						}
						goto l279
					l278:
						position, tokenIndex, depth = position278, tokenIndex278, depth278
					}
				l279:
					if buffer[position] != rune(',') {
						goto l277
					}
					position++
					{
						position280, tokenIndex280, depth280 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l280
						}
						goto l281
					l280:
						position, tokenIndex, depth = position280, tokenIndex280, depth280
					}
				l281:
					if !_rules[ruleSymbolArg]() {
						goto l277
					}
					goto l276
				l277:
					position, tokenIndex, depth = position277, tokenIndex277, depth277
				}
				depth--
				add(ruleSymbolArgs, position275)
			}
			return true
		l274:
			position, tokenIndex, depth = position274, tokenIndex274, depth274
			return false
		},
		/* 15 SymbolArg <- <(Offset / SymbolType / ((Offset / LocalSymbol / SymbolName / Dot) WS? Operator WS? (Offset / LocalSymbol / SymbolName)) / (LocalSymbol TCMarker?) / (SymbolName Offset) / (SymbolName TCMarker?))> */
		func() bool {
			position282, tokenIndex282, depth282 := position, tokenIndex, depth
			{
				position283 := position
				depth++
				{
					position284, tokenIndex284, depth284 := position, tokenIndex, depth
					if !_rules[ruleOffset]() {
						goto l285
					}
					goto l284
				l285:
					position, tokenIndex, depth = position284, tokenIndex284, depth284
					if !_rules[ruleSymbolType]() {
						goto l286
					}
					goto l284
				l286:
					position, tokenIndex, depth = position284, tokenIndex284, depth284
					{
						position288, tokenIndex288, depth288 := position, tokenIndex, depth
						if !_rules[ruleOffset]() {
							goto l289
						}
						goto l288
					l289:
						position, tokenIndex, depth = position288, tokenIndex288, depth288
						if !_rules[ruleLocalSymbol]() {
							goto l290
						}
						goto l288
					l290:
						position, tokenIndex, depth = position288, tokenIndex288, depth288
						if !_rules[ruleSymbolName]() {
							goto l291
						}
						goto l288
					l291:
						position, tokenIndex, depth = position288, tokenIndex288, depth288
						if !_rules[ruleDot]() {
							goto l287
						}
					}
				l288:
					{
						position292, tokenIndex292, depth292 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l292
						}
						goto l293
					l292:
						position, tokenIndex, depth = position292, tokenIndex292, depth292
					}
				l293:
					if !_rules[ruleOperator]() {
						goto l287
					}
					{
						position294, tokenIndex294, depth294 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l294
						}
						goto l295
					l294:
						position, tokenIndex, depth = position294, tokenIndex294, depth294
					}
				l295:
					{
						position296, tokenIndex296, depth296 := position, tokenIndex, depth
						if !_rules[ruleOffset]() {
							goto l297
						}
						goto l296
					l297:
						position, tokenIndex, depth = position296, tokenIndex296, depth296
						if !_rules[ruleLocalSymbol]() {
							goto l298
						}
						goto l296
					l298:
						position, tokenIndex, depth = position296, tokenIndex296, depth296
						if !_rules[ruleSymbolName]() {
							goto l287
						}
					}
				l296:
					goto l284
				l287:
					position, tokenIndex, depth = position284, tokenIndex284, depth284
					if !_rules[ruleLocalSymbol]() {
						goto l299
					}
					{
						position300, tokenIndex300, depth300 := position, tokenIndex, depth
						if !_rules[ruleTCMarker]() {
							goto l300
						}
						goto l301
					l300:
						position, tokenIndex, depth = position300, tokenIndex300, depth300
					}
				l301:
					goto l284
				l299:
					position, tokenIndex, depth = position284, tokenIndex284, depth284
					if !_rules[ruleSymbolName]() {
						goto l302
					}
					if !_rules[ruleOffset]() {
						goto l302
					}
					goto l284
				l302:
					position, tokenIndex, depth = position284, tokenIndex284, depth284
					if !_rules[ruleSymbolName]() {
						goto l282
					}
					{
						position303, tokenIndex303, depth303 := position, tokenIndex, depth
						if !_rules[ruleTCMarker]() {
							goto l303
						}
						goto l304
					l303:
						position, tokenIndex, depth = position303, tokenIndex303, depth303
					}
				l304:
				}
			l284:
				depth--
				add(ruleSymbolArg, position283)
			}
			return true
		l282:
			position, tokenIndex, depth = position282, tokenIndex282, depth282
			return false
		},
		/* 16 SymbolType <- <(('@' / '%') (('f' 'u' 'n' 'c' 't' 'i' 'o' 'n') / ('o' 'b' 'j' 'e' 'c' 't')))> */
		func() bool {
			position305, tokenIndex305, depth305 := position, tokenIndex, depth
			{
				position306 := position
				depth++
				{
					position307, tokenIndex307, depth307 := position, tokenIndex, depth
					if buffer[position] != rune('@') {
						goto l308
					}
					position++
					goto l307
				l308:
					position, tokenIndex, depth = position307, tokenIndex307, depth307
					if buffer[position] != rune('%') {
						goto l305
					}
					position++
				}
			l307:
				{
					position309, tokenIndex309, depth309 := position, tokenIndex, depth
					if buffer[position] != rune('f') {
						goto l310
					}
					position++
					if buffer[position] != rune('u') {
						goto l310
					}
					position++
					if buffer[position] != rune('n') {
						goto l310
					}
					position++
					if buffer[position] != rune('c') {
						goto l310
					}
					position++
					if buffer[position] != rune('t') {
						goto l310
					}
					position++
					if buffer[position] != rune('i') {
						goto l310
					}
					position++
					if buffer[position] != rune('o') {
						goto l310
					}
					position++
					if buffer[position] != rune('n') {
						goto l310
					}
					position++
					goto l309
				l310:
					position, tokenIndex, depth = position309, tokenIndex309, depth309
					if buffer[position] != rune('o') {
						goto l305
					}
					position++
					if buffer[position] != rune('b') {
						goto l305
					}
					position++
					if buffer[position] != rune('j') {
						goto l305
					}
					position++
					if buffer[position] != rune('e') {
						goto l305
					}
					position++
					if buffer[position] != rune('c') {
						goto l305
					}
					position++
					if buffer[position] != rune('t') {
						goto l305
					}
					position++
				}
			l309:
				depth--
				add(ruleSymbolType, position306)
			}
			return true
		l305:
			position, tokenIndex, depth = position305, tokenIndex305, depth305
			return false
		},
		/* 17 Dot <- <'.'> */
		func() bool {
			position311, tokenIndex311, depth311 := position, tokenIndex, depth
			{
				position312 := position
				depth++
				if buffer[position] != rune('.') {
					goto l311
				}
				position++
				depth--
				add(ruleDot, position312)
			}
			return true
		l311:
			position, tokenIndex, depth = position311, tokenIndex311, depth311
			return false
		},
		/* 18 TCMarker <- <('[' 'T' 'C' ']')> */
		func() bool {
			position313, tokenIndex313, depth313 := position, tokenIndex, depth
			{
				position314 := position
				depth++
				if buffer[position] != rune('[') {
					goto l313
				}
				position++
				if buffer[position] != rune('T') {
					goto l313
				}
				position++
				if buffer[position] != rune('C') {
					goto l313
				}
				position++
				if buffer[position] != rune(']') {
					goto l313
				}
				position++
				depth--
				add(ruleTCMarker, position314)
			}
			return true
		l313:
			position, tokenIndex, depth = position313, tokenIndex313, depth313
			return false
		},
		/* 19 EscapedChar <- <('\\' .)> */
		func() bool {
			position315, tokenIndex315, depth315 := position, tokenIndex, depth
			{
				position316 := position
				depth++
				if buffer[position] != rune('\\') {
					goto l315
				}
				position++
				if !matchDot() {
					goto l315
				}
				depth--
				add(ruleEscapedChar, position316)
			}
			return true
		l315:
			position, tokenIndex, depth = position315, tokenIndex315, depth315
			return false
		},
		/* 20 WS <- <(' ' / '\t')+> */
		func() bool {
			position317, tokenIndex317, depth317 := position, tokenIndex, depth
			{
				position318 := position
				depth++
				{
					position321, tokenIndex321, depth321 := position, tokenIndex, depth
					if buffer[position] != rune(' ') {
						goto l322
					}
					position++
					goto l321
				l322:
					position, tokenIndex, depth = position321, tokenIndex321, depth321
					if buffer[position] != rune('\t') {
						goto l317
					}
					position++
				}
			l321:
			l319:
				{
					position320, tokenIndex320, depth320 := position, tokenIndex, depth
					{
						position323, tokenIndex323, depth323 := position, tokenIndex, depth
						if buffer[position] != rune(' ') {
							goto l324
						}
						position++
						goto l323
					l324:
						position, tokenIndex, depth = position323, tokenIndex323, depth323
						if buffer[position] != rune('\t') {
							goto l320
						}
						position++
					}
				l323:
					goto l319
				l320:
					position, tokenIndex, depth = position320, tokenIndex320, depth320
				}
				depth--
				add(ruleWS, position318)
			}
			return true
		l317:
			position, tokenIndex, depth = position317, tokenIndex317, depth317
			return false
		},
		/* 21 Comment <- <((('/' '/') / '#') (!'\n' .)*)> */
		func() bool {
			position325, tokenIndex325, depth325 := position, tokenIndex, depth
			{
				position326 := position
				depth++
				{
					position327, tokenIndex327, depth327 := position, tokenIndex, depth
					if buffer[position] != rune('/') {
						goto l328
					}
					position++
					if buffer[position] != rune('/') {
						goto l328
					}
					position++
					goto l327
				l328:
					position, tokenIndex, depth = position327, tokenIndex327, depth327
					if buffer[position] != rune('#') {
						goto l325
					}
					position++
				}
			l327:
			l329:
				{
					position330, tokenIndex330, depth330 := position, tokenIndex, depth
					{
						position331, tokenIndex331, depth331 := position, tokenIndex, depth
						if buffer[position] != rune('\n') {
							goto l331
						}
						position++
						goto l330
					l331:
						position, tokenIndex, depth = position331, tokenIndex331, depth331
					}
					if !matchDot() {
						goto l330
					}
					goto l329
				l330:
					position, tokenIndex, depth = position330, tokenIndex330, depth330
				}
				depth--
				add(ruleComment, position326)
			}
			return true
		l325:
			position, tokenIndex, depth = position325, tokenIndex325, depth325
			return false
		},
		/* 22 Label <- <((LocalSymbol / LocalLabel / SymbolName) ':')> */
		func() bool {
			position332, tokenIndex332, depth332 := position, tokenIndex, depth
			{
				position333 := position
				depth++
				{
					position334, tokenIndex334, depth334 := position, tokenIndex, depth
					if !_rules[ruleLocalSymbol]() {
						goto l335
					}
					goto l334
				l335:
					position, tokenIndex, depth = position334, tokenIndex334, depth334
					if !_rules[ruleLocalLabel]() {
						goto l336
					}
					goto l334
				l336:
					position, tokenIndex, depth = position334, tokenIndex334, depth334
					if !_rules[ruleSymbolName]() {
						goto l332
					}
				}
			l334:
				if buffer[position] != rune(':') {
					goto l332
				}
				position++
				depth--
				add(ruleLabel, position333)
			}
			return true
		l332:
			position, tokenIndex, depth = position332, tokenIndex332, depth332
			return false
		},
		/* 23 SymbolName <- <(([a-z] / [A-Z] / '.' / '_') ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')*)> */
		func() bool {
			position337, tokenIndex337, depth337 := position, tokenIndex, depth
			{
				position338 := position
				depth++
				{
					position339, tokenIndex339, depth339 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l340
					}
					position++
					goto l339
				l340:
					position, tokenIndex, depth = position339, tokenIndex339, depth339
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l341
					}
					position++
					goto l339
				l341:
					position, tokenIndex, depth = position339, tokenIndex339, depth339
					if buffer[position] != rune('.') {
						goto l342
					}
					position++
					goto l339
				l342:
					position, tokenIndex, depth = position339, tokenIndex339, depth339
					if buffer[position] != rune('_') {
						goto l337
					}
					position++
				}
			l339:
			l343:
				{
					position344, tokenIndex344, depth344 := position, tokenIndex, depth
					{
						position345, tokenIndex345, depth345 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l346
						}
						position++
						goto l345
					l346:
						position, tokenIndex, depth = position345, tokenIndex345, depth345
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l347
						}
						position++
						goto l345
					l347:
						position, tokenIndex, depth = position345, tokenIndex345, depth345
						if buffer[position] != rune('.') {
							goto l348
						}
						position++
						goto l345
					l348:
						position, tokenIndex, depth = position345, tokenIndex345, depth345
						{
							position350, tokenIndex350, depth350 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l351
							}
							position++
							goto l350
						l351:
							position, tokenIndex, depth = position350, tokenIndex350, depth350
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l349
							}
							position++
						}
					l350:
						goto l345
					l349:
						position, tokenIndex, depth = position345, tokenIndex345, depth345
						if buffer[position] != rune('$') {
							goto l352
						}
						position++
						goto l345
					l352:
						position, tokenIndex, depth = position345, tokenIndex345, depth345
						if buffer[position] != rune('_') {
							goto l344
						}
						position++
					}
				l345:
					goto l343
				l344:
					position, tokenIndex, depth = position344, tokenIndex344, depth344
				}
				depth--
				add(ruleSymbolName, position338)
			}
			return true
		l337:
			position, tokenIndex, depth = position337, tokenIndex337, depth337
			return false
		},
		/* 24 LocalSymbol <- <('.' 'L' ([a-z] / [A-Z] / ([a-z] / [A-Z]) / '.' / ([0-9] / [0-9]) / '$' / '_')+)> */
		func() bool {
			position353, tokenIndex353, depth353 := position, tokenIndex, depth
			{
				position354 := position
				depth++
				if buffer[position] != rune('.') {
					goto l353
				}
				position++
				if buffer[position] != rune('L') {
					goto l353
				}
				position++
				{
					position357, tokenIndex357, depth357 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l358
					}
					position++
					goto l357
				l358:
					position, tokenIndex, depth = position357, tokenIndex357, depth357
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l359
					}
					position++
					goto l357
				l359:
					position, tokenIndex, depth = position357, tokenIndex357, depth357
					{
						position361, tokenIndex361, depth361 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l362
						}
						position++
						goto l361
					l362:
						position, tokenIndex, depth = position361, tokenIndex361, depth361
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l360
						}
						position++
					}
				l361:
					goto l357
				l360:
					position, tokenIndex, depth = position357, tokenIndex357, depth357
					if buffer[position] != rune('.') {
						goto l363
					}
					position++
					goto l357
				l363:
					position, tokenIndex, depth = position357, tokenIndex357, depth357
					{
						position365, tokenIndex365, depth365 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l366
						}
						position++
						goto l365
					l366:
						position, tokenIndex, depth = position365, tokenIndex365, depth365
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l364
						}
						position++
					}
				l365:
					goto l357
				l364:
					position, tokenIndex, depth = position357, tokenIndex357, depth357
					if buffer[position] != rune('$') {
						goto l367
					}
					position++
					goto l357
				l367:
					position, tokenIndex, depth = position357, tokenIndex357, depth357
					if buffer[position] != rune('_') {
						goto l353
					}
					position++
				}
			l357:
			l355:
				{
					position356, tokenIndex356, depth356 := position, tokenIndex, depth
					{
						position368, tokenIndex368, depth368 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l369
						}
						position++
						goto l368
					l369:
						position, tokenIndex, depth = position368, tokenIndex368, depth368
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l370
						}
						position++
						goto l368
					l370:
						position, tokenIndex, depth = position368, tokenIndex368, depth368
						{
							position372, tokenIndex372, depth372 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l373
							}
							position++
							goto l372
						l373:
							position, tokenIndex, depth = position372, tokenIndex372, depth372
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l371
							}
							position++
						}
					l372:
						goto l368
					l371:
						position, tokenIndex, depth = position368, tokenIndex368, depth368
						if buffer[position] != rune('.') {
							goto l374
						}
						position++
						goto l368
					l374:
						position, tokenIndex, depth = position368, tokenIndex368, depth368
						{
							position376, tokenIndex376, depth376 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l377
							}
							position++
							goto l376
						l377:
							position, tokenIndex, depth = position376, tokenIndex376, depth376
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l375
							}
							position++
						}
					l376:
						goto l368
					l375:
						position, tokenIndex, depth = position368, tokenIndex368, depth368
						if buffer[position] != rune('$') {
							goto l378
						}
						position++
						goto l368
					l378:
						position, tokenIndex, depth = position368, tokenIndex368, depth368
						if buffer[position] != rune('_') {
							goto l356
						}
						position++
					}
				l368:
					goto l355
				l356:
					position, tokenIndex, depth = position356, tokenIndex356, depth356
				}
				depth--
				add(ruleLocalSymbol, position354)
			}
			return true
		l353:
			position, tokenIndex, depth = position353, tokenIndex353, depth353
			return false
		},
		/* 25 LocalLabel <- <([0-9] ([0-9] / '$')*)> */
		func() bool {
			position379, tokenIndex379, depth379 := position, tokenIndex, depth
			{
				position380 := position
				depth++
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l379
				}
				position++
			l381:
				{
					position382, tokenIndex382, depth382 := position, tokenIndex, depth
					{
						position383, tokenIndex383, depth383 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l384
						}
						position++
						goto l383
					l384:
						position, tokenIndex, depth = position383, tokenIndex383, depth383
						if buffer[position] != rune('$') {
							goto l382
						}
						position++
					}
				l383:
					goto l381
				l382:
					position, tokenIndex, depth = position382, tokenIndex382, depth382
				}
				depth--
				add(ruleLocalLabel, position380)
			}
			return true
		l379:
			position, tokenIndex, depth = position379, tokenIndex379, depth379
			return false
		},
		/* 26 LocalLabelRef <- <([0-9] ([0-9] / '$')* ('b' / 'f'))> */
		func() bool {
			position385, tokenIndex385, depth385 := position, tokenIndex, depth
			{
				position386 := position
				depth++
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l385
				}
				position++
			l387:
				{
					position388, tokenIndex388, depth388 := position, tokenIndex, depth
					{
						position389, tokenIndex389, depth389 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l390
						}
						position++
						goto l389
					l390:
						position, tokenIndex, depth = position389, tokenIndex389, depth389
						if buffer[position] != rune('$') {
							goto l388
						}
						position++
					}
				l389:
					goto l387
				l388:
					position, tokenIndex, depth = position388, tokenIndex388, depth388
				}
				{
					position391, tokenIndex391, depth391 := position, tokenIndex, depth
					if buffer[position] != rune('b') {
						goto l392
					}
					position++
					goto l391
				l392:
					position, tokenIndex, depth = position391, tokenIndex391, depth391
					if buffer[position] != rune('f') {
						goto l385
					}
					position++
				}
			l391:
				depth--
				add(ruleLocalLabelRef, position386)
			}
			return true
		l385:
			position, tokenIndex, depth = position385, tokenIndex385, depth385
			return false
		},
		/* 27 Instruction <- <(InstructionName (WS InstructionArg (WS? ',' WS? InstructionArg)*)?)> */
		func() bool {
			position393, tokenIndex393, depth393 := position, tokenIndex, depth
			{
				position394 := position
				depth++
				if !_rules[ruleInstructionName]() {
					goto l393
				}
				{
					position395, tokenIndex395, depth395 := position, tokenIndex, depth
					if !_rules[ruleWS]() {
						goto l395
					}
					if !_rules[ruleInstructionArg]() {
						goto l395
					}
				l397:
					{
						position398, tokenIndex398, depth398 := position, tokenIndex, depth
						{
							position399, tokenIndex399, depth399 := position, tokenIndex, depth
							if !_rules[ruleWS]() {
								goto l399
							}
							goto l400
						l399:
							position, tokenIndex, depth = position399, tokenIndex399, depth399
						}
					l400:
						if buffer[position] != rune(',') {
							goto l398
						}
						position++
						{
							position401, tokenIndex401, depth401 := position, tokenIndex, depth
							if !_rules[ruleWS]() {
								goto l401
							}
							goto l402
						l401:
							position, tokenIndex, depth = position401, tokenIndex401, depth401
						}
					l402:
						if !_rules[ruleInstructionArg]() {
							goto l398
						}
						goto l397
					l398:
						position, tokenIndex, depth = position398, tokenIndex398, depth398
					}
					goto l396
				l395:
					position, tokenIndex, depth = position395, tokenIndex395, depth395
				}
			l396:
				depth--
				add(ruleInstruction, position394)
			}
			return true
		l393:
			position, tokenIndex, depth = position393, tokenIndex393, depth393
			return false
		},
		/* 28 InstructionName <- <(([a-z] / [A-Z]) ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]))* ('.' / '+' / '-')?)> */
		func() bool {
			position403, tokenIndex403, depth403 := position, tokenIndex, depth
			{
				position404 := position
				depth++
				{
					position405, tokenIndex405, depth405 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l406
					}
					position++
					goto l405
				l406:
					position, tokenIndex, depth = position405, tokenIndex405, depth405
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l403
					}
					position++
				}
			l405:
			l407:
				{
					position408, tokenIndex408, depth408 := position, tokenIndex, depth
					{
						position409, tokenIndex409, depth409 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l410
						}
						position++
						goto l409
					l410:
						position, tokenIndex, depth = position409, tokenIndex409, depth409
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l411
						}
						position++
						goto l409
					l411:
						position, tokenIndex, depth = position409, tokenIndex409, depth409
						if buffer[position] != rune('.') {
							goto l412
						}
						position++
						goto l409
					l412:
						position, tokenIndex, depth = position409, tokenIndex409, depth409
						{
							position413, tokenIndex413, depth413 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l414
							}
							position++
							goto l413
						l414:
							position, tokenIndex, depth = position413, tokenIndex413, depth413
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l408
							}
							position++
						}
					l413:
					}
				l409:
					goto l407
				l408:
					position, tokenIndex, depth = position408, tokenIndex408, depth408
				}
				{
					position415, tokenIndex415, depth415 := position, tokenIndex, depth
					{
						position417, tokenIndex417, depth417 := position, tokenIndex, depth
						if buffer[position] != rune('.') {
							goto l418
						}
						position++
						goto l417
					l418:
						position, tokenIndex, depth = position417, tokenIndex417, depth417
						if buffer[position] != rune('+') {
							goto l419
						}
						position++
						goto l417
					l419:
						position, tokenIndex, depth = position417, tokenIndex417, depth417
						if buffer[position] != rune('-') {
							goto l415
						}
						position++
					}
				l417:
					goto l416
				l415:
					position, tokenIndex, depth = position415, tokenIndex415, depth415
				}
			l416:
				depth--
				add(ruleInstructionName, position404)
			}
			return true
		l403:
			position, tokenIndex, depth = position403, tokenIndex403, depth403
			return false
		},
		/* 29 InstructionArg <- <(IndirectionIndicator? (ARMConstantTweak / RegisterOrConstant / LocalLabelRef / TOCRefHigh / TOCRefLow / GOTLocation / GOTSymbolOffset / MemoryRef) AVX512Token*)> */
		func() bool {
			position420, tokenIndex420, depth420 := position, tokenIndex, depth
			{
				position421 := position
				depth++
				{
					position422, tokenIndex422, depth422 := position, tokenIndex, depth
					if !_rules[ruleIndirectionIndicator]() {
						goto l422
					}
					goto l423
				l422:
					position, tokenIndex, depth = position422, tokenIndex422, depth422
				}
			l423:
				{
					position424, tokenIndex424, depth424 := position, tokenIndex, depth
					if !_rules[ruleARMConstantTweak]() {
						goto l425
					}
					goto l424
				l425:
					position, tokenIndex, depth = position424, tokenIndex424, depth424
					if !_rules[ruleRegisterOrConstant]() {
						goto l426
					}
					goto l424
				l426:
					position, tokenIndex, depth = position424, tokenIndex424, depth424
					if !_rules[ruleLocalLabelRef]() {
						goto l427
					}
					goto l424
				l427:
					position, tokenIndex, depth = position424, tokenIndex424, depth424
					if !_rules[ruleTOCRefHigh]() {
						goto l428
					}
					goto l424
				l428:
					position, tokenIndex, depth = position424, tokenIndex424, depth424
					if !_rules[ruleTOCRefLow]() {
						goto l429
					}
					goto l424
				l429:
					position, tokenIndex, depth = position424, tokenIndex424, depth424
					if !_rules[ruleGOTLocation]() {
						goto l430
					}
					goto l424
				l430:
					position, tokenIndex, depth = position424, tokenIndex424, depth424
					if !_rules[ruleGOTSymbolOffset]() {
						goto l431
					}
					goto l424
				l431:
					position, tokenIndex, depth = position424, tokenIndex424, depth424
					if !_rules[ruleMemoryRef]() {
						goto l420
					}
				}
			l424:
			l432:
				{
					position433, tokenIndex433, depth433 := position, tokenIndex, depth
					if !_rules[ruleAVX512Token]() {
						goto l433
					}
					goto l432
				l433:
					position, tokenIndex, depth = position433, tokenIndex433, depth433
				}
				depth--
				add(ruleInstructionArg, position421)
			}
			return true
		l420:
			position, tokenIndex, depth = position420, tokenIndex420, depth420
			return false
		},
		/* 30 GOTLocation <- <('$' '_' 'G' 'L' 'O' 'B' 'A' 'L' '_' 'O' 'F' 'F' 'S' 'E' 'T' '_' 'T' 'A' 'B' 'L' 'E' '_' '-' LocalSymbol)> */
		func() bool {
			position434, tokenIndex434, depth434 := position, tokenIndex, depth
			{
				position435 := position
				depth++
				if buffer[position] != rune('$') {
					goto l434
				}
				position++
				if buffer[position] != rune('_') {
					goto l434
				}
				position++
				if buffer[position] != rune('G') {
					goto l434
				}
				position++
				if buffer[position] != rune('L') {
					goto l434
				}
				position++
				if buffer[position] != rune('O') {
					goto l434
				}
				position++
				if buffer[position] != rune('B') {
					goto l434
				}
				position++
				if buffer[position] != rune('A') {
					goto l434
				}
				position++
				if buffer[position] != rune('L') {
					goto l434
				}
				position++
				if buffer[position] != rune('_') {
					goto l434
				}
				position++
				if buffer[position] != rune('O') {
					goto l434
				}
				position++
				if buffer[position] != rune('F') {
					goto l434
				}
				position++
				if buffer[position] != rune('F') {
					goto l434
				}
				position++
				if buffer[position] != rune('S') {
					goto l434
				}
				position++
				if buffer[position] != rune('E') {
					goto l434
				}
				position++
				if buffer[position] != rune('T') {
					goto l434
				}
				position++
				if buffer[position] != rune('_') {
					goto l434
				}
				position++
				if buffer[position] != rune('T') {
					goto l434
				}
				position++
				if buffer[position] != rune('A') {
					goto l434
				}
				position++
				if buffer[position] != rune('B') {
					goto l434
				}
				position++
				if buffer[position] != rune('L') {
					goto l434
				}
				position++
				if buffer[position] != rune('E') {
					goto l434
				}
				position++
				if buffer[position] != rune('_') {
					goto l434
				}
				position++
				if buffer[position] != rune('-') {
					goto l434
				}
				position++
				if !_rules[ruleLocalSymbol]() {
					goto l434
				}
				depth--
				add(ruleGOTLocation, position435)
			}
			return true
		l434:
			position, tokenIndex, depth = position434, tokenIndex434, depth434
			return false
		},
		/* 31 GOTSymbolOffset <- <(('$' SymbolName ('@' 'G' 'O' 'T') ('O' 'F' 'F')?) / (':' ('g' / 'G') ('o' / 'O') ('t' / 'T') ':' SymbolName))> */
		func() bool {
			position436, tokenIndex436, depth436 := position, tokenIndex, depth
			{
				position437 := position
				depth++
				{
					position438, tokenIndex438, depth438 := position, tokenIndex, depth
					if buffer[position] != rune('$') {
						goto l439
					}
					position++
					if !_rules[ruleSymbolName]() {
						goto l439
					}
					if buffer[position] != rune('@') {
						goto l439
					}
					position++
					if buffer[position] != rune('G') {
						goto l439
					}
					position++
					if buffer[position] != rune('O') {
						goto l439
					}
					position++
					if buffer[position] != rune('T') {
						goto l439
					}
					position++
					{
						position440, tokenIndex440, depth440 := position, tokenIndex, depth
						if buffer[position] != rune('O') {
							goto l440
						}
						position++
						if buffer[position] != rune('F') {
							goto l440
						}
						position++
						if buffer[position] != rune('F') {
							goto l440
						}
						position++
						goto l441
					l440:
						position, tokenIndex, depth = position440, tokenIndex440, depth440
					}
				l441:
					goto l438
				l439:
					position, tokenIndex, depth = position438, tokenIndex438, depth438
					if buffer[position] != rune(':') {
						goto l436
					}
					position++
					{
						position442, tokenIndex442, depth442 := position, tokenIndex, depth
						if buffer[position] != rune('g') {
							goto l443
						}
						position++
						goto l442
					l443:
						position, tokenIndex, depth = position442, tokenIndex442, depth442
						if buffer[position] != rune('G') {
							goto l436
						}
						position++
					}
				l442:
					{
						position444, tokenIndex444, depth444 := position, tokenIndex, depth
						if buffer[position] != rune('o') {
							goto l445
						}
						position++
						goto l444
					l445:
						position, tokenIndex, depth = position444, tokenIndex444, depth444
						if buffer[position] != rune('O') {
							goto l436
						}
						position++
					}
				l444:
					{
						position446, tokenIndex446, depth446 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l447
						}
						position++
						goto l446
					l447:
						position, tokenIndex, depth = position446, tokenIndex446, depth446
						if buffer[position] != rune('T') {
							goto l436
						}
						position++
					}
				l446:
					if buffer[position] != rune(':') {
						goto l436
					}
					position++
					if !_rules[ruleSymbolName]() {
						goto l436
					}
				}
			l438:
				depth--
				add(ruleGOTSymbolOffset, position437)
			}
			return true
		l436:
			position, tokenIndex, depth = position436, tokenIndex436, depth436
			return false
		},
		/* 32 AVX512Token <- <(WS? '{' '%'? ([0-9] / [a-z])* '}')> */
		func() bool {
			position448, tokenIndex448, depth448 := position, tokenIndex, depth
			{
				position449 := position
				depth++
				{
					position450, tokenIndex450, depth450 := position, tokenIndex, depth
					if !_rules[ruleWS]() {
						goto l450
					}
					goto l451
				l450:
					position, tokenIndex, depth = position450, tokenIndex450, depth450
				}
			l451:
				if buffer[position] != rune('{') {
					goto l448
				}
				position++
				{
					position452, tokenIndex452, depth452 := position, tokenIndex, depth
					if buffer[position] != rune('%') {
						goto l452
					}
					position++
					goto l453
				l452:
					position, tokenIndex, depth = position452, tokenIndex452, depth452
				}
			l453:
			l454:
				{
					position455, tokenIndex455, depth455 := position, tokenIndex, depth
					{
						position456, tokenIndex456, depth456 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l457
						}
						position++
						goto l456
					l457:
						position, tokenIndex, depth = position456, tokenIndex456, depth456
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l455
						}
						position++
					}
				l456:
					goto l454
				l455:
					position, tokenIndex, depth = position455, tokenIndex455, depth455
				}
				if buffer[position] != rune('}') {
					goto l448
				}
				position++
				depth--
				add(ruleAVX512Token, position449)
			}
			return true
		l448:
			position, tokenIndex, depth = position448, tokenIndex448, depth448
			return false
		},
		/* 33 TOCRefHigh <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' ([a-z] / [A-Z] / '_' / [0-9])+)) ('@' ('h' / 'H') ('a' / 'A')))> */
		func() bool {
			position458, tokenIndex458, depth458 := position, tokenIndex, depth
			{
				position459 := position
				depth++
				if buffer[position] != rune('.') {
					goto l458
				}
				position++
				if buffer[position] != rune('T') {
					goto l458
				}
				position++
				if buffer[position] != rune('O') {
					goto l458
				}
				position++
				if buffer[position] != rune('C') {
					goto l458
				}
				position++
				if buffer[position] != rune('.') {
					goto l458
				}
				position++
				if buffer[position] != rune('-') {
					goto l458
				}
				position++
				{
					position460, tokenIndex460, depth460 := position, tokenIndex, depth
					if buffer[position] != rune('0') {
						goto l461
					}
					position++
					if buffer[position] != rune('b') {
						goto l461
					}
					position++
					goto l460
				l461:
					position, tokenIndex, depth = position460, tokenIndex460, depth460
					if buffer[position] != rune('.') {
						goto l458
					}
					position++
					if buffer[position] != rune('L') {
						goto l458
					}
					position++
					{
						position464, tokenIndex464, depth464 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l465
						}
						position++
						goto l464
					l465:
						position, tokenIndex, depth = position464, tokenIndex464, depth464
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l466
						}
						position++
						goto l464
					l466:
						position, tokenIndex, depth = position464, tokenIndex464, depth464
						if buffer[position] != rune('_') {
							goto l467
						}
						position++
						goto l464
					l467:
						position, tokenIndex, depth = position464, tokenIndex464, depth464
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l458
						}
						position++
					}
				l464:
				l462:
					{
						position463, tokenIndex463, depth463 := position, tokenIndex, depth
						{
							position468, tokenIndex468, depth468 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l469
							}
							position++
							goto l468
						l469:
							position, tokenIndex, depth = position468, tokenIndex468, depth468
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l470
							}
							position++
							goto l468
						l470:
							position, tokenIndex, depth = position468, tokenIndex468, depth468
							if buffer[position] != rune('_') {
								goto l471
							}
							position++
							goto l468
						l471:
							position, tokenIndex, depth = position468, tokenIndex468, depth468
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l463
							}
							position++
						}
					l468:
						goto l462
					l463:
						position, tokenIndex, depth = position463, tokenIndex463, depth463
					}
				}
			l460:
				if buffer[position] != rune('@') {
					goto l458
				}
				position++
				{
					position472, tokenIndex472, depth472 := position, tokenIndex, depth
					if buffer[position] != rune('h') {
						goto l473
					}
					position++
					goto l472
				l473:
					position, tokenIndex, depth = position472, tokenIndex472, depth472
					if buffer[position] != rune('H') {
						goto l458
					}
					position++
				}
			l472:
				{
					position474, tokenIndex474, depth474 := position, tokenIndex, depth
					if buffer[position] != rune('a') {
						goto l475
					}
					position++
					goto l474
				l475:
					position, tokenIndex, depth = position474, tokenIndex474, depth474
					if buffer[position] != rune('A') {
						goto l458
					}
					position++
				}
			l474:
				depth--
				add(ruleTOCRefHigh, position459)
			}
			return true
		l458:
			position, tokenIndex, depth = position458, tokenIndex458, depth458
			return false
		},
		/* 34 TOCRefLow <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' ([a-z] / [A-Z] / '_' / [0-9])+)) ('@' ('l' / 'L')))> */
		func() bool {
			position476, tokenIndex476, depth476 := position, tokenIndex, depth
			{
				position477 := position
				depth++
				if buffer[position] != rune('.') {
					goto l476
				}
				position++
				if buffer[position] != rune('T') {
					goto l476
				}
				position++
				if buffer[position] != rune('O') {
					goto l476
				}
				position++
				if buffer[position] != rune('C') {
					goto l476
				}
				position++
				if buffer[position] != rune('.') {
					goto l476
				}
				position++
				if buffer[position] != rune('-') {
					goto l476
				}
				position++
				{
					position478, tokenIndex478, depth478 := position, tokenIndex, depth
					if buffer[position] != rune('0') {
						goto l479
					}
					position++
					if buffer[position] != rune('b') {
						goto l479
					}
					position++
					goto l478
				l479:
					position, tokenIndex, depth = position478, tokenIndex478, depth478
					if buffer[position] != rune('.') {
						goto l476
					}
					position++
					if buffer[position] != rune('L') {
						goto l476
					}
					position++
					{
						position482, tokenIndex482, depth482 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l483
						}
						position++
						goto l482
					l483:
						position, tokenIndex, depth = position482, tokenIndex482, depth482
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l484
						}
						position++
						goto l482
					l484:
						position, tokenIndex, depth = position482, tokenIndex482, depth482
						if buffer[position] != rune('_') {
							goto l485
						}
						position++
						goto l482
					l485:
						position, tokenIndex, depth = position482, tokenIndex482, depth482
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l476
						}
						position++
					}
				l482:
				l480:
					{
						position481, tokenIndex481, depth481 := position, tokenIndex, depth
						{
							position486, tokenIndex486, depth486 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l487
							}
							position++
							goto l486
						l487:
							position, tokenIndex, depth = position486, tokenIndex486, depth486
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l488
							}
							position++
							goto l486
						l488:
							position, tokenIndex, depth = position486, tokenIndex486, depth486
							if buffer[position] != rune('_') {
								goto l489
							}
							position++
							goto l486
						l489:
							position, tokenIndex, depth = position486, tokenIndex486, depth486
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l481
							}
							position++
						}
					l486:
						goto l480
					l481:
						position, tokenIndex, depth = position481, tokenIndex481, depth481
					}
				}
			l478:
				if buffer[position] != rune('@') {
					goto l476
				}
				position++
				{
					position490, tokenIndex490, depth490 := position, tokenIndex, depth
					if buffer[position] != rune('l') {
						goto l491
					}
					position++
					goto l490
				l491:
					position, tokenIndex, depth = position490, tokenIndex490, depth490
					if buffer[position] != rune('L') {
						goto l476
					}
					position++
				}
			l490:
				depth--
				add(ruleTOCRefLow, position477)
			}
			return true
		l476:
			position, tokenIndex, depth = position476, tokenIndex476, depth476
			return false
		},
		/* 35 IndirectionIndicator <- <'*'> */
		func() bool {
			position492, tokenIndex492, depth492 := position, tokenIndex, depth
			{
				position493 := position
				depth++
				if buffer[position] != rune('*') {
					goto l492
				}
				position++
				depth--
				add(ruleIndirectionIndicator, position493)
			}
			return true
		l492:
			position, tokenIndex, depth = position492, tokenIndex492, depth492
			return false
		},
		/* 36 RegisterOrConstant <- <((('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))*) / ('$'? ((Offset Offset) / Offset)) / ('#' Offset ('*' [0-9]+ ('-' [0-9] [0-9]*)?)?) / ('#' '~'? '(' [0-9] WS? ('<' '<') WS? [0-9] ')') / ARMRegister) !('f' / 'b' / ':' / '(' / '+' / '-'))> */
		func() bool {
			position494, tokenIndex494, depth494 := position, tokenIndex, depth
			{
				position495 := position
				depth++
				{
					position496, tokenIndex496, depth496 := position, tokenIndex, depth
					if buffer[position] != rune('%') {
						goto l497
					}
					position++
					{
						position498, tokenIndex498, depth498 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l499
						}
						position++
						goto l498
					l499:
						position, tokenIndex, depth = position498, tokenIndex498, depth498
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l497
						}
						position++
					}
				l498:
				l500:
					{
						position501, tokenIndex501, depth501 := position, tokenIndex, depth
						{
							position502, tokenIndex502, depth502 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l503
							}
							position++
							goto l502
						l503:
							position, tokenIndex, depth = position502, tokenIndex502, depth502
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l504
							}
							position++
							goto l502
						l504:
							position, tokenIndex, depth = position502, tokenIndex502, depth502
							{
								position505, tokenIndex505, depth505 := position, tokenIndex, depth
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l506
								}
								position++
								goto l505
							l506:
								position, tokenIndex, depth = position505, tokenIndex505, depth505
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l501
								}
								position++
							}
						l505:
						}
					l502:
						goto l500
					l501:
						position, tokenIndex, depth = position501, tokenIndex501, depth501
					}
					goto l496
				l497:
					position, tokenIndex, depth = position496, tokenIndex496, depth496
					{
						position508, tokenIndex508, depth508 := position, tokenIndex, depth
						if buffer[position] != rune('$') {
							goto l508
						}
						position++
						goto l509
					l508:
						position, tokenIndex, depth = position508, tokenIndex508, depth508
					}
				l509:
					{
						position510, tokenIndex510, depth510 := position, tokenIndex, depth
						if !_rules[ruleOffset]() {
							goto l511
						}
						if !_rules[ruleOffset]() {
							goto l511
						}
						goto l510
					l511:
						position, tokenIndex, depth = position510, tokenIndex510, depth510
						if !_rules[ruleOffset]() {
							goto l507
						}
					}
				l510:
					goto l496
				l507:
					position, tokenIndex, depth = position496, tokenIndex496, depth496
					if buffer[position] != rune('#') {
						goto l512
					}
					position++
					if !_rules[ruleOffset]() {
						goto l512
					}
					{
						position513, tokenIndex513, depth513 := position, tokenIndex, depth
						if buffer[position] != rune('*') {
							goto l513
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l513
						}
						position++
					l515:
						{
							position516, tokenIndex516, depth516 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l516
							}
							position++
							goto l515
						l516:
							position, tokenIndex, depth = position516, tokenIndex516, depth516
						}
						{
							position517, tokenIndex517, depth517 := position, tokenIndex, depth
							if buffer[position] != rune('-') {
								goto l517
							}
							position++
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l517
							}
							position++
						l519:
							{
								position520, tokenIndex520, depth520 := position, tokenIndex, depth
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l520
								}
								position++
								goto l519
							l520:
								position, tokenIndex, depth = position520, tokenIndex520, depth520
							}
							goto l518
						l517:
							position, tokenIndex, depth = position517, tokenIndex517, depth517
						}
					l518:
						goto l514
					l513:
						position, tokenIndex, depth = position513, tokenIndex513, depth513
					}
				l514:
					goto l496
				l512:
					position, tokenIndex, depth = position496, tokenIndex496, depth496
					if buffer[position] != rune('#') {
						goto l521
					}
					position++
					{
						position522, tokenIndex522, depth522 := position, tokenIndex, depth
						if buffer[position] != rune('~') {
							goto l522
						}
						position++
						goto l523
					l522:
						position, tokenIndex, depth = position522, tokenIndex522, depth522
					}
				l523:
					if buffer[position] != rune('(') {
						goto l521
					}
					position++
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l521
					}
					position++
					{
						position524, tokenIndex524, depth524 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l524
						}
						goto l525
					l524:
						position, tokenIndex, depth = position524, tokenIndex524, depth524
					}
				l525:
					if buffer[position] != rune('<') {
						goto l521
					}
					position++
					if buffer[position] != rune('<') {
						goto l521
					}
					position++
					{
						position526, tokenIndex526, depth526 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l526
						}
						goto l527
					l526:
						position, tokenIndex, depth = position526, tokenIndex526, depth526
					}
				l527:
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l521
					}
					position++
					if buffer[position] != rune(')') {
						goto l521
					}
					position++
					goto l496
				l521:
					position, tokenIndex, depth = position496, tokenIndex496, depth496
					if !_rules[ruleARMRegister]() {
						goto l494
					}
				}
			l496:
				{
					position528, tokenIndex528, depth528 := position, tokenIndex, depth
					{
						position529, tokenIndex529, depth529 := position, tokenIndex, depth
						if buffer[position] != rune('f') {
							goto l530
						}
						position++
						goto l529
					l530:
						position, tokenIndex, depth = position529, tokenIndex529, depth529
						if buffer[position] != rune('b') {
							goto l531
						}
						position++
						goto l529
					l531:
						position, tokenIndex, depth = position529, tokenIndex529, depth529
						if buffer[position] != rune(':') {
							goto l532
						}
						position++
						goto l529
					l532:
						position, tokenIndex, depth = position529, tokenIndex529, depth529
						if buffer[position] != rune('(') {
							goto l533
						}
						position++
						goto l529
					l533:
						position, tokenIndex, depth = position529, tokenIndex529, depth529
						if buffer[position] != rune('+') {
							goto l534
						}
						position++
						goto l529
					l534:
						position, tokenIndex, depth = position529, tokenIndex529, depth529
						if buffer[position] != rune('-') {
							goto l528
						}
						position++
					}
				l529:
					goto l494
				l528:
					position, tokenIndex, depth = position528, tokenIndex528, depth528
				}
				depth--
				add(ruleRegisterOrConstant, position495)
			}
			return true
		l494:
			position, tokenIndex, depth = position494, tokenIndex494, depth494
			return false
		},
		/* 37 ARMConstantTweak <- <(((('l' / 'L') ('s' / 'S') ('l' / 'L')) / (('s' / 'S') ('x' / 'X') ('t' / 'T') ('w' / 'W')) / (('u' / 'U') ('x' / 'X') ('t' / 'T') ('w' / 'W')) / (('u' / 'U') ('x' / 'X') ('t' / 'T') ('b' / 'B')) / (('l' / 'L') ('s' / 'S') ('r' / 'R')) / (('r' / 'R') ('o' / 'O') ('r' / 'R')) / (('a' / 'A') ('s' / 'S') ('r' / 'R'))) (WS '#' Offset)?)> */
		func() bool {
			position535, tokenIndex535, depth535 := position, tokenIndex, depth
			{
				position536 := position
				depth++
				{
					position537, tokenIndex537, depth537 := position, tokenIndex, depth
					{
						position539, tokenIndex539, depth539 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l540
						}
						position++
						goto l539
					l540:
						position, tokenIndex, depth = position539, tokenIndex539, depth539
						if buffer[position] != rune('L') {
							goto l538
						}
						position++
					}
				l539:
					{
						position541, tokenIndex541, depth541 := position, tokenIndex, depth
						if buffer[position] != rune('s') {
							goto l542
						}
						position++
						goto l541
					l542:
						position, tokenIndex, depth = position541, tokenIndex541, depth541
						if buffer[position] != rune('S') {
							goto l538
						}
						position++
					}
				l541:
					{
						position543, tokenIndex543, depth543 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l544
						}
						position++
						goto l543
					l544:
						position, tokenIndex, depth = position543, tokenIndex543, depth543
						if buffer[position] != rune('L') {
							goto l538
						}
						position++
					}
				l543:
					goto l537
				l538:
					position, tokenIndex, depth = position537, tokenIndex537, depth537
					{
						position546, tokenIndex546, depth546 := position, tokenIndex, depth
						if buffer[position] != rune('s') {
							goto l547
						}
						position++
						goto l546
					l547:
						position, tokenIndex, depth = position546, tokenIndex546, depth546
						if buffer[position] != rune('S') {
							goto l545
						}
						position++
					}
				l546:
					{
						position548, tokenIndex548, depth548 := position, tokenIndex, depth
						if buffer[position] != rune('x') {
							goto l549
						}
						position++
						goto l548
					l549:
						position, tokenIndex, depth = position548, tokenIndex548, depth548
						if buffer[position] != rune('X') {
							goto l545
						}
						position++
					}
				l548:
					{
						position550, tokenIndex550, depth550 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l551
						}
						position++
						goto l550
					l551:
						position, tokenIndex, depth = position550, tokenIndex550, depth550
						if buffer[position] != rune('T') {
							goto l545
						}
						position++
					}
				l550:
					{
						position552, tokenIndex552, depth552 := position, tokenIndex, depth
						if buffer[position] != rune('w') {
							goto l553
						}
						position++
						goto l552
					l553:
						position, tokenIndex, depth = position552, tokenIndex552, depth552
						if buffer[position] != rune('W') {
							goto l545
						}
						position++
					}
				l552:
					goto l537
				l545:
					position, tokenIndex, depth = position537, tokenIndex537, depth537
					{
						position555, tokenIndex555, depth555 := position, tokenIndex, depth
						if buffer[position] != rune('u') {
							goto l556
						}
						position++
						goto l555
					l556:
						position, tokenIndex, depth = position555, tokenIndex555, depth555
						if buffer[position] != rune('U') {
							goto l554
						}
						position++
					}
				l555:
					{
						position557, tokenIndex557, depth557 := position, tokenIndex, depth
						if buffer[position] != rune('x') {
							goto l558
						}
						position++
						goto l557
					l558:
						position, tokenIndex, depth = position557, tokenIndex557, depth557
						if buffer[position] != rune('X') {
							goto l554
						}
						position++
					}
				l557:
					{
						position559, tokenIndex559, depth559 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l560
						}
						position++
						goto l559
					l560:
						position, tokenIndex, depth = position559, tokenIndex559, depth559
						if buffer[position] != rune('T') {
							goto l554
						}
						position++
					}
				l559:
					{
						position561, tokenIndex561, depth561 := position, tokenIndex, depth
						if buffer[position] != rune('w') {
							goto l562
						}
						position++
						goto l561
					l562:
						position, tokenIndex, depth = position561, tokenIndex561, depth561
						if buffer[position] != rune('W') {
							goto l554
						}
						position++
					}
				l561:
					goto l537
				l554:
					position, tokenIndex, depth = position537, tokenIndex537, depth537
					{
						position564, tokenIndex564, depth564 := position, tokenIndex, depth
						if buffer[position] != rune('u') {
							goto l565
						}
						position++
						goto l564
					l565:
						position, tokenIndex, depth = position564, tokenIndex564, depth564
						if buffer[position] != rune('U') {
							goto l563
						}
						position++
					}
				l564:
					{
						position566, tokenIndex566, depth566 := position, tokenIndex, depth
						if buffer[position] != rune('x') {
							goto l567
						}
						position++
						goto l566
					l567:
						position, tokenIndex, depth = position566, tokenIndex566, depth566
						if buffer[position] != rune('X') {
							goto l563
						}
						position++
					}
				l566:
					{
						position568, tokenIndex568, depth568 := position, tokenIndex, depth
						if buffer[position] != rune('t') {
							goto l569
						}
						position++
						goto l568
					l569:
						position, tokenIndex, depth = position568, tokenIndex568, depth568
						if buffer[position] != rune('T') {
							goto l563
						}
						position++
					}
				l568:
					{
						position570, tokenIndex570, depth570 := position, tokenIndex, depth
						if buffer[position] != rune('b') {
							goto l571
						}
						position++
						goto l570
					l571:
						position, tokenIndex, depth = position570, tokenIndex570, depth570
						if buffer[position] != rune('B') {
							goto l563
						}
						position++
					}
				l570:
					goto l537
				l563:
					position, tokenIndex, depth = position537, tokenIndex537, depth537
					{
						position573, tokenIndex573, depth573 := position, tokenIndex, depth
						if buffer[position] != rune('l') {
							goto l574
						}
						position++
						goto l573
					l574:
						position, tokenIndex, depth = position573, tokenIndex573, depth573
						if buffer[position] != rune('L') {
							goto l572
						}
						position++
					}
				l573:
					{
						position575, tokenIndex575, depth575 := position, tokenIndex, depth
						if buffer[position] != rune('s') {
							goto l576
						}
						position++
						goto l575
					l576:
						position, tokenIndex, depth = position575, tokenIndex575, depth575
						if buffer[position] != rune('S') {
							goto l572
						}
						position++
					}
				l575:
					{
						position577, tokenIndex577, depth577 := position, tokenIndex, depth
						if buffer[position] != rune('r') {
							goto l578
						}
						position++
						goto l577
					l578:
						position, tokenIndex, depth = position577, tokenIndex577, depth577
						if buffer[position] != rune('R') {
							goto l572
						}
						position++
					}
				l577:
					goto l537
				l572:
					position, tokenIndex, depth = position537, tokenIndex537, depth537
					{
						position580, tokenIndex580, depth580 := position, tokenIndex, depth
						if buffer[position] != rune('r') {
							goto l581
						}
						position++
						goto l580
					l581:
						position, tokenIndex, depth = position580, tokenIndex580, depth580
						if buffer[position] != rune('R') {
							goto l579
						}
						position++
					}
				l580:
					{
						position582, tokenIndex582, depth582 := position, tokenIndex, depth
						if buffer[position] != rune('o') {
							goto l583
						}
						position++
						goto l582
					l583:
						position, tokenIndex, depth = position582, tokenIndex582, depth582
						if buffer[position] != rune('O') {
							goto l579
						}
						position++
					}
				l582:
					{
						position584, tokenIndex584, depth584 := position, tokenIndex, depth
						if buffer[position] != rune('r') {
							goto l585
						}
						position++
						goto l584
					l585:
						position, tokenIndex, depth = position584, tokenIndex584, depth584
						if buffer[position] != rune('R') {
							goto l579
						}
						position++
					}
				l584:
					goto l537
				l579:
					position, tokenIndex, depth = position537, tokenIndex537, depth537
					{
						position586, tokenIndex586, depth586 := position, tokenIndex, depth
						if buffer[position] != rune('a') {
							goto l587
						}
						position++
						goto l586
					l587:
						position, tokenIndex, depth = position586, tokenIndex586, depth586
						if buffer[position] != rune('A') {
							goto l535
						}
						position++
					}
				l586:
					{
						position588, tokenIndex588, depth588 := position, tokenIndex, depth
						if buffer[position] != rune('s') {
							goto l589
						}
						position++
						goto l588
					l589:
						position, tokenIndex, depth = position588, tokenIndex588, depth588
						if buffer[position] != rune('S') {
							goto l535
						}
						position++
					}
				l588:
					{
						position590, tokenIndex590, depth590 := position, tokenIndex, depth
						if buffer[position] != rune('r') {
							goto l591
						}
						position++
						goto l590
					l591:
						position, tokenIndex, depth = position590, tokenIndex590, depth590
						if buffer[position] != rune('R') {
							goto l535
						}
						position++
					}
				l590:
				}
			l537:
				{
					position592, tokenIndex592, depth592 := position, tokenIndex, depth
					if !_rules[ruleWS]() {
						goto l592
					}
					if buffer[position] != rune('#') {
						goto l592
					}
					position++
					if !_rules[ruleOffset]() {
						goto l592
					}
					goto l593
				l592:
					position, tokenIndex, depth = position592, tokenIndex592, depth592
				}
			l593:
				depth--
				add(ruleARMConstantTweak, position536)
			}
			return true
		l535:
			position, tokenIndex, depth = position535, tokenIndex535, depth535
			return false
		},
		/* 38 ARMRegister <- <((('s' / 'S') ('p' / 'P')) / (('x' / 'w' / 'd' / 'q' / 's') [0-9] [0-9]?) / (('x' / 'X') ('z' / 'Z') ('r' / 'R')) / (('w' / 'W') ('z' / 'Z') ('r' / 'R')) / ARMVectorRegister / ('{' WS? ARMVectorRegister (',' WS? ARMVectorRegister)* WS? '}' ('[' [0-9] ']')?))> */
		func() bool {
			position594, tokenIndex594, depth594 := position, tokenIndex, depth
			{
				position595 := position
				depth++
				{
					position596, tokenIndex596, depth596 := position, tokenIndex, depth
					{
						position598, tokenIndex598, depth598 := position, tokenIndex, depth
						if buffer[position] != rune('s') {
							goto l599
						}
						position++
						goto l598
					l599:
						position, tokenIndex, depth = position598, tokenIndex598, depth598
						if buffer[position] != rune('S') {
							goto l597
						}
						position++
					}
				l598:
					{
						position600, tokenIndex600, depth600 := position, tokenIndex, depth
						if buffer[position] != rune('p') {
							goto l601
						}
						position++
						goto l600
					l601:
						position, tokenIndex, depth = position600, tokenIndex600, depth600
						if buffer[position] != rune('P') {
							goto l597
						}
						position++
					}
				l600:
					goto l596
				l597:
					position, tokenIndex, depth = position596, tokenIndex596, depth596
					{
						position603, tokenIndex603, depth603 := position, tokenIndex, depth
						if buffer[position] != rune('x') {
							goto l604
						}
						position++
						goto l603
					l604:
						position, tokenIndex, depth = position603, tokenIndex603, depth603
						if buffer[position] != rune('w') {
							goto l605
						}
						position++
						goto l603
					l605:
						position, tokenIndex, depth = position603, tokenIndex603, depth603
						if buffer[position] != rune('d') {
							goto l606
						}
						position++
						goto l603
					l606:
						position, tokenIndex, depth = position603, tokenIndex603, depth603
						if buffer[position] != rune('q') {
							goto l607
						}
						position++
						goto l603
					l607:
						position, tokenIndex, depth = position603, tokenIndex603, depth603
						if buffer[position] != rune('s') {
							goto l602
						}
						position++
					}
				l603:
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l602
					}
					position++
					{
						position608, tokenIndex608, depth608 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l608
						}
						position++
						goto l609
					l608:
						position, tokenIndex, depth = position608, tokenIndex608, depth608
					}
				l609:
					goto l596
				l602:
					position, tokenIndex, depth = position596, tokenIndex596, depth596
					{
						position611, tokenIndex611, depth611 := position, tokenIndex, depth
						if buffer[position] != rune('x') {
							goto l612
						}
						position++
						goto l611
					l612:
						position, tokenIndex, depth = position611, tokenIndex611, depth611
						if buffer[position] != rune('X') {
							goto l610
						}
						position++
					}
				l611:
					{
						position613, tokenIndex613, depth613 := position, tokenIndex, depth
						if buffer[position] != rune('z') {
							goto l614
						}
						position++
						goto l613
					l614:
						position, tokenIndex, depth = position613, tokenIndex613, depth613
						if buffer[position] != rune('Z') {
							goto l610
						}
						position++
					}
				l613:
					{
						position615, tokenIndex615, depth615 := position, tokenIndex, depth
						if buffer[position] != rune('r') {
							goto l616
						}
						position++
						goto l615
					l616:
						position, tokenIndex, depth = position615, tokenIndex615, depth615
						if buffer[position] != rune('R') {
							goto l610
						}
						position++
					}
				l615:
					goto l596
				l610:
					position, tokenIndex, depth = position596, tokenIndex596, depth596
					{
						position618, tokenIndex618, depth618 := position, tokenIndex, depth
						if buffer[position] != rune('w') {
							goto l619
						}
						position++
						goto l618
					l619:
						position, tokenIndex, depth = position618, tokenIndex618, depth618
						if buffer[position] != rune('W') {
							goto l617
						}
						position++
					}
				l618:
					{
						position620, tokenIndex620, depth620 := position, tokenIndex, depth
						if buffer[position] != rune('z') {
							goto l621
						}
						position++
						goto l620
					l621:
						position, tokenIndex, depth = position620, tokenIndex620, depth620
						if buffer[position] != rune('Z') {
							goto l617
						}
						position++
					}
				l620:
					{
						position622, tokenIndex622, depth622 := position, tokenIndex, depth
						if buffer[position] != rune('r') {
							goto l623
						}
						position++
						goto l622
					l623:
						position, tokenIndex, depth = position622, tokenIndex622, depth622
						if buffer[position] != rune('R') {
							goto l617
						}
						position++
					}
				l622:
					goto l596
				l617:
					position, tokenIndex, depth = position596, tokenIndex596, depth596
					if !_rules[ruleARMVectorRegister]() {
						goto l624
					}
					goto l596
				l624:
					position, tokenIndex, depth = position596, tokenIndex596, depth596
					if buffer[position] != rune('{') {
						goto l594
					}
					position++
					{
						position625, tokenIndex625, depth625 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l625
						}
						goto l626
					l625:
						position, tokenIndex, depth = position625, tokenIndex625, depth625
					}
				l626:
					if !_rules[ruleARMVectorRegister]() {
						goto l594
					}
				l627:
					{
						position628, tokenIndex628, depth628 := position, tokenIndex, depth
						if buffer[position] != rune(',') {
							goto l628
						}
						position++
						{
							position629, tokenIndex629, depth629 := position, tokenIndex, depth
							if !_rules[ruleWS]() {
								goto l629
							}
							goto l630
						l629:
							position, tokenIndex, depth = position629, tokenIndex629, depth629
						}
					l630:
						if !_rules[ruleARMVectorRegister]() {
							goto l628
						}
						goto l627
					l628:
						position, tokenIndex, depth = position628, tokenIndex628, depth628
					}
					{
						position631, tokenIndex631, depth631 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l631
						}
						goto l632
					l631:
						position, tokenIndex, depth = position631, tokenIndex631, depth631
					}
				l632:
					if buffer[position] != rune('}') {
						goto l594
					}
					position++
					{
						position633, tokenIndex633, depth633 := position, tokenIndex, depth
						if buffer[position] != rune('[') {
							goto l633
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l633
						}
						position++
						if buffer[position] != rune(']') {
							goto l633
						}
						position++
						goto l634
					l633:
						position, tokenIndex, depth = position633, tokenIndex633, depth633
					}
				l634:
				}
			l596:
				depth--
				add(ruleARMRegister, position595)
			}
			return true
		l594:
			position, tokenIndex, depth = position594, tokenIndex594, depth594
			return false
		},
		/* 39 ARMVectorRegister <- <(('v' / 'V') [0-9] [0-9]? ('.' [0-9]* ('b' / 's' / 'd' / 'h' / 'q') ('[' [0-9] ']')?)?)> */
		func() bool {
			position635, tokenIndex635, depth635 := position, tokenIndex, depth
			{
				position636 := position
				depth++
				{
					position637, tokenIndex637, depth637 := position, tokenIndex, depth
					if buffer[position] != rune('v') {
						goto l638
					}
					position++
					goto l637
				l638:
					position, tokenIndex, depth = position637, tokenIndex637, depth637
					if buffer[position] != rune('V') {
						goto l635
					}
					position++
				}
			l637:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l635
				}
				position++
				{
					position639, tokenIndex639, depth639 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l639
					}
					position++
					goto l640
				l639:
					position, tokenIndex, depth = position639, tokenIndex639, depth639
				}
			l640:
				{
					position641, tokenIndex641, depth641 := position, tokenIndex, depth
					if buffer[position] != rune('.') {
						goto l641
					}
					position++
				l643:
					{
						position644, tokenIndex644, depth644 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l644
						}
						position++
						goto l643
					l644:
						position, tokenIndex, depth = position644, tokenIndex644, depth644
					}
					{
						position645, tokenIndex645, depth645 := position, tokenIndex, depth
						if buffer[position] != rune('b') {
							goto l646
						}
						position++
						goto l645
					l646:
						position, tokenIndex, depth = position645, tokenIndex645, depth645
						if buffer[position] != rune('s') {
							goto l647
						}
						position++
						goto l645
					l647:
						position, tokenIndex, depth = position645, tokenIndex645, depth645
						if buffer[position] != rune('d') {
							goto l648
						}
						position++
						goto l645
					l648:
						position, tokenIndex, depth = position645, tokenIndex645, depth645
						if buffer[position] != rune('h') {
							goto l649
						}
						position++
						goto l645
					l649:
						position, tokenIndex, depth = position645, tokenIndex645, depth645
						if buffer[position] != rune('q') {
							goto l641
						}
						position++
					}
				l645:
					{
						position650, tokenIndex650, depth650 := position, tokenIndex, depth
						if buffer[position] != rune('[') {
							goto l650
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l650
						}
						position++
						if buffer[position] != rune(']') {
							goto l650
						}
						position++
						goto l651
					l650:
						position, tokenIndex, depth = position650, tokenIndex650, depth650
					}
				l651:
					goto l642
				l641:
					position, tokenIndex, depth = position641, tokenIndex641, depth641
				}
			l642:
				depth--
				add(ruleARMVectorRegister, position636)
			}
			return true
		l635:
			position, tokenIndex, depth = position635, tokenIndex635, depth635
			return false
		},
		/* 40 MemoryRef <- <((SymbolRef BaseIndexScale) / SymbolRef / Low12BitsSymbolRef / (Offset* BaseIndexScale) / (SegmentRegister Offset BaseIndexScale) / (SegmentRegister BaseIndexScale) / (SegmentRegister Offset) / ARMBaseIndexScale / BaseIndexScale)> */
		func() bool {
			position652, tokenIndex652, depth652 := position, tokenIndex, depth
			{
				position653 := position
				depth++
				{
					position654, tokenIndex654, depth654 := position, tokenIndex, depth
					if !_rules[ruleSymbolRef]() {
						goto l655
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l655
					}
					goto l654
				l655:
					position, tokenIndex, depth = position654, tokenIndex654, depth654
					if !_rules[ruleSymbolRef]() {
						goto l656
					}
					goto l654
				l656:
					position, tokenIndex, depth = position654, tokenIndex654, depth654
					if !_rules[ruleLow12BitsSymbolRef]() {
						goto l657
					}
					goto l654
				l657:
					position, tokenIndex, depth = position654, tokenIndex654, depth654
				l659:
					{
						position660, tokenIndex660, depth660 := position, tokenIndex, depth
						if !_rules[ruleOffset]() {
							goto l660
						}
						goto l659
					l660:
						position, tokenIndex, depth = position660, tokenIndex660, depth660
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l658
					}
					goto l654
				l658:
					position, tokenIndex, depth = position654, tokenIndex654, depth654
					if !_rules[ruleSegmentRegister]() {
						goto l661
					}
					if !_rules[ruleOffset]() {
						goto l661
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l661
					}
					goto l654
				l661:
					position, tokenIndex, depth = position654, tokenIndex654, depth654
					if !_rules[ruleSegmentRegister]() {
						goto l662
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l662
					}
					goto l654
				l662:
					position, tokenIndex, depth = position654, tokenIndex654, depth654
					if !_rules[ruleSegmentRegister]() {
						goto l663
					}
					if !_rules[ruleOffset]() {
						goto l663
					}
					goto l654
				l663:
					position, tokenIndex, depth = position654, tokenIndex654, depth654
					if !_rules[ruleARMBaseIndexScale]() {
						goto l664
					}
					goto l654
				l664:
					position, tokenIndex, depth = position654, tokenIndex654, depth654
					if !_rules[ruleBaseIndexScale]() {
						goto l652
					}
				}
			l654:
				depth--
				add(ruleMemoryRef, position653)
			}
			return true
		l652:
			position, tokenIndex, depth = position652, tokenIndex652, depth652
			return false
		},
		/* 41 SymbolRef <- <((Offset* '+')? (LocalSymbol / SymbolName) Offset* ('@' Section Offset*)?)> */
		func() bool {
			position665, tokenIndex665, depth665 := position, tokenIndex, depth
			{
				position666 := position
				depth++
				{
					position667, tokenIndex667, depth667 := position, tokenIndex, depth
				l669:
					{
						position670, tokenIndex670, depth670 := position, tokenIndex, depth
						if !_rules[ruleOffset]() {
							goto l670
						}
						goto l669
					l670:
						position, tokenIndex, depth = position670, tokenIndex670, depth670
					}
					if buffer[position] != rune('+') {
						goto l667
					}
					position++
					goto l668
				l667:
					position, tokenIndex, depth = position667, tokenIndex667, depth667
				}
			l668:
				{
					position671, tokenIndex671, depth671 := position, tokenIndex, depth
					if !_rules[ruleLocalSymbol]() {
						goto l672
					}
					goto l671
				l672:
					position, tokenIndex, depth = position671, tokenIndex671, depth671
					if !_rules[ruleSymbolName]() {
						goto l665
					}
				}
			l671:
			l673:
				{
					position674, tokenIndex674, depth674 := position, tokenIndex, depth
					if !_rules[ruleOffset]() {
						goto l674
					}
					goto l673
				l674:
					position, tokenIndex, depth = position674, tokenIndex674, depth674
				}
				{
					position675, tokenIndex675, depth675 := position, tokenIndex, depth
					if buffer[position] != rune('@') {
						goto l675
					}
					position++
					if !_rules[ruleSection]() {
						goto l675
					}
				l677:
					{
						position678, tokenIndex678, depth678 := position, tokenIndex, depth
						if !_rules[ruleOffset]() {
							goto l678
						}
						goto l677
					l678:
						position, tokenIndex, depth = position678, tokenIndex678, depth678
					}
					goto l676
				l675:
					position, tokenIndex, depth = position675, tokenIndex675, depth675
				}
			l676:
				depth--
				add(ruleSymbolRef, position666)
			}
			return true
		l665:
			position, tokenIndex, depth = position665, tokenIndex665, depth665
			return false
		},
		/* 42 Low12BitsSymbolRef <- <(':' ('l' / 'L') ('o' / 'O') '1' '2' ':' (LocalSymbol / SymbolName) Offset?)> */
		func() bool {
			position679, tokenIndex679, depth679 := position, tokenIndex, depth
			{
				position680 := position
				depth++
				if buffer[position] != rune(':') {
					goto l679
				}
				position++
				{
					position681, tokenIndex681, depth681 := position, tokenIndex, depth
					if buffer[position] != rune('l') {
						goto l682
					}
					position++
					goto l681
				l682:
					position, tokenIndex, depth = position681, tokenIndex681, depth681
					if buffer[position] != rune('L') {
						goto l679
					}
					position++
				}
			l681:
				{
					position683, tokenIndex683, depth683 := position, tokenIndex, depth
					if buffer[position] != rune('o') {
						goto l684
					}
					position++
					goto l683
				l684:
					position, tokenIndex, depth = position683, tokenIndex683, depth683
					if buffer[position] != rune('O') {
						goto l679
					}
					position++
				}
			l683:
				if buffer[position] != rune('1') {
					goto l679
				}
				position++
				if buffer[position] != rune('2') {
					goto l679
				}
				position++
				if buffer[position] != rune(':') {
					goto l679
				}
				position++
				{
					position685, tokenIndex685, depth685 := position, tokenIndex, depth
					if !_rules[ruleLocalSymbol]() {
						goto l686
					}
					goto l685
				l686:
					position, tokenIndex, depth = position685, tokenIndex685, depth685
					if !_rules[ruleSymbolName]() {
						goto l679
					}
				}
			l685:
				{
					position687, tokenIndex687, depth687 := position, tokenIndex, depth
					if !_rules[ruleOffset]() {
						goto l687
					}
					goto l688
				l687:
					position, tokenIndex, depth = position687, tokenIndex687, depth687
				}
			l688:
				depth--
				add(ruleLow12BitsSymbolRef, position680)
			}
			return true
		l679:
			position, tokenIndex, depth = position679, tokenIndex679, depth679
			return false
		},
		/* 43 ARMBaseIndexScale <- <('[' ARMRegister (',' WS? (('#' Offset ('*' [0-9]+)?) / ARMGOTLow12 / Low12BitsSymbolRef / ARMCapReference / ARMRegister) (',' WS? ARMConstantTweak)?)? ']' ARMPostincrement?)> */
		func() bool {
			position689, tokenIndex689, depth689 := position, tokenIndex, depth
			{
				position690 := position
				depth++
				if buffer[position] != rune('[') {
					goto l689
				}
				position++
				if !_rules[ruleARMRegister]() {
					goto l689
				}
				{
					position691, tokenIndex691, depth691 := position, tokenIndex, depth
					if buffer[position] != rune(',') {
						goto l691
					}
					position++
					{
						position693, tokenIndex693, depth693 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l693
						}
						goto l694
					l693:
						position, tokenIndex, depth = position693, tokenIndex693, depth693
					}
				l694:
					{
						position695, tokenIndex695, depth695 := position, tokenIndex, depth
						if buffer[position] != rune('#') {
							goto l696
						}
						position++
						if !_rules[ruleOffset]() {
							goto l696
						}
						{
							position697, tokenIndex697, depth697 := position, tokenIndex, depth
							if buffer[position] != rune('*') {
								goto l697
							}
							position++
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l697
							}
							position++
						l699:
							{
								position700, tokenIndex700, depth700 := position, tokenIndex, depth
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l700
								}
								position++
								goto l699
							l700:
								position, tokenIndex, depth = position700, tokenIndex700, depth700
							}
							goto l698
						l697:
							position, tokenIndex, depth = position697, tokenIndex697, depth697
						}
					l698:
						goto l695
					l696:
						position, tokenIndex, depth = position695, tokenIndex695, depth695
						if !_rules[ruleARMGOTLow12]() {
							goto l701
						}
						goto l695
					l701:
						position, tokenIndex, depth = position695, tokenIndex695, depth695
						if !_rules[ruleLow12BitsSymbolRef]() {
							goto l702
						}
						goto l695
					l702:
						position, tokenIndex, depth = position695, tokenIndex695, depth695
						if !_rules[ruleARMCapReference]() {
							goto l703
						}
						goto l695
					l703:
						position, tokenIndex, depth = position695, tokenIndex695, depth695
						if !_rules[ruleARMRegister]() {
							goto l691
						}
					}
				l695:
					{
						position704, tokenIndex704, depth704 := position, tokenIndex, depth
						if buffer[position] != rune(',') {
							goto l704
						}
						position++
						{
							position706, tokenIndex706, depth706 := position, tokenIndex, depth
							if !_rules[ruleWS]() {
								goto l706
							}
							goto l707
						l706:
							position, tokenIndex, depth = position706, tokenIndex706, depth706
						}
					l707:
						if !_rules[ruleARMConstantTweak]() {
							goto l704
						}
						goto l705
					l704:
						position, tokenIndex, depth = position704, tokenIndex704, depth704
					}
				l705:
					goto l692
				l691:
					position, tokenIndex, depth = position691, tokenIndex691, depth691
				}
			l692:
				if buffer[position] != rune(']') {
					goto l689
				}
				position++
				{
					position708, tokenIndex708, depth708 := position, tokenIndex, depth
					if !_rules[ruleARMPostincrement]() {
						goto l708
					}
					goto l709
				l708:
					position, tokenIndex, depth = position708, tokenIndex708, depth708
				}
			l709:
				depth--
				add(ruleARMBaseIndexScale, position690)
			}
			return true
		l689:
			position, tokenIndex, depth = position689, tokenIndex689, depth689
			return false
		},
		/* 44 ARMGOTLow12 <- <(':' ('g' / 'G') ('o' / 'O') ('t' / 'T') '_' ('l' / 'L') ('o' / 'O') '1' '2' ':' SymbolName)> */
		func() bool {
			position710, tokenIndex710, depth710 := position, tokenIndex, depth
			{
				position711 := position
				depth++
				if buffer[position] != rune(':') {
					goto l710
				}
				position++
				{
					position712, tokenIndex712, depth712 := position, tokenIndex, depth
					if buffer[position] != rune('g') {
						goto l713
					}
					position++
					goto l712
				l713:
					position, tokenIndex, depth = position712, tokenIndex712, depth712
					if buffer[position] != rune('G') {
						goto l710
					}
					position++
				}
			l712:
				{
					position714, tokenIndex714, depth714 := position, tokenIndex, depth
					if buffer[position] != rune('o') {
						goto l715
					}
					position++
					goto l714
				l715:
					position, tokenIndex, depth = position714, tokenIndex714, depth714
					if buffer[position] != rune('O') {
						goto l710
					}
					position++
				}
			l714:
				{
					position716, tokenIndex716, depth716 := position, tokenIndex, depth
					if buffer[position] != rune('t') {
						goto l717
					}
					position++
					goto l716
				l717:
					position, tokenIndex, depth = position716, tokenIndex716, depth716
					if buffer[position] != rune('T') {
						goto l710
					}
					position++
				}
			l716:
				if buffer[position] != rune('_') {
					goto l710
				}
				position++
				{
					position718, tokenIndex718, depth718 := position, tokenIndex, depth
					if buffer[position] != rune('l') {
						goto l719
					}
					position++
					goto l718
				l719:
					position, tokenIndex, depth = position718, tokenIndex718, depth718
					if buffer[position] != rune('L') {
						goto l710
					}
					position++
				}
			l718:
				{
					position720, tokenIndex720, depth720 := position, tokenIndex, depth
					if buffer[position] != rune('o') {
						goto l721
					}
					position++
					goto l720
				l721:
					position, tokenIndex, depth = position720, tokenIndex720, depth720
					if buffer[position] != rune('O') {
						goto l710
					}
					position++
				}
			l720:
				if buffer[position] != rune('1') {
					goto l710
				}
				position++
				if buffer[position] != rune('2') {
					goto l710
				}
				position++
				if buffer[position] != rune(':') {
					goto l710
				}
				position++
				if !_rules[ruleSymbolName]() {
					goto l710
				}
				depth--
				add(ruleARMGOTLow12, position711)
			}
			return true
		l710:
			position, tokenIndex, depth = position710, tokenIndex710, depth710
			return false
		},
		/* 45 ARMCapReference <- <(':' ('l' / 'L') ('o' / 'O') '1' '2' ':' ('o' / 'O') ('p' / 'P') ('e' / 'E') ('n' / 'N') ('s' / 'S') ('s' / 'S') ('l' / 'L') '_' ('a' / 'A') ('r' / 'R') ('m' / 'M') ('c' / 'C') ('a' / 'A') ('p' / 'P') '_' ('p' / 'P'))> */
		func() bool {
			position722, tokenIndex722, depth722 := position, tokenIndex, depth
			{
				position723 := position
				depth++
				if buffer[position] != rune(':') {
					goto l722
				}
				position++
				{
					position724, tokenIndex724, depth724 := position, tokenIndex, depth
					if buffer[position] != rune('l') {
						goto l725
					}
					position++
					goto l724
				l725:
					position, tokenIndex, depth = position724, tokenIndex724, depth724
					if buffer[position] != rune('L') {
						goto l722
					}
					position++
				}
			l724:
				{
					position726, tokenIndex726, depth726 := position, tokenIndex, depth
					if buffer[position] != rune('o') {
						goto l727
					}
					position++
					goto l726
				l727:
					position, tokenIndex, depth = position726, tokenIndex726, depth726
					if buffer[position] != rune('O') {
						goto l722
					}
					position++
				}
			l726:
				if buffer[position] != rune('1') {
					goto l722
				}
				position++
				if buffer[position] != rune('2') {
					goto l722
				}
				position++
				if buffer[position] != rune(':') {
					goto l722
				}
				position++
				{
					position728, tokenIndex728, depth728 := position, tokenIndex, depth
					if buffer[position] != rune('o') {
						goto l729
					}
					position++
					goto l728
				l729:
					position, tokenIndex, depth = position728, tokenIndex728, depth728
					if buffer[position] != rune('O') {
						goto l722
					}
					position++
				}
			l728:
				{
					position730, tokenIndex730, depth730 := position, tokenIndex, depth
					if buffer[position] != rune('p') {
						goto l731
					}
					position++
					goto l730
				l731:
					position, tokenIndex, depth = position730, tokenIndex730, depth730
					if buffer[position] != rune('P') {
						goto l722
					}
					position++
				}
			l730:
				{
					position732, tokenIndex732, depth732 := position, tokenIndex, depth
					if buffer[position] != rune('e') {
						goto l733
					}
					position++
					goto l732
				l733:
					position, tokenIndex, depth = position732, tokenIndex732, depth732
					if buffer[position] != rune('E') {
						goto l722
					}
					position++
				}
			l732:
				{
					position734, tokenIndex734, depth734 := position, tokenIndex, depth
					if buffer[position] != rune('n') {
						goto l735
					}
					position++
					goto l734
				l735:
					position, tokenIndex, depth = position734, tokenIndex734, depth734
					if buffer[position] != rune('N') {
						goto l722
					}
					position++
				}
			l734:
				{
					position736, tokenIndex736, depth736 := position, tokenIndex, depth
					if buffer[position] != rune('s') {
						goto l737
					}
					position++
					goto l736
				l737:
					position, tokenIndex, depth = position736, tokenIndex736, depth736
					if buffer[position] != rune('S') {
						goto l722
					}
					position++
				}
			l736:
				{
					position738, tokenIndex738, depth738 := position, tokenIndex, depth
					if buffer[position] != rune('s') {
						goto l739
					}
					position++
					goto l738
				l739:
					position, tokenIndex, depth = position738, tokenIndex738, depth738
					if buffer[position] != rune('S') {
						goto l722
					}
					position++
				}
			l738:
				{
					position740, tokenIndex740, depth740 := position, tokenIndex, depth
					if buffer[position] != rune('l') {
						goto l741
					}
					position++
					goto l740
				l741:
					position, tokenIndex, depth = position740, tokenIndex740, depth740
					if buffer[position] != rune('L') {
						goto l722
					}
					position++
				}
			l740:
				if buffer[position] != rune('_') {
					goto l722
				}
				position++
				{
					position742, tokenIndex742, depth742 := position, tokenIndex, depth
					if buffer[position] != rune('a') {
						goto l743
					}
					position++
					goto l742
				l743:
					position, tokenIndex, depth = position742, tokenIndex742, depth742
					if buffer[position] != rune('A') {
						goto l722
					}
					position++
				}
			l742:
				{
					position744, tokenIndex744, depth744 := position, tokenIndex, depth
					if buffer[position] != rune('r') {
						goto l745
					}
					position++
					goto l744
				l745:
					position, tokenIndex, depth = position744, tokenIndex744, depth744
					if buffer[position] != rune('R') {
						goto l722
					}
					position++
				}
			l744:
				{
					position746, tokenIndex746, depth746 := position, tokenIndex, depth
					if buffer[position] != rune('m') {
						goto l747
					}
					position++
					goto l746
				l747:
					position, tokenIndex, depth = position746, tokenIndex746, depth746
					if buffer[position] != rune('M') {
						goto l722
					}
					position++
				}
			l746:
				{
					position748, tokenIndex748, depth748 := position, tokenIndex, depth
					if buffer[position] != rune('c') {
						goto l749
					}
					position++
					goto l748
				l749:
					position, tokenIndex, depth = position748, tokenIndex748, depth748
					if buffer[position] != rune('C') {
						goto l722
					}
					position++
				}
			l748:
				{
					position750, tokenIndex750, depth750 := position, tokenIndex, depth
					if buffer[position] != rune('a') {
						goto l751
					}
					position++
					goto l750
				l751:
					position, tokenIndex, depth = position750, tokenIndex750, depth750
					if buffer[position] != rune('A') {
						goto l722
					}
					position++
				}
			l750:
				{
					position752, tokenIndex752, depth752 := position, tokenIndex, depth
					if buffer[position] != rune('p') {
						goto l753
					}
					position++
					goto l752
				l753:
					position, tokenIndex, depth = position752, tokenIndex752, depth752
					if buffer[position] != rune('P') {
						goto l722
					}
					position++
				}
			l752:
				if buffer[position] != rune('_') {
					goto l722
				}
				position++
				{
					position754, tokenIndex754, depth754 := position, tokenIndex, depth
					if buffer[position] != rune('p') {
						goto l755
					}
					position++
					goto l754
				l755:
					position, tokenIndex, depth = position754, tokenIndex754, depth754
					if buffer[position] != rune('P') {
						goto l722
					}
					position++
				}
			l754:
				depth--
				add(ruleARMCapReference, position723)
			}
			return true
		l722:
			position, tokenIndex, depth = position722, tokenIndex722, depth722
			return false
		},
		/* 46 ARMPostincrement <- <'!'> */
		func() bool {
			position756, tokenIndex756, depth756 := position, tokenIndex, depth
			{
				position757 := position
				depth++
				if buffer[position] != rune('!') {
					goto l756
				}
				position++
				depth--
				add(ruleARMPostincrement, position757)
			}
			return true
		l756:
			position, tokenIndex, depth = position756, tokenIndex756, depth756
			return false
		},
		/* 47 BaseIndexScale <- <('(' RegisterOrConstant? WS? (',' WS? RegisterOrConstant WS? (',' [0-9]+)?)? ')')> */
		func() bool {
			position758, tokenIndex758, depth758 := position, tokenIndex, depth
			{
				position759 := position
				depth++
				if buffer[position] != rune('(') {
					goto l758
				}
				position++
				{
					position760, tokenIndex760, depth760 := position, tokenIndex, depth
					if !_rules[ruleRegisterOrConstant]() {
						goto l760
					}
					goto l761
				l760:
					position, tokenIndex, depth = position760, tokenIndex760, depth760
				}
			l761:
				{
					position762, tokenIndex762, depth762 := position, tokenIndex, depth
					if !_rules[ruleWS]() {
						goto l762
					}
					goto l763
				l762:
					position, tokenIndex, depth = position762, tokenIndex762, depth762
				}
			l763:
				{
					position764, tokenIndex764, depth764 := position, tokenIndex, depth
					if buffer[position] != rune(',') {
						goto l764
					}
					position++
					{
						position766, tokenIndex766, depth766 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l766
						}
						goto l767
					l766:
						position, tokenIndex, depth = position766, tokenIndex766, depth766
					}
				l767:
					if !_rules[ruleRegisterOrConstant]() {
						goto l764
					}
					{
						position768, tokenIndex768, depth768 := position, tokenIndex, depth
						if !_rules[ruleWS]() {
							goto l768
						}
						goto l769
					l768:
						position, tokenIndex, depth = position768, tokenIndex768, depth768
					}
				l769:
					{
						position770, tokenIndex770, depth770 := position, tokenIndex, depth
						if buffer[position] != rune(',') {
							goto l770
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l770
						}
						position++
					l772:
						{
							position773, tokenIndex773, depth773 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l773
							}
							position++
							goto l772
						l773:
							position, tokenIndex, depth = position773, tokenIndex773, depth773
						}
						goto l771
					l770:
						position, tokenIndex, depth = position770, tokenIndex770, depth770
					}
				l771:
					goto l765
				l764:
					position, tokenIndex, depth = position764, tokenIndex764, depth764
				}
			l765:
				if buffer[position] != rune(')') {
					goto l758
				}
				position++
				depth--
				add(ruleBaseIndexScale, position759)
			}
			return true
		l758:
			position, tokenIndex, depth = position758, tokenIndex758, depth758
			return false
		},
		/* 48 Operator <- <('+' / '-')> */
		func() bool {
			position774, tokenIndex774, depth774 := position, tokenIndex, depth
			{
				position775 := position
				depth++
				{
					position776, tokenIndex776, depth776 := position, tokenIndex, depth
					if buffer[position] != rune('+') {
						goto l777
					}
					position++
					goto l776
				l777:
					position, tokenIndex, depth = position776, tokenIndex776, depth776
					if buffer[position] != rune('-') {
						goto l774
					}
					position++
				}
			l776:
				depth--
				add(ruleOperator, position775)
			}
			return true
		l774:
			position, tokenIndex, depth = position774, tokenIndex774, depth774
			return false
		},
		/* 49 Offset <- <('+'? '-'? (('0' ('b' / 'B') ('0' / '1')+) / ('0' ('x' / 'X') ([0-9] / [0-9] / ([a-f] / [A-F]))+) / [0-9]+))> */
		func() bool {
			position778, tokenIndex778, depth778 := position, tokenIndex, depth
			{
				position779 := position
				depth++
				{
					position780, tokenIndex780, depth780 := position, tokenIndex, depth
					if buffer[position] != rune('+') {
						goto l780
					}
					position++
					goto l781
				l780:
					position, tokenIndex, depth = position780, tokenIndex780, depth780
				}
			l781:
				{
					position782, tokenIndex782, depth782 := position, tokenIndex, depth
					if buffer[position] != rune('-') {
						goto l782
					}
					position++
					goto l783
				l782:
					position, tokenIndex, depth = position782, tokenIndex782, depth782
				}
			l783:
				{
					position784, tokenIndex784, depth784 := position, tokenIndex, depth
					if buffer[position] != rune('0') {
						goto l785
					}
					position++
					{
						position786, tokenIndex786, depth786 := position, tokenIndex, depth
						if buffer[position] != rune('b') {
							goto l787
						}
						position++
						goto l786
					l787:
						position, tokenIndex, depth = position786, tokenIndex786, depth786
						if buffer[position] != rune('B') {
							goto l785
						}
						position++
					}
				l786:
					{
						position790, tokenIndex790, depth790 := position, tokenIndex, depth
						if buffer[position] != rune('0') {
							goto l791
						}
						position++
						goto l790
					l791:
						position, tokenIndex, depth = position790, tokenIndex790, depth790
						if buffer[position] != rune('1') {
							goto l785
						}
						position++
					}
				l790:
				l788:
					{
						position789, tokenIndex789, depth789 := position, tokenIndex, depth
						{
							position792, tokenIndex792, depth792 := position, tokenIndex, depth
							if buffer[position] != rune('0') {
								goto l793
							}
							position++
							goto l792
						l793:
							position, tokenIndex, depth = position792, tokenIndex792, depth792
							if buffer[position] != rune('1') {
								goto l789
							}
							position++
						}
					l792:
						goto l788
					l789:
						position, tokenIndex, depth = position789, tokenIndex789, depth789
					}
					goto l784
				l785:
					position, tokenIndex, depth = position784, tokenIndex784, depth784
					if buffer[position] != rune('0') {
						goto l794
					}
					position++
					{
						position795, tokenIndex795, depth795 := position, tokenIndex, depth
						if buffer[position] != rune('x') {
							goto l796
						}
						position++
						goto l795
					l796:
						position, tokenIndex, depth = position795, tokenIndex795, depth795
						if buffer[position] != rune('X') {
							goto l794
						}
						position++
					}
				l795:
					{
						position799, tokenIndex799, depth799 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l800
						}
						position++
						goto l799
					l800:
						position, tokenIndex, depth = position799, tokenIndex799, depth799
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l801
						}
						position++
						goto l799
					l801:
						position, tokenIndex, depth = position799, tokenIndex799, depth799
						{
							position802, tokenIndex802, depth802 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('a') || c > rune('f') {
								goto l803
							}
							position++
							goto l802
						l803:
							position, tokenIndex, depth = position802, tokenIndex802, depth802
							if c := buffer[position]; c < rune('A') || c > rune('F') {
								goto l794
							}
							position++
						}
					l802:
					}
				l799:
				l797:
					{
						position798, tokenIndex798, depth798 := position, tokenIndex, depth
						{
							position804, tokenIndex804, depth804 := position, tokenIndex, depth
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l805
							}
							position++
							goto l804
						l805:
							position, tokenIndex, depth = position804, tokenIndex804, depth804
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l806
							}
							position++
							goto l804
						l806:
							position, tokenIndex, depth = position804, tokenIndex804, depth804
							{
								position807, tokenIndex807, depth807 := position, tokenIndex, depth
								if c := buffer[position]; c < rune('a') || c > rune('f') {
									goto l808
								}
								position++
								goto l807
							l808:
								position, tokenIndex, depth = position807, tokenIndex807, depth807
								if c := buffer[position]; c < rune('A') || c > rune('F') {
									goto l798
								}
								position++
							}
						l807:
						}
					l804:
						goto l797
					l798:
						position, tokenIndex, depth = position798, tokenIndex798, depth798
					}
					goto l784
				l794:
					position, tokenIndex, depth = position784, tokenIndex784, depth784
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l778
					}
					position++
				l809:
					{
						position810, tokenIndex810, depth810 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l810
						}
						position++
						goto l809
					l810:
						position, tokenIndex, depth = position810, tokenIndex810, depth810
					}
				}
			l784:
				depth--
				add(ruleOffset, position779)
			}
			return true
		l778:
			position, tokenIndex, depth = position778, tokenIndex778, depth778
			return false
		},
		/* 50 Section <- <([a-z] / [A-Z] / '@')+> */
		func() bool {
			position811, tokenIndex811, depth811 := position, tokenIndex, depth
			{
				position812 := position
				depth++
				{
					position815, tokenIndex815, depth815 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l816
					}
					position++
					goto l815
				l816:
					position, tokenIndex, depth = position815, tokenIndex815, depth815
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l817
					}
					position++
					goto l815
				l817:
					position, tokenIndex, depth = position815, tokenIndex815, depth815
					if buffer[position] != rune('@') {
						goto l811
					}
					position++
				}
			l815:
			l813:
				{
					position814, tokenIndex814, depth814 := position, tokenIndex, depth
					{
						position818, tokenIndex818, depth818 := position, tokenIndex, depth
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l819
						}
						position++
						goto l818
					l819:
						position, tokenIndex, depth = position818, tokenIndex818, depth818
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l820
						}
						position++
						goto l818
					l820:
						position, tokenIndex, depth = position818, tokenIndex818, depth818
						if buffer[position] != rune('@') {
							goto l814
						}
						position++
					}
				l818:
					goto l813
				l814:
					position, tokenIndex, depth = position814, tokenIndex814, depth814
				}
				depth--
				add(ruleSection, position812)
			}
			return true
		l811:
			position, tokenIndex, depth = position811, tokenIndex811, depth811
			return false
		},
		/* 51 SegmentRegister <- <('%' ([c-g] / 's') ('s' ':'))> */
		func() bool {
			position821, tokenIndex821, depth821 := position, tokenIndex, depth
			{
				position822 := position
				depth++
				if buffer[position] != rune('%') {
					goto l821
				}
				position++
				{
					position823, tokenIndex823, depth823 := position, tokenIndex, depth
					if c := buffer[position]; c < rune('c') || c > rune('g') {
						goto l824
					}
					position++
					goto l823
				l824:
					position, tokenIndex, depth = position823, tokenIndex823, depth823
					if buffer[position] != rune('s') {
						goto l821
					}
					position++
				}
			l823:
				if buffer[position] != rune('s') {
					goto l821
				}
				position++
				if buffer[position] != rune(':') {
					goto l821
				}
				position++
				depth--
				add(ruleSegmentRegister, position822)
			}
			return true
		l821:
			position, tokenIndex, depth = position821, tokenIndex821, depth821
			return false
		},
	}
	p.rules = _rules
}
