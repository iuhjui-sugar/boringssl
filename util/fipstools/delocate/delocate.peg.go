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
	ruleSymbolShift
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
	ruleARMPostincrement
	ruleBaseIndexScale
	ruleOperator
	ruleOffset
	ruleSection
	ruleSegmentRegister
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
	"SymbolShift",
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
	"ARMPostincrement",
	"BaseIndexScale",
	"Operator",
	"Offset",
	"Section",
	"SegmentRegister",
}

type token32 struct {
	pegRule
	begin, end uint32
}

func (t *token32) String() string {
	return fmt.Sprintf("\x1B[34m%v\x1B[m %v %v", rul3s[t.pegRule], t.begin, t.end)
}

type node32 struct {
	token32
	up, next *node32
}

func (node *node32) print(pretty bool, buffer string) {
	var print func(node *node32, depth int)
	print = func(node *node32, depth int) {
		for node != nil {
			for c := 0; c < depth; c++ {
				fmt.Printf(" ")
			}
			rule := rul3s[node.pegRule]
			quote := strconv.Quote(string(([]rune(buffer)[node.begin:node.end])))
			if !pretty {
				fmt.Printf("%v %v\n", rule, quote)
			} else {
				fmt.Printf("\x1B[34m%v\x1B[m %v\n", rule, quote)
			}
			if node.up != nil {
				print(node.up, depth+1)
			}
			node = node.next
		}
	}
	print(node, 0)
}

func (node *node32) Print(buffer string) {
	node.print(false, buffer)
}

func (node *node32) PrettyPrint(buffer string) {
	node.print(true, buffer)
}

type tokens32 struct {
	tree []token32
}

func (t *tokens32) Trim(length uint32) {
	t.tree = t.tree[:length]
}

func (t *tokens32) Print() {
	for _, token := range t.tree {
		fmt.Println(token.String())
	}
}

func (t *tokens32) AST() *node32 {
	type element struct {
		node *node32
		down *element
	}
	tokens := t.Tokens()
	var stack *element
	for _, token := range tokens {
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
	if stack != nil {
		return stack.node
	}
	return nil
}

func (t *tokens32) PrintSyntaxTree(buffer string) {
	t.AST().Print(buffer)
}

func (t *tokens32) PrettyPrintSyntaxTree(buffer string) {
	t.AST().PrettyPrint(buffer)
}

func (t *tokens32) Add(rule pegRule, begin, end, index uint32) {
	if tree := t.tree; int(index) >= len(tree) {
		expanded := make([]token32, 2*len(tree))
		copy(expanded, tree)
		t.tree = expanded
	}
	t.tree[index] = token32{
		pegRule: rule,
		begin:   begin,
		end:     end,
	}
}

func (t *tokens32) Tokens() []token32 {
	return t.tree
}

type Asm struct {
	Buffer string
	buffer []rune
	rules  [53]func() bool
	parse  func(rule ...int) error
	reset  func()
	Pretty bool
	tokens32
}

func (p *Asm) Parse(rule ...int) error {
	return p.parse(rule...)
}

func (p *Asm) Reset() {
	p.reset()
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
	if p.Pretty {
		p.tokens32.PrettyPrintSyntaxTree(p.Buffer)
	} else {
		p.tokens32.PrintSyntaxTree(p.Buffer)
	}
}

func (p *Asm) Init() {
	var (
		max                  token32
		position, tokenIndex uint32
		buffer               []rune
	)
	p.reset = func() {
		max = token32{}
		position, tokenIndex = 0, 0

		p.buffer = []rune(p.Buffer)
		if len(p.buffer) == 0 || p.buffer[len(p.buffer)-1] != endSymbol {
			p.buffer = append(p.buffer, endSymbol)
		}
		buffer = p.buffer
	}
	p.reset()

	_rules := p.rules
	tree := tokens32{tree: make([]token32, math.MaxInt16)}
	p.parse = func(rule ...int) error {
		r := 1
		if len(rule) > 0 {
			r = rule[0]
		}
		matches := p.rules[r]()
		p.tokens32 = tree
		if matches {
			p.Trim(tokenIndex)
			return nil
		}
		return &parseError{p, max}
	}

	add := func(rule pegRule, begin uint32) {
		tree.Add(rule, begin, position, tokenIndex)
		tokenIndex++
		if begin != position && position > max.end {
			max = token32{rule, begin, position}
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
			position0, tokenIndex0 := position, tokenIndex
			{
				position1 := position
			l2:
				{
					position3, tokenIndex3 := position, tokenIndex
					if !_rules[ruleStatement]() {
						goto l3
					}
					goto l2
				l3:
					position, tokenIndex = position3, tokenIndex3
				}
				{
					position4, tokenIndex4 := position, tokenIndex
					if !matchDot() {
						goto l4
					}
					goto l0
				l4:
					position, tokenIndex = position4, tokenIndex4
				}
				add(ruleAsmFile, position1)
			}
			return true
		l0:
			position, tokenIndex = position0, tokenIndex0
			return false
		},
		/* 1 Statement <- <(WS? (Label / ((GlobalDirective / LocationDirective / LabelContainingDirective / Instruction / Directive / Comment / ) WS? ((Comment? '\n') / ';'))))> */
		func() bool {
			position5, tokenIndex5 := position, tokenIndex
			{
				position6 := position
				{
					position7, tokenIndex7 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l7
					}
					goto l8
				l7:
					position, tokenIndex = position7, tokenIndex7
				}
			l8:
				{
					position9, tokenIndex9 := position, tokenIndex
					if !_rules[ruleLabel]() {
						goto l10
					}
					goto l9
				l10:
					position, tokenIndex = position9, tokenIndex9
					{
						position11, tokenIndex11 := position, tokenIndex
						if !_rules[ruleGlobalDirective]() {
							goto l12
						}
						goto l11
					l12:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleLocationDirective]() {
							goto l13
						}
						goto l11
					l13:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleLabelContainingDirective]() {
							goto l14
						}
						goto l11
					l14:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleInstruction]() {
							goto l15
						}
						goto l11
					l15:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleDirective]() {
							goto l16
						}
						goto l11
					l16:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleComment]() {
							goto l17
						}
						goto l11
					l17:
						position, tokenIndex = position11, tokenIndex11
					}
				l11:
					{
						position18, tokenIndex18 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l18
						}
						goto l19
					l18:
						position, tokenIndex = position18, tokenIndex18
					}
				l19:
					{
						position20, tokenIndex20 := position, tokenIndex
						{
							position22, tokenIndex22 := position, tokenIndex
							if !_rules[ruleComment]() {
								goto l22
							}
							goto l23
						l22:
							position, tokenIndex = position22, tokenIndex22
						}
					l23:
						if buffer[position] != rune('\n') {
							goto l21
						}
						position++
						goto l20
					l21:
						position, tokenIndex = position20, tokenIndex20
						if buffer[position] != rune(';') {
							goto l5
						}
						position++
					}
				l20:
				}
			l9:
				add(ruleStatement, position6)
			}
			return true
		l5:
			position, tokenIndex = position5, tokenIndex5
			return false
		},
		/* 2 GlobalDirective <- <((('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('a' / 'A') ('l' / 'L')) / ('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('l' / 'L'))) WS SymbolName)> */
		func() bool {
			position24, tokenIndex24 := position, tokenIndex
			{
				position25 := position
				{
					position26, tokenIndex26 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l27
					}
					position++
					{
						position28, tokenIndex28 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l29
						}
						position++
						goto l28
					l29:
						position, tokenIndex = position28, tokenIndex28
						if buffer[position] != rune('G') {
							goto l27
						}
						position++
					}
				l28:
					{
						position30, tokenIndex30 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l31
						}
						position++
						goto l30
					l31:
						position, tokenIndex = position30, tokenIndex30
						if buffer[position] != rune('L') {
							goto l27
						}
						position++
					}
				l30:
					{
						position32, tokenIndex32 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l33
						}
						position++
						goto l32
					l33:
						position, tokenIndex = position32, tokenIndex32
						if buffer[position] != rune('O') {
							goto l27
						}
						position++
					}
				l32:
					{
						position34, tokenIndex34 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l35
						}
						position++
						goto l34
					l35:
						position, tokenIndex = position34, tokenIndex34
						if buffer[position] != rune('B') {
							goto l27
						}
						position++
					}
				l34:
					{
						position36, tokenIndex36 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l37
						}
						position++
						goto l36
					l37:
						position, tokenIndex = position36, tokenIndex36
						if buffer[position] != rune('A') {
							goto l27
						}
						position++
					}
				l36:
					{
						position38, tokenIndex38 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l39
						}
						position++
						goto l38
					l39:
						position, tokenIndex = position38, tokenIndex38
						if buffer[position] != rune('L') {
							goto l27
						}
						position++
					}
				l38:
					goto l26
				l27:
					position, tokenIndex = position26, tokenIndex26
					if buffer[position] != rune('.') {
						goto l24
					}
					position++
					{
						position40, tokenIndex40 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l41
						}
						position++
						goto l40
					l41:
						position, tokenIndex = position40, tokenIndex40
						if buffer[position] != rune('G') {
							goto l24
						}
						position++
					}
				l40:
					{
						position42, tokenIndex42 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l43
						}
						position++
						goto l42
					l43:
						position, tokenIndex = position42, tokenIndex42
						if buffer[position] != rune('L') {
							goto l24
						}
						position++
					}
				l42:
					{
						position44, tokenIndex44 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l45
						}
						position++
						goto l44
					l45:
						position, tokenIndex = position44, tokenIndex44
						if buffer[position] != rune('O') {
							goto l24
						}
						position++
					}
				l44:
					{
						position46, tokenIndex46 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l47
						}
						position++
						goto l46
					l47:
						position, tokenIndex = position46, tokenIndex46
						if buffer[position] != rune('B') {
							goto l24
						}
						position++
					}
				l46:
					{
						position48, tokenIndex48 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l49
						}
						position++
						goto l48
					l49:
						position, tokenIndex = position48, tokenIndex48
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
				add(ruleGlobalDirective, position25)
			}
			return true
		l24:
			position, tokenIndex = position24, tokenIndex24
			return false
		},
		/* 3 Directive <- <('.' DirectiveName (WS Args)?)> */
		func() bool {
			position50, tokenIndex50 := position, tokenIndex
			{
				position51 := position
				if buffer[position] != rune('.') {
					goto l50
				}
				position++
				if !_rules[ruleDirectiveName]() {
					goto l50
				}
				{
					position52, tokenIndex52 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l52
					}
					if !_rules[ruleArgs]() {
						goto l52
					}
					goto l53
				l52:
					position, tokenIndex = position52, tokenIndex52
				}
			l53:
				add(ruleDirective, position51)
			}
			return true
		l50:
			position, tokenIndex = position50, tokenIndex50
			return false
		},
		/* 4 DirectiveName <- <([a-z] / [A-Z] / ([0-9] / [0-9]) / '_')+> */
		func() bool {
			position54, tokenIndex54 := position, tokenIndex
			{
				position55 := position
				{
					position58, tokenIndex58 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l59
					}
					position++
					goto l58
				l59:
					position, tokenIndex = position58, tokenIndex58
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l60
					}
					position++
					goto l58
				l60:
					position, tokenIndex = position58, tokenIndex58
					{
						position62, tokenIndex62 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l63
						}
						position++
						goto l62
					l63:
						position, tokenIndex = position62, tokenIndex62
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l61
						}
						position++
					}
				l62:
					goto l58
				l61:
					position, tokenIndex = position58, tokenIndex58
					if buffer[position] != rune('_') {
						goto l54
					}
					position++
				}
			l58:
			l56:
				{
					position57, tokenIndex57 := position, tokenIndex
					{
						position64, tokenIndex64 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l65
						}
						position++
						goto l64
					l65:
						position, tokenIndex = position64, tokenIndex64
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l66
						}
						position++
						goto l64
					l66:
						position, tokenIndex = position64, tokenIndex64
						{
							position68, tokenIndex68 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l69
							}
							position++
							goto l68
						l69:
							position, tokenIndex = position68, tokenIndex68
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l67
							}
							position++
						}
					l68:
						goto l64
					l67:
						position, tokenIndex = position64, tokenIndex64
						if buffer[position] != rune('_') {
							goto l57
						}
						position++
					}
				l64:
					goto l56
				l57:
					position, tokenIndex = position57, tokenIndex57
				}
				add(ruleDirectiveName, position55)
			}
			return true
		l54:
			position, tokenIndex = position54, tokenIndex54
			return false
		},
		/* 5 LocationDirective <- <(FileDirective / LocDirective)> */
		func() bool {
			position70, tokenIndex70 := position, tokenIndex
			{
				position71 := position
				{
					position72, tokenIndex72 := position, tokenIndex
					if !_rules[ruleFileDirective]() {
						goto l73
					}
					goto l72
				l73:
					position, tokenIndex = position72, tokenIndex72
					if !_rules[ruleLocDirective]() {
						goto l70
					}
				}
			l72:
				add(ruleLocationDirective, position71)
			}
			return true
		l70:
			position, tokenIndex = position70, tokenIndex70
			return false
		},
		/* 6 FileDirective <- <('.' ('f' / 'F') ('i' / 'I') ('l' / 'L') ('e' / 'E') WS (!('#' / '\n') .)+)> */
		func() bool {
			position74, tokenIndex74 := position, tokenIndex
			{
				position75 := position
				if buffer[position] != rune('.') {
					goto l74
				}
				position++
				{
					position76, tokenIndex76 := position, tokenIndex
					if buffer[position] != rune('f') {
						goto l77
					}
					position++
					goto l76
				l77:
					position, tokenIndex = position76, tokenIndex76
					if buffer[position] != rune('F') {
						goto l74
					}
					position++
				}
			l76:
				{
					position78, tokenIndex78 := position, tokenIndex
					if buffer[position] != rune('i') {
						goto l79
					}
					position++
					goto l78
				l79:
					position, tokenIndex = position78, tokenIndex78
					if buffer[position] != rune('I') {
						goto l74
					}
					position++
				}
			l78:
				{
					position80, tokenIndex80 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l81
					}
					position++
					goto l80
				l81:
					position, tokenIndex = position80, tokenIndex80
					if buffer[position] != rune('L') {
						goto l74
					}
					position++
				}
			l80:
				{
					position82, tokenIndex82 := position, tokenIndex
					if buffer[position] != rune('e') {
						goto l83
					}
					position++
					goto l82
				l83:
					position, tokenIndex = position82, tokenIndex82
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
					position86, tokenIndex86 := position, tokenIndex
					{
						position87, tokenIndex87 := position, tokenIndex
						if buffer[position] != rune('#') {
							goto l88
						}
						position++
						goto l87
					l88:
						position, tokenIndex = position87, tokenIndex87
						if buffer[position] != rune('\n') {
							goto l86
						}
						position++
					}
				l87:
					goto l74
				l86:
					position, tokenIndex = position86, tokenIndex86
				}
				if !matchDot() {
					goto l74
				}
			l84:
				{
					position85, tokenIndex85 := position, tokenIndex
					{
						position89, tokenIndex89 := position, tokenIndex
						{
							position90, tokenIndex90 := position, tokenIndex
							if buffer[position] != rune('#') {
								goto l91
							}
							position++
							goto l90
						l91:
							position, tokenIndex = position90, tokenIndex90
							if buffer[position] != rune('\n') {
								goto l89
							}
							position++
						}
					l90:
						goto l85
					l89:
						position, tokenIndex = position89, tokenIndex89
					}
					if !matchDot() {
						goto l85
					}
					goto l84
				l85:
					position, tokenIndex = position85, tokenIndex85
				}
				add(ruleFileDirective, position75)
			}
			return true
		l74:
			position, tokenIndex = position74, tokenIndex74
			return false
		},
		/* 7 LocDirective <- <('.' ('l' / 'L') ('o' / 'O') ('c' / 'C') WS (!('#' / '/' / '\n') .)+)> */
		func() bool {
			position92, tokenIndex92 := position, tokenIndex
			{
				position93 := position
				if buffer[position] != rune('.') {
					goto l92
				}
				position++
				{
					position94, tokenIndex94 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l95
					}
					position++
					goto l94
				l95:
					position, tokenIndex = position94, tokenIndex94
					if buffer[position] != rune('L') {
						goto l92
					}
					position++
				}
			l94:
				{
					position96, tokenIndex96 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l97
					}
					position++
					goto l96
				l97:
					position, tokenIndex = position96, tokenIndex96
					if buffer[position] != rune('O') {
						goto l92
					}
					position++
				}
			l96:
				{
					position98, tokenIndex98 := position, tokenIndex
					if buffer[position] != rune('c') {
						goto l99
					}
					position++
					goto l98
				l99:
					position, tokenIndex = position98, tokenIndex98
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
					position102, tokenIndex102 := position, tokenIndex
					{
						position103, tokenIndex103 := position, tokenIndex
						if buffer[position] != rune('#') {
							goto l104
						}
						position++
						goto l103
					l104:
						position, tokenIndex = position103, tokenIndex103
						if buffer[position] != rune('/') {
							goto l105
						}
						position++
						goto l103
					l105:
						position, tokenIndex = position103, tokenIndex103
						if buffer[position] != rune('\n') {
							goto l102
						}
						position++
					}
				l103:
					goto l92
				l102:
					position, tokenIndex = position102, tokenIndex102
				}
				if !matchDot() {
					goto l92
				}
			l100:
				{
					position101, tokenIndex101 := position, tokenIndex
					{
						position106, tokenIndex106 := position, tokenIndex
						{
							position107, tokenIndex107 := position, tokenIndex
							if buffer[position] != rune('#') {
								goto l108
							}
							position++
							goto l107
						l108:
							position, tokenIndex = position107, tokenIndex107
							if buffer[position] != rune('/') {
								goto l109
							}
							position++
							goto l107
						l109:
							position, tokenIndex = position107, tokenIndex107
							if buffer[position] != rune('\n') {
								goto l106
							}
							position++
						}
					l107:
						goto l101
					l106:
						position, tokenIndex = position106, tokenIndex106
					}
					if !matchDot() {
						goto l101
					}
					goto l100
				l101:
					position, tokenIndex = position101, tokenIndex101
				}
				add(ruleLocDirective, position93)
			}
			return true
		l92:
			position, tokenIndex = position92, tokenIndex92
			return false
		},
		/* 8 Args <- <(Arg (WS? ',' WS? Arg)*)> */
		func() bool {
			position110, tokenIndex110 := position, tokenIndex
			{
				position111 := position
				if !_rules[ruleArg]() {
					goto l110
				}
			l112:
				{
					position113, tokenIndex113 := position, tokenIndex
					{
						position114, tokenIndex114 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l114
						}
						goto l115
					l114:
						position, tokenIndex = position114, tokenIndex114
					}
				l115:
					if buffer[position] != rune(',') {
						goto l113
					}
					position++
					{
						position116, tokenIndex116 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l116
						}
						goto l117
					l116:
						position, tokenIndex = position116, tokenIndex116
					}
				l117:
					if !_rules[ruleArg]() {
						goto l113
					}
					goto l112
				l113:
					position, tokenIndex = position113, tokenIndex113
				}
				add(ruleArgs, position111)
			}
			return true
		l110:
			position, tokenIndex = position110, tokenIndex110
			return false
		},
		/* 9 Arg <- <(QuotedArg / ([0-9] / [0-9] / ([a-z] / [A-Z]) / '%' / '+' / '-' / '*' / '_' / '@' / '.')*)> */
		func() bool {
			{
				position119 := position
				{
					position120, tokenIndex120 := position, tokenIndex
					if !_rules[ruleQuotedArg]() {
						goto l121
					}
					goto l120
				l121:
					position, tokenIndex = position120, tokenIndex120
				l122:
					{
						position123, tokenIndex123 := position, tokenIndex
						{
							position124, tokenIndex124 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l125
							}
							position++
							goto l124
						l125:
							position, tokenIndex = position124, tokenIndex124
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l126
							}
							position++
							goto l124
						l126:
							position, tokenIndex = position124, tokenIndex124
							{
								position128, tokenIndex128 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('z') {
									goto l129
								}
								position++
								goto l128
							l129:
								position, tokenIndex = position128, tokenIndex128
								if c := buffer[position]; c < rune('A') || c > rune('Z') {
									goto l127
								}
								position++
							}
						l128:
							goto l124
						l127:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('%') {
								goto l130
							}
							position++
							goto l124
						l130:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('+') {
								goto l131
							}
							position++
							goto l124
						l131:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('-') {
								goto l132
							}
							position++
							goto l124
						l132:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('*') {
								goto l133
							}
							position++
							goto l124
						l133:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('_') {
								goto l134
							}
							position++
							goto l124
						l134:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('@') {
								goto l135
							}
							position++
							goto l124
						l135:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('.') {
								goto l123
							}
							position++
						}
					l124:
						goto l122
					l123:
						position, tokenIndex = position123, tokenIndex123
					}
				}
			l120:
				add(ruleArg, position119)
			}
			return true
		},
		/* 10 QuotedArg <- <('"' QuotedText '"')> */
		func() bool {
			position136, tokenIndex136 := position, tokenIndex
			{
				position137 := position
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
				add(ruleQuotedArg, position137)
			}
			return true
		l136:
			position, tokenIndex = position136, tokenIndex136
			return false
		},
		/* 11 QuotedText <- <(EscapedChar / (!'"' .))*> */
		func() bool {
			{
				position139 := position
			l140:
				{
					position141, tokenIndex141 := position, tokenIndex
					{
						position142, tokenIndex142 := position, tokenIndex
						if !_rules[ruleEscapedChar]() {
							goto l143
						}
						goto l142
					l143:
						position, tokenIndex = position142, tokenIndex142
						{
							position144, tokenIndex144 := position, tokenIndex
							if buffer[position] != rune('"') {
								goto l144
							}
							position++
							goto l141
						l144:
							position, tokenIndex = position144, tokenIndex144
						}
						if !matchDot() {
							goto l141
						}
					}
				l142:
					goto l140
				l141:
					position, tokenIndex = position141, tokenIndex141
				}
				add(ruleQuotedText, position139)
			}
			return true
		},
		/* 12 LabelContainingDirective <- <(LabelContainingDirectiveName WS SymbolArgs)> */
		func() bool {
			position145, tokenIndex145 := position, tokenIndex
			{
				position146 := position
				if !_rules[ruleLabelContainingDirectiveName]() {
					goto l145
				}
				if !_rules[ruleWS]() {
					goto l145
				}
				if !_rules[ruleSymbolArgs]() {
					goto l145
				}
				add(ruleLabelContainingDirective, position146)
			}
			return true
		l145:
			position, tokenIndex = position145, tokenIndex145
			return false
		},
		/* 13 LabelContainingDirectiveName <- <(('.' ('x' / 'X') ('w' / 'W') ('o' / 'O') ('r' / 'R') ('d' / 'D')) / ('.' ('w' / 'W') ('o' / 'O') ('r' / 'R') ('d' / 'D')) / ('.' ('l' / 'L') ('o' / 'O') ('n' / 'N') ('g' / 'G')) / ('.' ('s' / 'S') ('e' / 'E') ('t' / 'T')) / ('.' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' '8' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' '4' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' ('q' / 'Q') ('u' / 'U') ('a' / 'A') ('d' / 'D')) / ('.' ('t' / 'T') ('c' / 'C')) / ('.' ('l' / 'L') ('o' / 'O') ('c' / 'C') ('a' / 'A') ('l' / 'L') ('e' / 'E') ('n' / 'N') ('t' / 'T') ('r' / 'R') ('y' / 'Y')) / ('.' ('s' / 'S') ('i' / 'I') ('z' / 'Z') ('e' / 'E')) / ('.' ('t' / 'T') ('y' / 'Y') ('p' / 'P') ('e' / 'E')) / ('.' ('u' / 'U') ('l' / 'L') ('e' / 'E') ('b' / 'B') '1' '2' '8') / ('.' ('s' / 'S') ('l' / 'L') ('e' / 'E') ('b' / 'B') '1' '2' '8'))> */
		func() bool {
			position147, tokenIndex147 := position, tokenIndex
			{
				position148 := position
				{
					position149, tokenIndex149 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l150
					}
					position++
					{
						position151, tokenIndex151 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l152
						}
						position++
						goto l151
					l152:
						position, tokenIndex = position151, tokenIndex151
						if buffer[position] != rune('X') {
							goto l150
						}
						position++
					}
				l151:
					{
						position153, tokenIndex153 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l154
						}
						position++
						goto l153
					l154:
						position, tokenIndex = position153, tokenIndex153
						if buffer[position] != rune('W') {
							goto l150
						}
						position++
					}
				l153:
					{
						position155, tokenIndex155 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l156
						}
						position++
						goto l155
					l156:
						position, tokenIndex = position155, tokenIndex155
						if buffer[position] != rune('O') {
							goto l150
						}
						position++
					}
				l155:
					{
						position157, tokenIndex157 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l158
						}
						position++
						goto l157
					l158:
						position, tokenIndex = position157, tokenIndex157
						if buffer[position] != rune('R') {
							goto l150
						}
						position++
					}
				l157:
					{
						position159, tokenIndex159 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l160
						}
						position++
						goto l159
					l160:
						position, tokenIndex = position159, tokenIndex159
						if buffer[position] != rune('D') {
							goto l150
						}
						position++
					}
				l159:
					goto l149
				l150:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l161
					}
					position++
					{
						position162, tokenIndex162 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l163
						}
						position++
						goto l162
					l163:
						position, tokenIndex = position162, tokenIndex162
						if buffer[position] != rune('W') {
							goto l161
						}
						position++
					}
				l162:
					{
						position164, tokenIndex164 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l165
						}
						position++
						goto l164
					l165:
						position, tokenIndex = position164, tokenIndex164
						if buffer[position] != rune('O') {
							goto l161
						}
						position++
					}
				l164:
					{
						position166, tokenIndex166 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l167
						}
						position++
						goto l166
					l167:
						position, tokenIndex = position166, tokenIndex166
						if buffer[position] != rune('R') {
							goto l161
						}
						position++
					}
				l166:
					{
						position168, tokenIndex168 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l169
						}
						position++
						goto l168
					l169:
						position, tokenIndex = position168, tokenIndex168
						if buffer[position] != rune('D') {
							goto l161
						}
						position++
					}
				l168:
					goto l149
				l161:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l170
					}
					position++
					{
						position171, tokenIndex171 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l172
						}
						position++
						goto l171
					l172:
						position, tokenIndex = position171, tokenIndex171
						if buffer[position] != rune('L') {
							goto l170
						}
						position++
					}
				l171:
					{
						position173, tokenIndex173 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l174
						}
						position++
						goto l173
					l174:
						position, tokenIndex = position173, tokenIndex173
						if buffer[position] != rune('O') {
							goto l170
						}
						position++
					}
				l173:
					{
						position175, tokenIndex175 := position, tokenIndex
						if buffer[position] != rune('n') {
							goto l176
						}
						position++
						goto l175
					l176:
						position, tokenIndex = position175, tokenIndex175
						if buffer[position] != rune('N') {
							goto l170
						}
						position++
					}
				l175:
					{
						position177, tokenIndex177 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l178
						}
						position++
						goto l177
					l178:
						position, tokenIndex = position177, tokenIndex177
						if buffer[position] != rune('G') {
							goto l170
						}
						position++
					}
				l177:
					goto l149
				l170:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l179
					}
					position++
					{
						position180, tokenIndex180 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l181
						}
						position++
						goto l180
					l181:
						position, tokenIndex = position180, tokenIndex180
						if buffer[position] != rune('S') {
							goto l179
						}
						position++
					}
				l180:
					{
						position182, tokenIndex182 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l183
						}
						position++
						goto l182
					l183:
						position, tokenIndex = position182, tokenIndex182
						if buffer[position] != rune('E') {
							goto l179
						}
						position++
					}
				l182:
					{
						position184, tokenIndex184 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l185
						}
						position++
						goto l184
					l185:
						position, tokenIndex = position184, tokenIndex184
						if buffer[position] != rune('T') {
							goto l179
						}
						position++
					}
				l184:
					goto l149
				l179:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l186
					}
					position++
					{
						position187, tokenIndex187 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l188
						}
						position++
						goto l187
					l188:
						position, tokenIndex = position187, tokenIndex187
						if buffer[position] != rune('B') {
							goto l186
						}
						position++
					}
				l187:
					{
						position189, tokenIndex189 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l190
						}
						position++
						goto l189
					l190:
						position, tokenIndex = position189, tokenIndex189
						if buffer[position] != rune('Y') {
							goto l186
						}
						position++
					}
				l189:
					{
						position191, tokenIndex191 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l192
						}
						position++
						goto l191
					l192:
						position, tokenIndex = position191, tokenIndex191
						if buffer[position] != rune('T') {
							goto l186
						}
						position++
					}
				l191:
					{
						position193, tokenIndex193 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l194
						}
						position++
						goto l193
					l194:
						position, tokenIndex = position193, tokenIndex193
						if buffer[position] != rune('E') {
							goto l186
						}
						position++
					}
				l193:
					goto l149
				l186:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l195
					}
					position++
					if buffer[position] != rune('8') {
						goto l195
					}
					position++
					{
						position196, tokenIndex196 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l197
						}
						position++
						goto l196
					l197:
						position, tokenIndex = position196, tokenIndex196
						if buffer[position] != rune('B') {
							goto l195
						}
						position++
					}
				l196:
					{
						position198, tokenIndex198 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l199
						}
						position++
						goto l198
					l199:
						position, tokenIndex = position198, tokenIndex198
						if buffer[position] != rune('Y') {
							goto l195
						}
						position++
					}
				l198:
					{
						position200, tokenIndex200 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l201
						}
						position++
						goto l200
					l201:
						position, tokenIndex = position200, tokenIndex200
						if buffer[position] != rune('T') {
							goto l195
						}
						position++
					}
				l200:
					{
						position202, tokenIndex202 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l203
						}
						position++
						goto l202
					l203:
						position, tokenIndex = position202, tokenIndex202
						if buffer[position] != rune('E') {
							goto l195
						}
						position++
					}
				l202:
					goto l149
				l195:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l204
					}
					position++
					if buffer[position] != rune('4') {
						goto l204
					}
					position++
					{
						position205, tokenIndex205 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l206
						}
						position++
						goto l205
					l206:
						position, tokenIndex = position205, tokenIndex205
						if buffer[position] != rune('B') {
							goto l204
						}
						position++
					}
				l205:
					{
						position207, tokenIndex207 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l208
						}
						position++
						goto l207
					l208:
						position, tokenIndex = position207, tokenIndex207
						if buffer[position] != rune('Y') {
							goto l204
						}
						position++
					}
				l207:
					{
						position209, tokenIndex209 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l210
						}
						position++
						goto l209
					l210:
						position, tokenIndex = position209, tokenIndex209
						if buffer[position] != rune('T') {
							goto l204
						}
						position++
					}
				l209:
					{
						position211, tokenIndex211 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l212
						}
						position++
						goto l211
					l212:
						position, tokenIndex = position211, tokenIndex211
						if buffer[position] != rune('E') {
							goto l204
						}
						position++
					}
				l211:
					goto l149
				l204:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l213
					}
					position++
					{
						position214, tokenIndex214 := position, tokenIndex
						if buffer[position] != rune('q') {
							goto l215
						}
						position++
						goto l214
					l215:
						position, tokenIndex = position214, tokenIndex214
						if buffer[position] != rune('Q') {
							goto l213
						}
						position++
					}
				l214:
					{
						position216, tokenIndex216 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l217
						}
						position++
						goto l216
					l217:
						position, tokenIndex = position216, tokenIndex216
						if buffer[position] != rune('U') {
							goto l213
						}
						position++
					}
				l216:
					{
						position218, tokenIndex218 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l219
						}
						position++
						goto l218
					l219:
						position, tokenIndex = position218, tokenIndex218
						if buffer[position] != rune('A') {
							goto l213
						}
						position++
					}
				l218:
					{
						position220, tokenIndex220 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l221
						}
						position++
						goto l220
					l221:
						position, tokenIndex = position220, tokenIndex220
						if buffer[position] != rune('D') {
							goto l213
						}
						position++
					}
				l220:
					goto l149
				l213:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l222
					}
					position++
					{
						position223, tokenIndex223 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l224
						}
						position++
						goto l223
					l224:
						position, tokenIndex = position223, tokenIndex223
						if buffer[position] != rune('T') {
							goto l222
						}
						position++
					}
				l223:
					{
						position225, tokenIndex225 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l226
						}
						position++
						goto l225
					l226:
						position, tokenIndex = position225, tokenIndex225
						if buffer[position] != rune('C') {
							goto l222
						}
						position++
					}
				l225:
					goto l149
				l222:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l227
					}
					position++
					{
						position228, tokenIndex228 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l229
						}
						position++
						goto l228
					l229:
						position, tokenIndex = position228, tokenIndex228
						if buffer[position] != rune('L') {
							goto l227
						}
						position++
					}
				l228:
					{
						position230, tokenIndex230 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l231
						}
						position++
						goto l230
					l231:
						position, tokenIndex = position230, tokenIndex230
						if buffer[position] != rune('O') {
							goto l227
						}
						position++
					}
				l230:
					{
						position232, tokenIndex232 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l233
						}
						position++
						goto l232
					l233:
						position, tokenIndex = position232, tokenIndex232
						if buffer[position] != rune('C') {
							goto l227
						}
						position++
					}
				l232:
					{
						position234, tokenIndex234 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l235
						}
						position++
						goto l234
					l235:
						position, tokenIndex = position234, tokenIndex234
						if buffer[position] != rune('A') {
							goto l227
						}
						position++
					}
				l234:
					{
						position236, tokenIndex236 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l237
						}
						position++
						goto l236
					l237:
						position, tokenIndex = position236, tokenIndex236
						if buffer[position] != rune('L') {
							goto l227
						}
						position++
					}
				l236:
					{
						position238, tokenIndex238 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l239
						}
						position++
						goto l238
					l239:
						position, tokenIndex = position238, tokenIndex238
						if buffer[position] != rune('E') {
							goto l227
						}
						position++
					}
				l238:
					{
						position240, tokenIndex240 := position, tokenIndex
						if buffer[position] != rune('n') {
							goto l241
						}
						position++
						goto l240
					l241:
						position, tokenIndex = position240, tokenIndex240
						if buffer[position] != rune('N') {
							goto l227
						}
						position++
					}
				l240:
					{
						position242, tokenIndex242 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l243
						}
						position++
						goto l242
					l243:
						position, tokenIndex = position242, tokenIndex242
						if buffer[position] != rune('T') {
							goto l227
						}
						position++
					}
				l242:
					{
						position244, tokenIndex244 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l245
						}
						position++
						goto l244
					l245:
						position, tokenIndex = position244, tokenIndex244
						if buffer[position] != rune('R') {
							goto l227
						}
						position++
					}
				l244:
					{
						position246, tokenIndex246 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l247
						}
						position++
						goto l246
					l247:
						position, tokenIndex = position246, tokenIndex246
						if buffer[position] != rune('Y') {
							goto l227
						}
						position++
					}
				l246:
					goto l149
				l227:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l248
					}
					position++
					{
						position249, tokenIndex249 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l250
						}
						position++
						goto l249
					l250:
						position, tokenIndex = position249, tokenIndex249
						if buffer[position] != rune('S') {
							goto l248
						}
						position++
					}
				l249:
					{
						position251, tokenIndex251 := position, tokenIndex
						if buffer[position] != rune('i') {
							goto l252
						}
						position++
						goto l251
					l252:
						position, tokenIndex = position251, tokenIndex251
						if buffer[position] != rune('I') {
							goto l248
						}
						position++
					}
				l251:
					{
						position253, tokenIndex253 := position, tokenIndex
						if buffer[position] != rune('z') {
							goto l254
						}
						position++
						goto l253
					l254:
						position, tokenIndex = position253, tokenIndex253
						if buffer[position] != rune('Z') {
							goto l248
						}
						position++
					}
				l253:
					{
						position255, tokenIndex255 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l256
						}
						position++
						goto l255
					l256:
						position, tokenIndex = position255, tokenIndex255
						if buffer[position] != rune('E') {
							goto l248
						}
						position++
					}
				l255:
					goto l149
				l248:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l257
					}
					position++
					{
						position258, tokenIndex258 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l259
						}
						position++
						goto l258
					l259:
						position, tokenIndex = position258, tokenIndex258
						if buffer[position] != rune('T') {
							goto l257
						}
						position++
					}
				l258:
					{
						position260, tokenIndex260 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l261
						}
						position++
						goto l260
					l261:
						position, tokenIndex = position260, tokenIndex260
						if buffer[position] != rune('Y') {
							goto l257
						}
						position++
					}
				l260:
					{
						position262, tokenIndex262 := position, tokenIndex
						if buffer[position] != rune('p') {
							goto l263
						}
						position++
						goto l262
					l263:
						position, tokenIndex = position262, tokenIndex262
						if buffer[position] != rune('P') {
							goto l257
						}
						position++
					}
				l262:
					{
						position264, tokenIndex264 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l265
						}
						position++
						goto l264
					l265:
						position, tokenIndex = position264, tokenIndex264
						if buffer[position] != rune('E') {
							goto l257
						}
						position++
					}
				l264:
					goto l149
				l257:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l266
					}
					position++
					{
						position267, tokenIndex267 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l268
						}
						position++
						goto l267
					l268:
						position, tokenIndex = position267, tokenIndex267
						if buffer[position] != rune('U') {
							goto l266
						}
						position++
					}
				l267:
					{
						position269, tokenIndex269 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l270
						}
						position++
						goto l269
					l270:
						position, tokenIndex = position269, tokenIndex269
						if buffer[position] != rune('L') {
							goto l266
						}
						position++
					}
				l269:
					{
						position271, tokenIndex271 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l272
						}
						position++
						goto l271
					l272:
						position, tokenIndex = position271, tokenIndex271
						if buffer[position] != rune('E') {
							goto l266
						}
						position++
					}
				l271:
					{
						position273, tokenIndex273 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l274
						}
						position++
						goto l273
					l274:
						position, tokenIndex = position273, tokenIndex273
						if buffer[position] != rune('B') {
							goto l266
						}
						position++
					}
				l273:
					if buffer[position] != rune('1') {
						goto l266
					}
					position++
					if buffer[position] != rune('2') {
						goto l266
					}
					position++
					if buffer[position] != rune('8') {
						goto l266
					}
					position++
					goto l149
				l266:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l147
					}
					position++
					{
						position275, tokenIndex275 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l276
						}
						position++
						goto l275
					l276:
						position, tokenIndex = position275, tokenIndex275
						if buffer[position] != rune('S') {
							goto l147
						}
						position++
					}
				l275:
					{
						position277, tokenIndex277 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l278
						}
						position++
						goto l277
					l278:
						position, tokenIndex = position277, tokenIndex277
						if buffer[position] != rune('L') {
							goto l147
						}
						position++
					}
				l277:
					{
						position279, tokenIndex279 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l280
						}
						position++
						goto l279
					l280:
						position, tokenIndex = position279, tokenIndex279
						if buffer[position] != rune('E') {
							goto l147
						}
						position++
					}
				l279:
					{
						position281, tokenIndex281 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l282
						}
						position++
						goto l281
					l282:
						position, tokenIndex = position281, tokenIndex281
						if buffer[position] != rune('B') {
							goto l147
						}
						position++
					}
				l281:
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
				add(ruleLabelContainingDirectiveName, position148)
			}
			return true
		l147:
			position, tokenIndex = position147, tokenIndex147
			return false
		},
		/* 14 SymbolArgs <- <('('? WS? SymbolArg WS? ')'? WS? SymbolShift? (WS? ',' WS? SymbolArg)*)> */
		func() bool {
			position283, tokenIndex283 := position, tokenIndex
			{
				position284 := position
				{
					position285, tokenIndex285 := position, tokenIndex
					if buffer[position] != rune('(') {
						goto l285
					}
					position++
					goto l286
				l285:
					position, tokenIndex = position285, tokenIndex285
				}
			l286:
				{
					position287, tokenIndex287 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l287
					}
					goto l288
				l287:
					position, tokenIndex = position287, tokenIndex287
				}
			l288:
				if !_rules[ruleSymbolArg]() {
					goto l283
				}
				{
					position289, tokenIndex289 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l289
					}
					goto l290
				l289:
					position, tokenIndex = position289, tokenIndex289
				}
			l290:
				{
					position291, tokenIndex291 := position, tokenIndex
					if buffer[position] != rune(')') {
						goto l291
					}
					position++
					goto l292
				l291:
					position, tokenIndex = position291, tokenIndex291
				}
			l292:
				{
					position293, tokenIndex293 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l293
					}
					goto l294
				l293:
					position, tokenIndex = position293, tokenIndex293
				}
			l294:
				{
					position295, tokenIndex295 := position, tokenIndex
					if !_rules[ruleSymbolShift]() {
						goto l295
					}
					goto l296
				l295:
					position, tokenIndex = position295, tokenIndex295
				}
			l296:
			l297:
				{
					position298, tokenIndex298 := position, tokenIndex
					{
						position299, tokenIndex299 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l299
						}
						goto l300
					l299:
						position, tokenIndex = position299, tokenIndex299
					}
				l300:
					if buffer[position] != rune(',') {
						goto l298
					}
					position++
					{
						position301, tokenIndex301 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l301
						}
						goto l302
					l301:
						position, tokenIndex = position301, tokenIndex301
					}
				l302:
					if !_rules[ruleSymbolArg]() {
						goto l298
					}
					goto l297
				l298:
					position, tokenIndex = position298, tokenIndex298
				}
				add(ruleSymbolArgs, position284)
			}
			return true
		l283:
			position, tokenIndex = position283, tokenIndex283
			return false
		},
		/* 15 SymbolShift <- <((('<' '<') / ('>' '>')) [0-9]+)> */
		func() bool {
			position303, tokenIndex303 := position, tokenIndex
			{
				position304 := position
				{
					position305, tokenIndex305 := position, tokenIndex
					if buffer[position] != rune('<') {
						goto l306
					}
					position++
					if buffer[position] != rune('<') {
						goto l306
					}
					position++
					goto l305
				l306:
					position, tokenIndex = position305, tokenIndex305
					if buffer[position] != rune('>') {
						goto l303
					}
					position++
					if buffer[position] != rune('>') {
						goto l303
					}
					position++
				}
			l305:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l303
				}
				position++
			l307:
				{
					position308, tokenIndex308 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l308
					}
					position++
					goto l307
				l308:
					position, tokenIndex = position308, tokenIndex308
				}
				add(ruleSymbolShift, position304)
			}
			return true
		l303:
			position, tokenIndex = position303, tokenIndex303
			return false
		},
		/* 16 SymbolArg <- <(Offset / SymbolType / ((Offset / LocalSymbol / SymbolName / Dot) WS? Operator WS? (Offset / LocalSymbol / SymbolName)) / (LocalSymbol TCMarker?) / (SymbolName Offset) / (SymbolName TCMarker?))> */
		func() bool {
			position309, tokenIndex309 := position, tokenIndex
			{
				position310 := position
				{
					position311, tokenIndex311 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l312
					}
					goto l311
				l312:
					position, tokenIndex = position311, tokenIndex311
					if !_rules[ruleSymbolType]() {
						goto l313
					}
					goto l311
				l313:
					position, tokenIndex = position311, tokenIndex311
					{
						position315, tokenIndex315 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l316
						}
						goto l315
					l316:
						position, tokenIndex = position315, tokenIndex315
						if !_rules[ruleLocalSymbol]() {
							goto l317
						}
						goto l315
					l317:
						position, tokenIndex = position315, tokenIndex315
						if !_rules[ruleSymbolName]() {
							goto l318
						}
						goto l315
					l318:
						position, tokenIndex = position315, tokenIndex315
						if !_rules[ruleDot]() {
							goto l314
						}
					}
				l315:
					{
						position319, tokenIndex319 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l319
						}
						goto l320
					l319:
						position, tokenIndex = position319, tokenIndex319
					}
				l320:
					if !_rules[ruleOperator]() {
						goto l314
					}
					{
						position321, tokenIndex321 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l321
						}
						goto l322
					l321:
						position, tokenIndex = position321, tokenIndex321
					}
				l322:
					{
						position323, tokenIndex323 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l324
						}
						goto l323
					l324:
						position, tokenIndex = position323, tokenIndex323
						if !_rules[ruleLocalSymbol]() {
							goto l325
						}
						goto l323
					l325:
						position, tokenIndex = position323, tokenIndex323
						if !_rules[ruleSymbolName]() {
							goto l314
						}
					}
				l323:
					goto l311
				l314:
					position, tokenIndex = position311, tokenIndex311
					if !_rules[ruleLocalSymbol]() {
						goto l326
					}
					{
						position327, tokenIndex327 := position, tokenIndex
						if !_rules[ruleTCMarker]() {
							goto l327
						}
						goto l328
					l327:
						position, tokenIndex = position327, tokenIndex327
					}
				l328:
					goto l311
				l326:
					position, tokenIndex = position311, tokenIndex311
					if !_rules[ruleSymbolName]() {
						goto l329
					}
					if !_rules[ruleOffset]() {
						goto l329
					}
					goto l311
				l329:
					position, tokenIndex = position311, tokenIndex311
					if !_rules[ruleSymbolName]() {
						goto l309
					}
					{
						position330, tokenIndex330 := position, tokenIndex
						if !_rules[ruleTCMarker]() {
							goto l330
						}
						goto l331
					l330:
						position, tokenIndex = position330, tokenIndex330
					}
				l331:
				}
			l311:
				add(ruleSymbolArg, position310)
			}
			return true
		l309:
			position, tokenIndex = position309, tokenIndex309
			return false
		},
		/* 17 SymbolType <- <(('@' / '%') (('f' 'u' 'n' 'c' 't' 'i' 'o' 'n') / ('o' 'b' 'j' 'e' 'c' 't')))> */
		func() bool {
			position332, tokenIndex332 := position, tokenIndex
			{
				position333 := position
				{
					position334, tokenIndex334 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l335
					}
					position++
					goto l334
				l335:
					position, tokenIndex = position334, tokenIndex334
					if buffer[position] != rune('%') {
						goto l332
					}
					position++
				}
			l334:
				{
					position336, tokenIndex336 := position, tokenIndex
					if buffer[position] != rune('f') {
						goto l337
					}
					position++
					if buffer[position] != rune('u') {
						goto l337
					}
					position++
					if buffer[position] != rune('n') {
						goto l337
					}
					position++
					if buffer[position] != rune('c') {
						goto l337
					}
					position++
					if buffer[position] != rune('t') {
						goto l337
					}
					position++
					if buffer[position] != rune('i') {
						goto l337
					}
					position++
					if buffer[position] != rune('o') {
						goto l337
					}
					position++
					if buffer[position] != rune('n') {
						goto l337
					}
					position++
					goto l336
				l337:
					position, tokenIndex = position336, tokenIndex336
					if buffer[position] != rune('o') {
						goto l332
					}
					position++
					if buffer[position] != rune('b') {
						goto l332
					}
					position++
					if buffer[position] != rune('j') {
						goto l332
					}
					position++
					if buffer[position] != rune('e') {
						goto l332
					}
					position++
					if buffer[position] != rune('c') {
						goto l332
					}
					position++
					if buffer[position] != rune('t') {
						goto l332
					}
					position++
				}
			l336:
				add(ruleSymbolType, position333)
			}
			return true
		l332:
			position, tokenIndex = position332, tokenIndex332
			return false
		},
		/* 18 Dot <- <'.'> */
		func() bool {
			position338, tokenIndex338 := position, tokenIndex
			{
				position339 := position
				if buffer[position] != rune('.') {
					goto l338
				}
				position++
				add(ruleDot, position339)
			}
			return true
		l338:
			position, tokenIndex = position338, tokenIndex338
			return false
		},
		/* 19 TCMarker <- <('[' 'T' 'C' ']')> */
		func() bool {
			position340, tokenIndex340 := position, tokenIndex
			{
				position341 := position
				if buffer[position] != rune('[') {
					goto l340
				}
				position++
				if buffer[position] != rune('T') {
					goto l340
				}
				position++
				if buffer[position] != rune('C') {
					goto l340
				}
				position++
				if buffer[position] != rune(']') {
					goto l340
				}
				position++
				add(ruleTCMarker, position341)
			}
			return true
		l340:
			position, tokenIndex = position340, tokenIndex340
			return false
		},
		/* 20 EscapedChar <- <('\\' .)> */
		func() bool {
			position342, tokenIndex342 := position, tokenIndex
			{
				position343 := position
				if buffer[position] != rune('\\') {
					goto l342
				}
				position++
				if !matchDot() {
					goto l342
				}
				add(ruleEscapedChar, position343)
			}
			return true
		l342:
			position, tokenIndex = position342, tokenIndex342
			return false
		},
		/* 21 WS <- <(' ' / '\t')+> */
		func() bool {
			position344, tokenIndex344 := position, tokenIndex
			{
				position345 := position
				{
					position348, tokenIndex348 := position, tokenIndex
					if buffer[position] != rune(' ') {
						goto l349
					}
					position++
					goto l348
				l349:
					position, tokenIndex = position348, tokenIndex348
					if buffer[position] != rune('\t') {
						goto l344
					}
					position++
				}
			l348:
			l346:
				{
					position347, tokenIndex347 := position, tokenIndex
					{
						position350, tokenIndex350 := position, tokenIndex
						if buffer[position] != rune(' ') {
							goto l351
						}
						position++
						goto l350
					l351:
						position, tokenIndex = position350, tokenIndex350
						if buffer[position] != rune('\t') {
							goto l347
						}
						position++
					}
				l350:
					goto l346
				l347:
					position, tokenIndex = position347, tokenIndex347
				}
				add(ruleWS, position345)
			}
			return true
		l344:
			position, tokenIndex = position344, tokenIndex344
			return false
		},
		/* 22 Comment <- <((('/' '/') / '#') (!'\n' .)*)> */
		func() bool {
			position352, tokenIndex352 := position, tokenIndex
			{
				position353 := position
				{
					position354, tokenIndex354 := position, tokenIndex
					if buffer[position] != rune('/') {
						goto l355
					}
					position++
					if buffer[position] != rune('/') {
						goto l355
					}
					position++
					goto l354
				l355:
					position, tokenIndex = position354, tokenIndex354
					if buffer[position] != rune('#') {
						goto l352
					}
					position++
				}
			l354:
			l356:
				{
					position357, tokenIndex357 := position, tokenIndex
					{
						position358, tokenIndex358 := position, tokenIndex
						if buffer[position] != rune('\n') {
							goto l358
						}
						position++
						goto l357
					l358:
						position, tokenIndex = position358, tokenIndex358
					}
					if !matchDot() {
						goto l357
					}
					goto l356
				l357:
					position, tokenIndex = position357, tokenIndex357
				}
				add(ruleComment, position353)
			}
			return true
		l352:
			position, tokenIndex = position352, tokenIndex352
			return false
		},
		/* 23 Label <- <((LocalSymbol / LocalLabel / SymbolName) ':')> */
		func() bool {
			position359, tokenIndex359 := position, tokenIndex
			{
				position360 := position
				{
					position361, tokenIndex361 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l362
					}
					goto l361
				l362:
					position, tokenIndex = position361, tokenIndex361
					if !_rules[ruleLocalLabel]() {
						goto l363
					}
					goto l361
				l363:
					position, tokenIndex = position361, tokenIndex361
					if !_rules[ruleSymbolName]() {
						goto l359
					}
				}
			l361:
				if buffer[position] != rune(':') {
					goto l359
				}
				position++
				add(ruleLabel, position360)
			}
			return true
		l359:
			position, tokenIndex = position359, tokenIndex359
			return false
		},
		/* 24 SymbolName <- <(([a-z] / [A-Z] / '.' / '_') ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')*)> */
		func() bool {
			position364, tokenIndex364 := position, tokenIndex
			{
				position365 := position
				{
					position366, tokenIndex366 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l367
					}
					position++
					goto l366
				l367:
					position, tokenIndex = position366, tokenIndex366
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l368
					}
					position++
					goto l366
				l368:
					position, tokenIndex = position366, tokenIndex366
					if buffer[position] != rune('.') {
						goto l369
					}
					position++
					goto l366
				l369:
					position, tokenIndex = position366, tokenIndex366
					if buffer[position] != rune('_') {
						goto l364
					}
					position++
				}
			l366:
			l370:
				{
					position371, tokenIndex371 := position, tokenIndex
					{
						position372, tokenIndex372 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l373
						}
						position++
						goto l372
					l373:
						position, tokenIndex = position372, tokenIndex372
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l374
						}
						position++
						goto l372
					l374:
						position, tokenIndex = position372, tokenIndex372
						if buffer[position] != rune('.') {
							goto l375
						}
						position++
						goto l372
					l375:
						position, tokenIndex = position372, tokenIndex372
						{
							position377, tokenIndex377 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l378
							}
							position++
							goto l377
						l378:
							position, tokenIndex = position377, tokenIndex377
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l376
							}
							position++
						}
					l377:
						goto l372
					l376:
						position, tokenIndex = position372, tokenIndex372
						if buffer[position] != rune('$') {
							goto l379
						}
						position++
						goto l372
					l379:
						position, tokenIndex = position372, tokenIndex372
						if buffer[position] != rune('_') {
							goto l371
						}
						position++
					}
				l372:
					goto l370
				l371:
					position, tokenIndex = position371, tokenIndex371
				}
				add(ruleSymbolName, position365)
			}
			return true
		l364:
			position, tokenIndex = position364, tokenIndex364
			return false
		},
		/* 25 LocalSymbol <- <('.' 'L' ([a-z] / [A-Z] / ([a-z] / [A-Z]) / '.' / ([0-9] / [0-9]) / '$' / '_')+)> */
		func() bool {
			position380, tokenIndex380 := position, tokenIndex
			{
				position381 := position
				if buffer[position] != rune('.') {
					goto l380
				}
				position++
				if buffer[position] != rune('L') {
					goto l380
				}
				position++
				{
					position384, tokenIndex384 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l385
					}
					position++
					goto l384
				l385:
					position, tokenIndex = position384, tokenIndex384
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l386
					}
					position++
					goto l384
				l386:
					position, tokenIndex = position384, tokenIndex384
					{
						position388, tokenIndex388 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l389
						}
						position++
						goto l388
					l389:
						position, tokenIndex = position388, tokenIndex388
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l387
						}
						position++
					}
				l388:
					goto l384
				l387:
					position, tokenIndex = position384, tokenIndex384
					if buffer[position] != rune('.') {
						goto l390
					}
					position++
					goto l384
				l390:
					position, tokenIndex = position384, tokenIndex384
					{
						position392, tokenIndex392 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l393
						}
						position++
						goto l392
					l393:
						position, tokenIndex = position392, tokenIndex392
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l391
						}
						position++
					}
				l392:
					goto l384
				l391:
					position, tokenIndex = position384, tokenIndex384
					if buffer[position] != rune('$') {
						goto l394
					}
					position++
					goto l384
				l394:
					position, tokenIndex = position384, tokenIndex384
					if buffer[position] != rune('_') {
						goto l380
					}
					position++
				}
			l384:
			l382:
				{
					position383, tokenIndex383 := position, tokenIndex
					{
						position395, tokenIndex395 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l396
						}
						position++
						goto l395
					l396:
						position, tokenIndex = position395, tokenIndex395
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l397
						}
						position++
						goto l395
					l397:
						position, tokenIndex = position395, tokenIndex395
						{
							position399, tokenIndex399 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l400
							}
							position++
							goto l399
						l400:
							position, tokenIndex = position399, tokenIndex399
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l398
							}
							position++
						}
					l399:
						goto l395
					l398:
						position, tokenIndex = position395, tokenIndex395
						if buffer[position] != rune('.') {
							goto l401
						}
						position++
						goto l395
					l401:
						position, tokenIndex = position395, tokenIndex395
						{
							position403, tokenIndex403 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l404
							}
							position++
							goto l403
						l404:
							position, tokenIndex = position403, tokenIndex403
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l402
							}
							position++
						}
					l403:
						goto l395
					l402:
						position, tokenIndex = position395, tokenIndex395
						if buffer[position] != rune('$') {
							goto l405
						}
						position++
						goto l395
					l405:
						position, tokenIndex = position395, tokenIndex395
						if buffer[position] != rune('_') {
							goto l383
						}
						position++
					}
				l395:
					goto l382
				l383:
					position, tokenIndex = position383, tokenIndex383
				}
				add(ruleLocalSymbol, position381)
			}
			return true
		l380:
			position, tokenIndex = position380, tokenIndex380
			return false
		},
		/* 26 LocalLabel <- <([0-9] ([0-9] / '$')*)> */
		func() bool {
			position406, tokenIndex406 := position, tokenIndex
			{
				position407 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l406
				}
				position++
			l408:
				{
					position409, tokenIndex409 := position, tokenIndex
					{
						position410, tokenIndex410 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l411
						}
						position++
						goto l410
					l411:
						position, tokenIndex = position410, tokenIndex410
						if buffer[position] != rune('$') {
							goto l409
						}
						position++
					}
				l410:
					goto l408
				l409:
					position, tokenIndex = position409, tokenIndex409
				}
				add(ruleLocalLabel, position407)
			}
			return true
		l406:
			position, tokenIndex = position406, tokenIndex406
			return false
		},
		/* 27 LocalLabelRef <- <([0-9] ([0-9] / '$')* ('b' / 'f'))> */
		func() bool {
			position412, tokenIndex412 := position, tokenIndex
			{
				position413 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l412
				}
				position++
			l414:
				{
					position415, tokenIndex415 := position, tokenIndex
					{
						position416, tokenIndex416 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l417
						}
						position++
						goto l416
					l417:
						position, tokenIndex = position416, tokenIndex416
						if buffer[position] != rune('$') {
							goto l415
						}
						position++
					}
				l416:
					goto l414
				l415:
					position, tokenIndex = position415, tokenIndex415
				}
				{
					position418, tokenIndex418 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l419
					}
					position++
					goto l418
				l419:
					position, tokenIndex = position418, tokenIndex418
					if buffer[position] != rune('f') {
						goto l412
					}
					position++
				}
			l418:
				add(ruleLocalLabelRef, position413)
			}
			return true
		l412:
			position, tokenIndex = position412, tokenIndex412
			return false
		},
		/* 28 Instruction <- <(InstructionName (WS InstructionArg (WS? ',' WS? InstructionArg)*)?)> */
		func() bool {
			position420, tokenIndex420 := position, tokenIndex
			{
				position421 := position
				if !_rules[ruleInstructionName]() {
					goto l420
				}
				{
					position422, tokenIndex422 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l422
					}
					if !_rules[ruleInstructionArg]() {
						goto l422
					}
				l424:
					{
						position425, tokenIndex425 := position, tokenIndex
						{
							position426, tokenIndex426 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l426
							}
							goto l427
						l426:
							position, tokenIndex = position426, tokenIndex426
						}
					l427:
						if buffer[position] != rune(',') {
							goto l425
						}
						position++
						{
							position428, tokenIndex428 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l428
							}
							goto l429
						l428:
							position, tokenIndex = position428, tokenIndex428
						}
					l429:
						if !_rules[ruleInstructionArg]() {
							goto l425
						}
						goto l424
					l425:
						position, tokenIndex = position425, tokenIndex425
					}
					goto l423
				l422:
					position, tokenIndex = position422, tokenIndex422
				}
			l423:
				add(ruleInstruction, position421)
			}
			return true
		l420:
			position, tokenIndex = position420, tokenIndex420
			return false
		},
		/* 29 InstructionName <- <(([a-z] / [A-Z]) ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]))* ('.' / '+' / '-')?)> */
		func() bool {
			position430, tokenIndex430 := position, tokenIndex
			{
				position431 := position
				{
					position432, tokenIndex432 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l433
					}
					position++
					goto l432
				l433:
					position, tokenIndex = position432, tokenIndex432
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l430
					}
					position++
				}
			l432:
			l434:
				{
					position435, tokenIndex435 := position, tokenIndex
					{
						position436, tokenIndex436 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l437
						}
						position++
						goto l436
					l437:
						position, tokenIndex = position436, tokenIndex436
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l438
						}
						position++
						goto l436
					l438:
						position, tokenIndex = position436, tokenIndex436
						if buffer[position] != rune('.') {
							goto l439
						}
						position++
						goto l436
					l439:
						position, tokenIndex = position436, tokenIndex436
						{
							position440, tokenIndex440 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l441
							}
							position++
							goto l440
						l441:
							position, tokenIndex = position440, tokenIndex440
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l435
							}
							position++
						}
					l440:
					}
				l436:
					goto l434
				l435:
					position, tokenIndex = position435, tokenIndex435
				}
				{
					position442, tokenIndex442 := position, tokenIndex
					{
						position444, tokenIndex444 := position, tokenIndex
						if buffer[position] != rune('.') {
							goto l445
						}
						position++
						goto l444
					l445:
						position, tokenIndex = position444, tokenIndex444
						if buffer[position] != rune('+') {
							goto l446
						}
						position++
						goto l444
					l446:
						position, tokenIndex = position444, tokenIndex444
						if buffer[position] != rune('-') {
							goto l442
						}
						position++
					}
				l444:
					goto l443
				l442:
					position, tokenIndex = position442, tokenIndex442
				}
			l443:
				add(ruleInstructionName, position431)
			}
			return true
		l430:
			position, tokenIndex = position430, tokenIndex430
			return false
		},
		/* 30 InstructionArg <- <(IndirectionIndicator? (ARMConstantTweak / RegisterOrConstant / LocalLabelRef / TOCRefHigh / TOCRefLow / GOTLocation / GOTSymbolOffset / MemoryRef) AVX512Token*)> */
		func() bool {
			position447, tokenIndex447 := position, tokenIndex
			{
				position448 := position
				{
					position449, tokenIndex449 := position, tokenIndex
					if !_rules[ruleIndirectionIndicator]() {
						goto l449
					}
					goto l450
				l449:
					position, tokenIndex = position449, tokenIndex449
				}
			l450:
				{
					position451, tokenIndex451 := position, tokenIndex
					if !_rules[ruleARMConstantTweak]() {
						goto l452
					}
					goto l451
				l452:
					position, tokenIndex = position451, tokenIndex451
					if !_rules[ruleRegisterOrConstant]() {
						goto l453
					}
					goto l451
				l453:
					position, tokenIndex = position451, tokenIndex451
					if !_rules[ruleLocalLabelRef]() {
						goto l454
					}
					goto l451
				l454:
					position, tokenIndex = position451, tokenIndex451
					if !_rules[ruleTOCRefHigh]() {
						goto l455
					}
					goto l451
				l455:
					position, tokenIndex = position451, tokenIndex451
					if !_rules[ruleTOCRefLow]() {
						goto l456
					}
					goto l451
				l456:
					position, tokenIndex = position451, tokenIndex451
					if !_rules[ruleGOTLocation]() {
						goto l457
					}
					goto l451
				l457:
					position, tokenIndex = position451, tokenIndex451
					if !_rules[ruleGOTSymbolOffset]() {
						goto l458
					}
					goto l451
				l458:
					position, tokenIndex = position451, tokenIndex451
					if !_rules[ruleMemoryRef]() {
						goto l447
					}
				}
			l451:
			l459:
				{
					position460, tokenIndex460 := position, tokenIndex
					if !_rules[ruleAVX512Token]() {
						goto l460
					}
					goto l459
				l460:
					position, tokenIndex = position460, tokenIndex460
				}
				add(ruleInstructionArg, position448)
			}
			return true
		l447:
			position, tokenIndex = position447, tokenIndex447
			return false
		},
		/* 31 GOTLocation <- <('$' '_' 'G' 'L' 'O' 'B' 'A' 'L' '_' 'O' 'F' 'F' 'S' 'E' 'T' '_' 'T' 'A' 'B' 'L' 'E' '_' '-' LocalSymbol)> */
		func() bool {
			position461, tokenIndex461 := position, tokenIndex
			{
				position462 := position
				if buffer[position] != rune('$') {
					goto l461
				}
				position++
				if buffer[position] != rune('_') {
					goto l461
				}
				position++
				if buffer[position] != rune('G') {
					goto l461
				}
				position++
				if buffer[position] != rune('L') {
					goto l461
				}
				position++
				if buffer[position] != rune('O') {
					goto l461
				}
				position++
				if buffer[position] != rune('B') {
					goto l461
				}
				position++
				if buffer[position] != rune('A') {
					goto l461
				}
				position++
				if buffer[position] != rune('L') {
					goto l461
				}
				position++
				if buffer[position] != rune('_') {
					goto l461
				}
				position++
				if buffer[position] != rune('O') {
					goto l461
				}
				position++
				if buffer[position] != rune('F') {
					goto l461
				}
				position++
				if buffer[position] != rune('F') {
					goto l461
				}
				position++
				if buffer[position] != rune('S') {
					goto l461
				}
				position++
				if buffer[position] != rune('E') {
					goto l461
				}
				position++
				if buffer[position] != rune('T') {
					goto l461
				}
				position++
				if buffer[position] != rune('_') {
					goto l461
				}
				position++
				if buffer[position] != rune('T') {
					goto l461
				}
				position++
				if buffer[position] != rune('A') {
					goto l461
				}
				position++
				if buffer[position] != rune('B') {
					goto l461
				}
				position++
				if buffer[position] != rune('L') {
					goto l461
				}
				position++
				if buffer[position] != rune('E') {
					goto l461
				}
				position++
				if buffer[position] != rune('_') {
					goto l461
				}
				position++
				if buffer[position] != rune('-') {
					goto l461
				}
				position++
				if !_rules[ruleLocalSymbol]() {
					goto l461
				}
				add(ruleGOTLocation, position462)
			}
			return true
		l461:
			position, tokenIndex = position461, tokenIndex461
			return false
		},
		/* 32 GOTSymbolOffset <- <(('$' SymbolName ('@' 'G' 'O' 'T') ('O' 'F' 'F')?) / (':' ('g' / 'G') ('o' / 'O') ('t' / 'T') ':' SymbolName))> */
		func() bool {
			position463, tokenIndex463 := position, tokenIndex
			{
				position464 := position
				{
					position465, tokenIndex465 := position, tokenIndex
					if buffer[position] != rune('$') {
						goto l466
					}
					position++
					if !_rules[ruleSymbolName]() {
						goto l466
					}
					if buffer[position] != rune('@') {
						goto l466
					}
					position++
					if buffer[position] != rune('G') {
						goto l466
					}
					position++
					if buffer[position] != rune('O') {
						goto l466
					}
					position++
					if buffer[position] != rune('T') {
						goto l466
					}
					position++
					{
						position467, tokenIndex467 := position, tokenIndex
						if buffer[position] != rune('O') {
							goto l467
						}
						position++
						if buffer[position] != rune('F') {
							goto l467
						}
						position++
						if buffer[position] != rune('F') {
							goto l467
						}
						position++
						goto l468
					l467:
						position, tokenIndex = position467, tokenIndex467
					}
				l468:
					goto l465
				l466:
					position, tokenIndex = position465, tokenIndex465
					if buffer[position] != rune(':') {
						goto l463
					}
					position++
					{
						position469, tokenIndex469 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l470
						}
						position++
						goto l469
					l470:
						position, tokenIndex = position469, tokenIndex469
						if buffer[position] != rune('G') {
							goto l463
						}
						position++
					}
				l469:
					{
						position471, tokenIndex471 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l472
						}
						position++
						goto l471
					l472:
						position, tokenIndex = position471, tokenIndex471
						if buffer[position] != rune('O') {
							goto l463
						}
						position++
					}
				l471:
					{
						position473, tokenIndex473 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l474
						}
						position++
						goto l473
					l474:
						position, tokenIndex = position473, tokenIndex473
						if buffer[position] != rune('T') {
							goto l463
						}
						position++
					}
				l473:
					if buffer[position] != rune(':') {
						goto l463
					}
					position++
					if !_rules[ruleSymbolName]() {
						goto l463
					}
				}
			l465:
				add(ruleGOTSymbolOffset, position464)
			}
			return true
		l463:
			position, tokenIndex = position463, tokenIndex463
			return false
		},
		/* 33 AVX512Token <- <(WS? '{' '%'? ([0-9] / [a-z])* '}')> */
		func() bool {
			position475, tokenIndex475 := position, tokenIndex
			{
				position476 := position
				{
					position477, tokenIndex477 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l477
					}
					goto l478
				l477:
					position, tokenIndex = position477, tokenIndex477
				}
			l478:
				if buffer[position] != rune('{') {
					goto l475
				}
				position++
				{
					position479, tokenIndex479 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l479
					}
					position++
					goto l480
				l479:
					position, tokenIndex = position479, tokenIndex479
				}
			l480:
			l481:
				{
					position482, tokenIndex482 := position, tokenIndex
					{
						position483, tokenIndex483 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l484
						}
						position++
						goto l483
					l484:
						position, tokenIndex = position483, tokenIndex483
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l482
						}
						position++
					}
				l483:
					goto l481
				l482:
					position, tokenIndex = position482, tokenIndex482
				}
				if buffer[position] != rune('}') {
					goto l475
				}
				position++
				add(ruleAVX512Token, position476)
			}
			return true
		l475:
			position, tokenIndex = position475, tokenIndex475
			return false
		},
		/* 34 TOCRefHigh <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' ([a-z] / [A-Z] / '_' / [0-9])+)) ('@' ('h' / 'H') ('a' / 'A')))> */
		func() bool {
			position485, tokenIndex485 := position, tokenIndex
			{
				position486 := position
				if buffer[position] != rune('.') {
					goto l485
				}
				position++
				if buffer[position] != rune('T') {
					goto l485
				}
				position++
				if buffer[position] != rune('O') {
					goto l485
				}
				position++
				if buffer[position] != rune('C') {
					goto l485
				}
				position++
				if buffer[position] != rune('.') {
					goto l485
				}
				position++
				if buffer[position] != rune('-') {
					goto l485
				}
				position++
				{
					position487, tokenIndex487 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l488
					}
					position++
					if buffer[position] != rune('b') {
						goto l488
					}
					position++
					goto l487
				l488:
					position, tokenIndex = position487, tokenIndex487
					if buffer[position] != rune('.') {
						goto l485
					}
					position++
					if buffer[position] != rune('L') {
						goto l485
					}
					position++
					{
						position491, tokenIndex491 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l492
						}
						position++
						goto l491
					l492:
						position, tokenIndex = position491, tokenIndex491
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l493
						}
						position++
						goto l491
					l493:
						position, tokenIndex = position491, tokenIndex491
						if buffer[position] != rune('_') {
							goto l494
						}
						position++
						goto l491
					l494:
						position, tokenIndex = position491, tokenIndex491
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l485
						}
						position++
					}
				l491:
				l489:
					{
						position490, tokenIndex490 := position, tokenIndex
						{
							position495, tokenIndex495 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l496
							}
							position++
							goto l495
						l496:
							position, tokenIndex = position495, tokenIndex495
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l497
							}
							position++
							goto l495
						l497:
							position, tokenIndex = position495, tokenIndex495
							if buffer[position] != rune('_') {
								goto l498
							}
							position++
							goto l495
						l498:
							position, tokenIndex = position495, tokenIndex495
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l490
							}
							position++
						}
					l495:
						goto l489
					l490:
						position, tokenIndex = position490, tokenIndex490
					}
				}
			l487:
				if buffer[position] != rune('@') {
					goto l485
				}
				position++
				{
					position499, tokenIndex499 := position, tokenIndex
					if buffer[position] != rune('h') {
						goto l500
					}
					position++
					goto l499
				l500:
					position, tokenIndex = position499, tokenIndex499
					if buffer[position] != rune('H') {
						goto l485
					}
					position++
				}
			l499:
				{
					position501, tokenIndex501 := position, tokenIndex
					if buffer[position] != rune('a') {
						goto l502
					}
					position++
					goto l501
				l502:
					position, tokenIndex = position501, tokenIndex501
					if buffer[position] != rune('A') {
						goto l485
					}
					position++
				}
			l501:
				add(ruleTOCRefHigh, position486)
			}
			return true
		l485:
			position, tokenIndex = position485, tokenIndex485
			return false
		},
		/* 35 TOCRefLow <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' ([a-z] / [A-Z] / '_' / [0-9])+)) ('@' ('l' / 'L')))> */
		func() bool {
			position503, tokenIndex503 := position, tokenIndex
			{
				position504 := position
				if buffer[position] != rune('.') {
					goto l503
				}
				position++
				if buffer[position] != rune('T') {
					goto l503
				}
				position++
				if buffer[position] != rune('O') {
					goto l503
				}
				position++
				if buffer[position] != rune('C') {
					goto l503
				}
				position++
				if buffer[position] != rune('.') {
					goto l503
				}
				position++
				if buffer[position] != rune('-') {
					goto l503
				}
				position++
				{
					position505, tokenIndex505 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l506
					}
					position++
					if buffer[position] != rune('b') {
						goto l506
					}
					position++
					goto l505
				l506:
					position, tokenIndex = position505, tokenIndex505
					if buffer[position] != rune('.') {
						goto l503
					}
					position++
					if buffer[position] != rune('L') {
						goto l503
					}
					position++
					{
						position509, tokenIndex509 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l510
						}
						position++
						goto l509
					l510:
						position, tokenIndex = position509, tokenIndex509
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l511
						}
						position++
						goto l509
					l511:
						position, tokenIndex = position509, tokenIndex509
						if buffer[position] != rune('_') {
							goto l512
						}
						position++
						goto l509
					l512:
						position, tokenIndex = position509, tokenIndex509
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l503
						}
						position++
					}
				l509:
				l507:
					{
						position508, tokenIndex508 := position, tokenIndex
						{
							position513, tokenIndex513 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l514
							}
							position++
							goto l513
						l514:
							position, tokenIndex = position513, tokenIndex513
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l515
							}
							position++
							goto l513
						l515:
							position, tokenIndex = position513, tokenIndex513
							if buffer[position] != rune('_') {
								goto l516
							}
							position++
							goto l513
						l516:
							position, tokenIndex = position513, tokenIndex513
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l508
							}
							position++
						}
					l513:
						goto l507
					l508:
						position, tokenIndex = position508, tokenIndex508
					}
				}
			l505:
				if buffer[position] != rune('@') {
					goto l503
				}
				position++
				{
					position517, tokenIndex517 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l518
					}
					position++
					goto l517
				l518:
					position, tokenIndex = position517, tokenIndex517
					if buffer[position] != rune('L') {
						goto l503
					}
					position++
				}
			l517:
				add(ruleTOCRefLow, position504)
			}
			return true
		l503:
			position, tokenIndex = position503, tokenIndex503
			return false
		},
		/* 36 IndirectionIndicator <- <'*'> */
		func() bool {
			position519, tokenIndex519 := position, tokenIndex
			{
				position520 := position
				if buffer[position] != rune('*') {
					goto l519
				}
				position++
				add(ruleIndirectionIndicator, position520)
			}
			return true
		l519:
			position, tokenIndex = position519, tokenIndex519
			return false
		},
		/* 37 RegisterOrConstant <- <((('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))*) / ('$'? ((Offset Offset) / Offset)) / ('#' Offset ('*' [0-9]+ ('-' [0-9] [0-9]*)?)?) / ('#' '~'? '(' [0-9] WS? ('<' '<') WS? [0-9] ')') / ARMRegister) !('f' / 'b' / ':' / '(' / '+' / '-'))> */
		func() bool {
			position521, tokenIndex521 := position, tokenIndex
			{
				position522 := position
				{
					position523, tokenIndex523 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l524
					}
					position++
					{
						position525, tokenIndex525 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l526
						}
						position++
						goto l525
					l526:
						position, tokenIndex = position525, tokenIndex525
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l524
						}
						position++
					}
				l525:
				l527:
					{
						position528, tokenIndex528 := position, tokenIndex
						{
							position529, tokenIndex529 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l530
							}
							position++
							goto l529
						l530:
							position, tokenIndex = position529, tokenIndex529
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l531
							}
							position++
							goto l529
						l531:
							position, tokenIndex = position529, tokenIndex529
							{
								position532, tokenIndex532 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l533
								}
								position++
								goto l532
							l533:
								position, tokenIndex = position532, tokenIndex532
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l528
								}
								position++
							}
						l532:
						}
					l529:
						goto l527
					l528:
						position, tokenIndex = position528, tokenIndex528
					}
					goto l523
				l524:
					position, tokenIndex = position523, tokenIndex523
					{
						position535, tokenIndex535 := position, tokenIndex
						if buffer[position] != rune('$') {
							goto l535
						}
						position++
						goto l536
					l535:
						position, tokenIndex = position535, tokenIndex535
					}
				l536:
					{
						position537, tokenIndex537 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l538
						}
						if !_rules[ruleOffset]() {
							goto l538
						}
						goto l537
					l538:
						position, tokenIndex = position537, tokenIndex537
						if !_rules[ruleOffset]() {
							goto l534
						}
					}
				l537:
					goto l523
				l534:
					position, tokenIndex = position523, tokenIndex523
					if buffer[position] != rune('#') {
						goto l539
					}
					position++
					if !_rules[ruleOffset]() {
						goto l539
					}
					{
						position540, tokenIndex540 := position, tokenIndex
						if buffer[position] != rune('*') {
							goto l540
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l540
						}
						position++
					l542:
						{
							position543, tokenIndex543 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l543
							}
							position++
							goto l542
						l543:
							position, tokenIndex = position543, tokenIndex543
						}
						{
							position544, tokenIndex544 := position, tokenIndex
							if buffer[position] != rune('-') {
								goto l544
							}
							position++
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l544
							}
							position++
						l546:
							{
								position547, tokenIndex547 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l547
								}
								position++
								goto l546
							l547:
								position, tokenIndex = position547, tokenIndex547
							}
							goto l545
						l544:
							position, tokenIndex = position544, tokenIndex544
						}
					l545:
						goto l541
					l540:
						position, tokenIndex = position540, tokenIndex540
					}
				l541:
					goto l523
				l539:
					position, tokenIndex = position523, tokenIndex523
					if buffer[position] != rune('#') {
						goto l548
					}
					position++
					{
						position549, tokenIndex549 := position, tokenIndex
						if buffer[position] != rune('~') {
							goto l549
						}
						position++
						goto l550
					l549:
						position, tokenIndex = position549, tokenIndex549
					}
				l550:
					if buffer[position] != rune('(') {
						goto l548
					}
					position++
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l548
					}
					position++
					{
						position551, tokenIndex551 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l551
						}
						goto l552
					l551:
						position, tokenIndex = position551, tokenIndex551
					}
				l552:
					if buffer[position] != rune('<') {
						goto l548
					}
					position++
					if buffer[position] != rune('<') {
						goto l548
					}
					position++
					{
						position553, tokenIndex553 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l553
						}
						goto l554
					l553:
						position, tokenIndex = position553, tokenIndex553
					}
				l554:
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l548
					}
					position++
					if buffer[position] != rune(')') {
						goto l548
					}
					position++
					goto l523
				l548:
					position, tokenIndex = position523, tokenIndex523
					if !_rules[ruleARMRegister]() {
						goto l521
					}
				}
			l523:
				{
					position555, tokenIndex555 := position, tokenIndex
					{
						position556, tokenIndex556 := position, tokenIndex
						if buffer[position] != rune('f') {
							goto l557
						}
						position++
						goto l556
					l557:
						position, tokenIndex = position556, tokenIndex556
						if buffer[position] != rune('b') {
							goto l558
						}
						position++
						goto l556
					l558:
						position, tokenIndex = position556, tokenIndex556
						if buffer[position] != rune(':') {
							goto l559
						}
						position++
						goto l556
					l559:
						position, tokenIndex = position556, tokenIndex556
						if buffer[position] != rune('(') {
							goto l560
						}
						position++
						goto l556
					l560:
						position, tokenIndex = position556, tokenIndex556
						if buffer[position] != rune('+') {
							goto l561
						}
						position++
						goto l556
					l561:
						position, tokenIndex = position556, tokenIndex556
						if buffer[position] != rune('-') {
							goto l555
						}
						position++
					}
				l556:
					goto l521
				l555:
					position, tokenIndex = position555, tokenIndex555
				}
				add(ruleRegisterOrConstant, position522)
			}
			return true
		l521:
			position, tokenIndex = position521, tokenIndex521
			return false
		},
		/* 38 ARMConstantTweak <- <(((('l' / 'L') ('s' / 'S') ('l' / 'L')) / (('s' / 'S') ('x' / 'X') ('t' / 'T') ('w' / 'W')) / (('u' / 'U') ('x' / 'X') ('t' / 'T') ('w' / 'W')) / (('u' / 'U') ('x' / 'X') ('t' / 'T') ('b' / 'B')) / (('l' / 'L') ('s' / 'S') ('r' / 'R')) / (('r' / 'R') ('o' / 'O') ('r' / 'R')) / (('a' / 'A') ('s' / 'S') ('r' / 'R'))) (WS '#' Offset)?)> */
		func() bool {
			position562, tokenIndex562 := position, tokenIndex
			{
				position563 := position
				{
					position564, tokenIndex564 := position, tokenIndex
					{
						position566, tokenIndex566 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l567
						}
						position++
						goto l566
					l567:
						position, tokenIndex = position566, tokenIndex566
						if buffer[position] != rune('L') {
							goto l565
						}
						position++
					}
				l566:
					{
						position568, tokenIndex568 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l569
						}
						position++
						goto l568
					l569:
						position, tokenIndex = position568, tokenIndex568
						if buffer[position] != rune('S') {
							goto l565
						}
						position++
					}
				l568:
					{
						position570, tokenIndex570 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l571
						}
						position++
						goto l570
					l571:
						position, tokenIndex = position570, tokenIndex570
						if buffer[position] != rune('L') {
							goto l565
						}
						position++
					}
				l570:
					goto l564
				l565:
					position, tokenIndex = position564, tokenIndex564
					{
						position573, tokenIndex573 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l574
						}
						position++
						goto l573
					l574:
						position, tokenIndex = position573, tokenIndex573
						if buffer[position] != rune('S') {
							goto l572
						}
						position++
					}
				l573:
					{
						position575, tokenIndex575 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l576
						}
						position++
						goto l575
					l576:
						position, tokenIndex = position575, tokenIndex575
						if buffer[position] != rune('X') {
							goto l572
						}
						position++
					}
				l575:
					{
						position577, tokenIndex577 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l578
						}
						position++
						goto l577
					l578:
						position, tokenIndex = position577, tokenIndex577
						if buffer[position] != rune('T') {
							goto l572
						}
						position++
					}
				l577:
					{
						position579, tokenIndex579 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l580
						}
						position++
						goto l579
					l580:
						position, tokenIndex = position579, tokenIndex579
						if buffer[position] != rune('W') {
							goto l572
						}
						position++
					}
				l579:
					goto l564
				l572:
					position, tokenIndex = position564, tokenIndex564
					{
						position582, tokenIndex582 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l583
						}
						position++
						goto l582
					l583:
						position, tokenIndex = position582, tokenIndex582
						if buffer[position] != rune('U') {
							goto l581
						}
						position++
					}
				l582:
					{
						position584, tokenIndex584 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l585
						}
						position++
						goto l584
					l585:
						position, tokenIndex = position584, tokenIndex584
						if buffer[position] != rune('X') {
							goto l581
						}
						position++
					}
				l584:
					{
						position586, tokenIndex586 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l587
						}
						position++
						goto l586
					l587:
						position, tokenIndex = position586, tokenIndex586
						if buffer[position] != rune('T') {
							goto l581
						}
						position++
					}
				l586:
					{
						position588, tokenIndex588 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l589
						}
						position++
						goto l588
					l589:
						position, tokenIndex = position588, tokenIndex588
						if buffer[position] != rune('W') {
							goto l581
						}
						position++
					}
				l588:
					goto l564
				l581:
					position, tokenIndex = position564, tokenIndex564
					{
						position591, tokenIndex591 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l592
						}
						position++
						goto l591
					l592:
						position, tokenIndex = position591, tokenIndex591
						if buffer[position] != rune('U') {
							goto l590
						}
						position++
					}
				l591:
					{
						position593, tokenIndex593 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l594
						}
						position++
						goto l593
					l594:
						position, tokenIndex = position593, tokenIndex593
						if buffer[position] != rune('X') {
							goto l590
						}
						position++
					}
				l593:
					{
						position595, tokenIndex595 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l596
						}
						position++
						goto l595
					l596:
						position, tokenIndex = position595, tokenIndex595
						if buffer[position] != rune('T') {
							goto l590
						}
						position++
					}
				l595:
					{
						position597, tokenIndex597 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l598
						}
						position++
						goto l597
					l598:
						position, tokenIndex = position597, tokenIndex597
						if buffer[position] != rune('B') {
							goto l590
						}
						position++
					}
				l597:
					goto l564
				l590:
					position, tokenIndex = position564, tokenIndex564
					{
						position600, tokenIndex600 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l601
						}
						position++
						goto l600
					l601:
						position, tokenIndex = position600, tokenIndex600
						if buffer[position] != rune('L') {
							goto l599
						}
						position++
					}
				l600:
					{
						position602, tokenIndex602 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l603
						}
						position++
						goto l602
					l603:
						position, tokenIndex = position602, tokenIndex602
						if buffer[position] != rune('S') {
							goto l599
						}
						position++
					}
				l602:
					{
						position604, tokenIndex604 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l605
						}
						position++
						goto l604
					l605:
						position, tokenIndex = position604, tokenIndex604
						if buffer[position] != rune('R') {
							goto l599
						}
						position++
					}
				l604:
					goto l564
				l599:
					position, tokenIndex = position564, tokenIndex564
					{
						position607, tokenIndex607 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l608
						}
						position++
						goto l607
					l608:
						position, tokenIndex = position607, tokenIndex607
						if buffer[position] != rune('R') {
							goto l606
						}
						position++
					}
				l607:
					{
						position609, tokenIndex609 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l610
						}
						position++
						goto l609
					l610:
						position, tokenIndex = position609, tokenIndex609
						if buffer[position] != rune('O') {
							goto l606
						}
						position++
					}
				l609:
					{
						position611, tokenIndex611 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l612
						}
						position++
						goto l611
					l612:
						position, tokenIndex = position611, tokenIndex611
						if buffer[position] != rune('R') {
							goto l606
						}
						position++
					}
				l611:
					goto l564
				l606:
					position, tokenIndex = position564, tokenIndex564
					{
						position613, tokenIndex613 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l614
						}
						position++
						goto l613
					l614:
						position, tokenIndex = position613, tokenIndex613
						if buffer[position] != rune('A') {
							goto l562
						}
						position++
					}
				l613:
					{
						position615, tokenIndex615 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l616
						}
						position++
						goto l615
					l616:
						position, tokenIndex = position615, tokenIndex615
						if buffer[position] != rune('S') {
							goto l562
						}
						position++
					}
				l615:
					{
						position617, tokenIndex617 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l618
						}
						position++
						goto l617
					l618:
						position, tokenIndex = position617, tokenIndex617
						if buffer[position] != rune('R') {
							goto l562
						}
						position++
					}
				l617:
				}
			l564:
				{
					position619, tokenIndex619 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l619
					}
					if buffer[position] != rune('#') {
						goto l619
					}
					position++
					if !_rules[ruleOffset]() {
						goto l619
					}
					goto l620
				l619:
					position, tokenIndex = position619, tokenIndex619
				}
			l620:
				add(ruleARMConstantTweak, position563)
			}
			return true
		l562:
			position, tokenIndex = position562, tokenIndex562
			return false
		},
		/* 39 ARMRegister <- <((('s' / 'S') ('p' / 'P')) / (('x' / 'w' / 'd' / 'q' / 's') [0-9] [0-9]?) / (('x' / 'X') ('z' / 'Z') ('r' / 'R')) / (('w' / 'W') ('z' / 'Z') ('r' / 'R')) / ARMVectorRegister / ('{' WS? ARMVectorRegister (',' WS? ARMVectorRegister)* WS? '}' ('[' [0-9] [0-9]? ']')?))> */
		func() bool {
			position621, tokenIndex621 := position, tokenIndex
			{
				position622 := position
				{
					position623, tokenIndex623 := position, tokenIndex
					{
						position625, tokenIndex625 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l626
						}
						position++
						goto l625
					l626:
						position, tokenIndex = position625, tokenIndex625
						if buffer[position] != rune('S') {
							goto l624
						}
						position++
					}
				l625:
					{
						position627, tokenIndex627 := position, tokenIndex
						if buffer[position] != rune('p') {
							goto l628
						}
						position++
						goto l627
					l628:
						position, tokenIndex = position627, tokenIndex627
						if buffer[position] != rune('P') {
							goto l624
						}
						position++
					}
				l627:
					goto l623
				l624:
					position, tokenIndex = position623, tokenIndex623
					{
						position630, tokenIndex630 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l631
						}
						position++
						goto l630
					l631:
						position, tokenIndex = position630, tokenIndex630
						if buffer[position] != rune('w') {
							goto l632
						}
						position++
						goto l630
					l632:
						position, tokenIndex = position630, tokenIndex630
						if buffer[position] != rune('d') {
							goto l633
						}
						position++
						goto l630
					l633:
						position, tokenIndex = position630, tokenIndex630
						if buffer[position] != rune('q') {
							goto l634
						}
						position++
						goto l630
					l634:
						position, tokenIndex = position630, tokenIndex630
						if buffer[position] != rune('s') {
							goto l629
						}
						position++
					}
				l630:
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l629
					}
					position++
					{
						position635, tokenIndex635 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l635
						}
						position++
						goto l636
					l635:
						position, tokenIndex = position635, tokenIndex635
					}
				l636:
					goto l623
				l629:
					position, tokenIndex = position623, tokenIndex623
					{
						position638, tokenIndex638 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l639
						}
						position++
						goto l638
					l639:
						position, tokenIndex = position638, tokenIndex638
						if buffer[position] != rune('X') {
							goto l637
						}
						position++
					}
				l638:
					{
						position640, tokenIndex640 := position, tokenIndex
						if buffer[position] != rune('z') {
							goto l641
						}
						position++
						goto l640
					l641:
						position, tokenIndex = position640, tokenIndex640
						if buffer[position] != rune('Z') {
							goto l637
						}
						position++
					}
				l640:
					{
						position642, tokenIndex642 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l643
						}
						position++
						goto l642
					l643:
						position, tokenIndex = position642, tokenIndex642
						if buffer[position] != rune('R') {
							goto l637
						}
						position++
					}
				l642:
					goto l623
				l637:
					position, tokenIndex = position623, tokenIndex623
					{
						position645, tokenIndex645 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l646
						}
						position++
						goto l645
					l646:
						position, tokenIndex = position645, tokenIndex645
						if buffer[position] != rune('W') {
							goto l644
						}
						position++
					}
				l645:
					{
						position647, tokenIndex647 := position, tokenIndex
						if buffer[position] != rune('z') {
							goto l648
						}
						position++
						goto l647
					l648:
						position, tokenIndex = position647, tokenIndex647
						if buffer[position] != rune('Z') {
							goto l644
						}
						position++
					}
				l647:
					{
						position649, tokenIndex649 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l650
						}
						position++
						goto l649
					l650:
						position, tokenIndex = position649, tokenIndex649
						if buffer[position] != rune('R') {
							goto l644
						}
						position++
					}
				l649:
					goto l623
				l644:
					position, tokenIndex = position623, tokenIndex623
					if !_rules[ruleARMVectorRegister]() {
						goto l651
					}
					goto l623
				l651:
					position, tokenIndex = position623, tokenIndex623
					if buffer[position] != rune('{') {
						goto l621
					}
					position++
					{
						position652, tokenIndex652 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l652
						}
						goto l653
					l652:
						position, tokenIndex = position652, tokenIndex652
					}
				l653:
					if !_rules[ruleARMVectorRegister]() {
						goto l621
					}
				l654:
					{
						position655, tokenIndex655 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l655
						}
						position++
						{
							position656, tokenIndex656 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l656
							}
							goto l657
						l656:
							position, tokenIndex = position656, tokenIndex656
						}
					l657:
						if !_rules[ruleARMVectorRegister]() {
							goto l655
						}
						goto l654
					l655:
						position, tokenIndex = position655, tokenIndex655
					}
					{
						position658, tokenIndex658 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l658
						}
						goto l659
					l658:
						position, tokenIndex = position658, tokenIndex658
					}
				l659:
					if buffer[position] != rune('}') {
						goto l621
					}
					position++
					{
						position660, tokenIndex660 := position, tokenIndex
						if buffer[position] != rune('[') {
							goto l660
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l660
						}
						position++
						{
							position662, tokenIndex662 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l662
							}
							position++
							goto l663
						l662:
							position, tokenIndex = position662, tokenIndex662
						}
					l663:
						if buffer[position] != rune(']') {
							goto l660
						}
						position++
						goto l661
					l660:
						position, tokenIndex = position660, tokenIndex660
					}
				l661:
				}
			l623:
				add(ruleARMRegister, position622)
			}
			return true
		l621:
			position, tokenIndex = position621, tokenIndex621
			return false
		},
		/* 40 ARMVectorRegister <- <(('v' / 'V') [0-9] [0-9]? ('.' [0-9]* ('b' / 's' / 'd' / 'h' / 'q') ('[' [0-9] [0-9]? ']')?)?)> */
		func() bool {
			position664, tokenIndex664 := position, tokenIndex
			{
				position665 := position
				{
					position666, tokenIndex666 := position, tokenIndex
					if buffer[position] != rune('v') {
						goto l667
					}
					position++
					goto l666
				l667:
					position, tokenIndex = position666, tokenIndex666
					if buffer[position] != rune('V') {
						goto l664
					}
					position++
				}
			l666:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l664
				}
				position++
				{
					position668, tokenIndex668 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l668
					}
					position++
					goto l669
				l668:
					position, tokenIndex = position668, tokenIndex668
				}
			l669:
				{
					position670, tokenIndex670 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l670
					}
					position++
				l672:
					{
						position673, tokenIndex673 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l673
						}
						position++
						goto l672
					l673:
						position, tokenIndex = position673, tokenIndex673
					}
					{
						position674, tokenIndex674 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l675
						}
						position++
						goto l674
					l675:
						position, tokenIndex = position674, tokenIndex674
						if buffer[position] != rune('s') {
							goto l676
						}
						position++
						goto l674
					l676:
						position, tokenIndex = position674, tokenIndex674
						if buffer[position] != rune('d') {
							goto l677
						}
						position++
						goto l674
					l677:
						position, tokenIndex = position674, tokenIndex674
						if buffer[position] != rune('h') {
							goto l678
						}
						position++
						goto l674
					l678:
						position, tokenIndex = position674, tokenIndex674
						if buffer[position] != rune('q') {
							goto l670
						}
						position++
					}
				l674:
					{
						position679, tokenIndex679 := position, tokenIndex
						if buffer[position] != rune('[') {
							goto l679
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l679
						}
						position++
						{
							position681, tokenIndex681 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l681
							}
							position++
							goto l682
						l681:
							position, tokenIndex = position681, tokenIndex681
						}
					l682:
						if buffer[position] != rune(']') {
							goto l679
						}
						position++
						goto l680
					l679:
						position, tokenIndex = position679, tokenIndex679
					}
				l680:
					goto l671
				l670:
					position, tokenIndex = position670, tokenIndex670
				}
			l671:
				add(ruleARMVectorRegister, position665)
			}
			return true
		l664:
			position, tokenIndex = position664, tokenIndex664
			return false
		},
		/* 41 MemoryRef <- <((SymbolRef BaseIndexScale) / SymbolRef / Low12BitsSymbolRef / (Offset* BaseIndexScale) / (SegmentRegister Offset BaseIndexScale) / (SegmentRegister BaseIndexScale) / (SegmentRegister Offset) / ARMBaseIndexScale / BaseIndexScale)> */
		func() bool {
			position683, tokenIndex683 := position, tokenIndex
			{
				position684 := position
				{
					position685, tokenIndex685 := position, tokenIndex
					if !_rules[ruleSymbolRef]() {
						goto l686
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l686
					}
					goto l685
				l686:
					position, tokenIndex = position685, tokenIndex685
					if !_rules[ruleSymbolRef]() {
						goto l687
					}
					goto l685
				l687:
					position, tokenIndex = position685, tokenIndex685
					if !_rules[ruleLow12BitsSymbolRef]() {
						goto l688
					}
					goto l685
				l688:
					position, tokenIndex = position685, tokenIndex685
				l690:
					{
						position691, tokenIndex691 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l691
						}
						goto l690
					l691:
						position, tokenIndex = position691, tokenIndex691
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l689
					}
					goto l685
				l689:
					position, tokenIndex = position685, tokenIndex685
					if !_rules[ruleSegmentRegister]() {
						goto l692
					}
					if !_rules[ruleOffset]() {
						goto l692
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l692
					}
					goto l685
				l692:
					position, tokenIndex = position685, tokenIndex685
					if !_rules[ruleSegmentRegister]() {
						goto l693
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l693
					}
					goto l685
				l693:
					position, tokenIndex = position685, tokenIndex685
					if !_rules[ruleSegmentRegister]() {
						goto l694
					}
					if !_rules[ruleOffset]() {
						goto l694
					}
					goto l685
				l694:
					position, tokenIndex = position685, tokenIndex685
					if !_rules[ruleARMBaseIndexScale]() {
						goto l695
					}
					goto l685
				l695:
					position, tokenIndex = position685, tokenIndex685
					if !_rules[ruleBaseIndexScale]() {
						goto l683
					}
				}
			l685:
				add(ruleMemoryRef, position684)
			}
			return true
		l683:
			position, tokenIndex = position683, tokenIndex683
			return false
		},
		/* 42 SymbolRef <- <((Offset* '+')? (LocalSymbol / SymbolName) Offset* ('@' Section Offset*)?)> */
		func() bool {
			position696, tokenIndex696 := position, tokenIndex
			{
				position697 := position
				{
					position698, tokenIndex698 := position, tokenIndex
				l700:
					{
						position701, tokenIndex701 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l701
						}
						goto l700
					l701:
						position, tokenIndex = position701, tokenIndex701
					}
					if buffer[position] != rune('+') {
						goto l698
					}
					position++
					goto l699
				l698:
					position, tokenIndex = position698, tokenIndex698
				}
			l699:
				{
					position702, tokenIndex702 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l703
					}
					goto l702
				l703:
					position, tokenIndex = position702, tokenIndex702
					if !_rules[ruleSymbolName]() {
						goto l696
					}
				}
			l702:
			l704:
				{
					position705, tokenIndex705 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l705
					}
					goto l704
				l705:
					position, tokenIndex = position705, tokenIndex705
				}
				{
					position706, tokenIndex706 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l706
					}
					position++
					if !_rules[ruleSection]() {
						goto l706
					}
				l708:
					{
						position709, tokenIndex709 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l709
						}
						goto l708
					l709:
						position, tokenIndex = position709, tokenIndex709
					}
					goto l707
				l706:
					position, tokenIndex = position706, tokenIndex706
				}
			l707:
				add(ruleSymbolRef, position697)
			}
			return true
		l696:
			position, tokenIndex = position696, tokenIndex696
			return false
		},
		/* 43 Low12BitsSymbolRef <- <(':' ('l' / 'L') ('o' / 'O') '1' '2' ':' (LocalSymbol / SymbolName) Offset?)> */
		func() bool {
			position710, tokenIndex710 := position, tokenIndex
			{
				position711 := position
				if buffer[position] != rune(':') {
					goto l710
				}
				position++
				{
					position712, tokenIndex712 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l713
					}
					position++
					goto l712
				l713:
					position, tokenIndex = position712, tokenIndex712
					if buffer[position] != rune('L') {
						goto l710
					}
					position++
				}
			l712:
				{
					position714, tokenIndex714 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l715
					}
					position++
					goto l714
				l715:
					position, tokenIndex = position714, tokenIndex714
					if buffer[position] != rune('O') {
						goto l710
					}
					position++
				}
			l714:
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
				{
					position716, tokenIndex716 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l717
					}
					goto l716
				l717:
					position, tokenIndex = position716, tokenIndex716
					if !_rules[ruleSymbolName]() {
						goto l710
					}
				}
			l716:
				{
					position718, tokenIndex718 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l718
					}
					goto l719
				l718:
					position, tokenIndex = position718, tokenIndex718
				}
			l719:
				add(ruleLow12BitsSymbolRef, position711)
			}
			return true
		l710:
			position, tokenIndex = position710, tokenIndex710
			return false
		},
		/* 44 ARMBaseIndexScale <- <('[' ARMRegister (',' WS? (('#' Offset ('*' [0-9]+)?) / ARMGOTLow12 / Low12BitsSymbolRef / ARMRegister) (',' WS? ARMConstantTweak)?)? ']' ARMPostincrement?)> */
		func() bool {
			position720, tokenIndex720 := position, tokenIndex
			{
				position721 := position
				if buffer[position] != rune('[') {
					goto l720
				}
				position++
				if !_rules[ruleARMRegister]() {
					goto l720
				}
				{
					position722, tokenIndex722 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l722
					}
					position++
					{
						position724, tokenIndex724 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l724
						}
						goto l725
					l724:
						position, tokenIndex = position724, tokenIndex724
					}
				l725:
					{
						position726, tokenIndex726 := position, tokenIndex
						if buffer[position] != rune('#') {
							goto l727
						}
						position++
						if !_rules[ruleOffset]() {
							goto l727
						}
						{
							position728, tokenIndex728 := position, tokenIndex
							if buffer[position] != rune('*') {
								goto l728
							}
							position++
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l728
							}
							position++
						l730:
							{
								position731, tokenIndex731 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l731
								}
								position++
								goto l730
							l731:
								position, tokenIndex = position731, tokenIndex731
							}
							goto l729
						l728:
							position, tokenIndex = position728, tokenIndex728
						}
					l729:
						goto l726
					l727:
						position, tokenIndex = position726, tokenIndex726
						if !_rules[ruleARMGOTLow12]() {
							goto l732
						}
						goto l726
					l732:
						position, tokenIndex = position726, tokenIndex726
						if !_rules[ruleLow12BitsSymbolRef]() {
							goto l733
						}
						goto l726
					l733:
						position, tokenIndex = position726, tokenIndex726
						if !_rules[ruleARMRegister]() {
							goto l722
						}
					}
				l726:
					{
						position734, tokenIndex734 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l734
						}
						position++
						{
							position736, tokenIndex736 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l736
							}
							goto l737
						l736:
							position, tokenIndex = position736, tokenIndex736
						}
					l737:
						if !_rules[ruleARMConstantTweak]() {
							goto l734
						}
						goto l735
					l734:
						position, tokenIndex = position734, tokenIndex734
					}
				l735:
					goto l723
				l722:
					position, tokenIndex = position722, tokenIndex722
				}
			l723:
				if buffer[position] != rune(']') {
					goto l720
				}
				position++
				{
					position738, tokenIndex738 := position, tokenIndex
					if !_rules[ruleARMPostincrement]() {
						goto l738
					}
					goto l739
				l738:
					position, tokenIndex = position738, tokenIndex738
				}
			l739:
				add(ruleARMBaseIndexScale, position721)
			}
			return true
		l720:
			position, tokenIndex = position720, tokenIndex720
			return false
		},
		/* 45 ARMGOTLow12 <- <(':' ('g' / 'G') ('o' / 'O') ('t' / 'T') '_' ('l' / 'L') ('o' / 'O') '1' '2' ':' SymbolName)> */
		func() bool {
			position740, tokenIndex740 := position, tokenIndex
			{
				position741 := position
				if buffer[position] != rune(':') {
					goto l740
				}
				position++
				{
					position742, tokenIndex742 := position, tokenIndex
					if buffer[position] != rune('g') {
						goto l743
					}
					position++
					goto l742
				l743:
					position, tokenIndex = position742, tokenIndex742
					if buffer[position] != rune('G') {
						goto l740
					}
					position++
				}
			l742:
				{
					position744, tokenIndex744 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l745
					}
					position++
					goto l744
				l745:
					position, tokenIndex = position744, tokenIndex744
					if buffer[position] != rune('O') {
						goto l740
					}
					position++
				}
			l744:
				{
					position746, tokenIndex746 := position, tokenIndex
					if buffer[position] != rune('t') {
						goto l747
					}
					position++
					goto l746
				l747:
					position, tokenIndex = position746, tokenIndex746
					if buffer[position] != rune('T') {
						goto l740
					}
					position++
				}
			l746:
				if buffer[position] != rune('_') {
					goto l740
				}
				position++
				{
					position748, tokenIndex748 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l749
					}
					position++
					goto l748
				l749:
					position, tokenIndex = position748, tokenIndex748
					if buffer[position] != rune('L') {
						goto l740
					}
					position++
				}
			l748:
				{
					position750, tokenIndex750 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l751
					}
					position++
					goto l750
				l751:
					position, tokenIndex = position750, tokenIndex750
					if buffer[position] != rune('O') {
						goto l740
					}
					position++
				}
			l750:
				if buffer[position] != rune('1') {
					goto l740
				}
				position++
				if buffer[position] != rune('2') {
					goto l740
				}
				position++
				if buffer[position] != rune(':') {
					goto l740
				}
				position++
				if !_rules[ruleSymbolName]() {
					goto l740
				}
				add(ruleARMGOTLow12, position741)
			}
			return true
		l740:
			position, tokenIndex = position740, tokenIndex740
			return false
		},
		/* 46 ARMPostincrement <- <'!'> */
		func() bool {
			position752, tokenIndex752 := position, tokenIndex
			{
				position753 := position
				if buffer[position] != rune('!') {
					goto l752
				}
				position++
				add(ruleARMPostincrement, position753)
			}
			return true
		l752:
			position, tokenIndex = position752, tokenIndex752
			return false
		},
		/* 47 BaseIndexScale <- <('(' RegisterOrConstant? WS? (',' WS? RegisterOrConstant WS? (',' [0-9]+)?)? ')')> */
		func() bool {
			position754, tokenIndex754 := position, tokenIndex
			{
				position755 := position
				if buffer[position] != rune('(') {
					goto l754
				}
				position++
				{
					position756, tokenIndex756 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l756
					}
					goto l757
				l756:
					position, tokenIndex = position756, tokenIndex756
				}
			l757:
				{
					position758, tokenIndex758 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l758
					}
					goto l759
				l758:
					position, tokenIndex = position758, tokenIndex758
				}
			l759:
				{
					position760, tokenIndex760 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l760
					}
					position++
					{
						position762, tokenIndex762 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l762
						}
						goto l763
					l762:
						position, tokenIndex = position762, tokenIndex762
					}
				l763:
					if !_rules[ruleRegisterOrConstant]() {
						goto l760
					}
					{
						position764, tokenIndex764 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l764
						}
						goto l765
					l764:
						position, tokenIndex = position764, tokenIndex764
					}
				l765:
					{
						position766, tokenIndex766 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l766
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l766
						}
						position++
					l768:
						{
							position769, tokenIndex769 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l769
							}
							position++
							goto l768
						l769:
							position, tokenIndex = position769, tokenIndex769
						}
						goto l767
					l766:
						position, tokenIndex = position766, tokenIndex766
					}
				l767:
					goto l761
				l760:
					position, tokenIndex = position760, tokenIndex760
				}
			l761:
				if buffer[position] != rune(')') {
					goto l754
				}
				position++
				add(ruleBaseIndexScale, position755)
			}
			return true
		l754:
			position, tokenIndex = position754, tokenIndex754
			return false
		},
		/* 48 Operator <- <('+' / '-')> */
		func() bool {
			position770, tokenIndex770 := position, tokenIndex
			{
				position771 := position
				{
					position772, tokenIndex772 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l773
					}
					position++
					goto l772
				l773:
					position, tokenIndex = position772, tokenIndex772
					if buffer[position] != rune('-') {
						goto l770
					}
					position++
				}
			l772:
				add(ruleOperator, position771)
			}
			return true
		l770:
			position, tokenIndex = position770, tokenIndex770
			return false
		},
		/* 49 Offset <- <('+'? '-'? (('0' ('b' / 'B') ('0' / '1')+) / ('0' ('x' / 'X') ([0-9] / [0-9] / ([a-f] / [A-F]))+) / [0-9]+))> */
		func() bool {
			position774, tokenIndex774 := position, tokenIndex
			{
				position775 := position
				{
					position776, tokenIndex776 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l776
					}
					position++
					goto l777
				l776:
					position, tokenIndex = position776, tokenIndex776
				}
			l777:
				{
					position778, tokenIndex778 := position, tokenIndex
					if buffer[position] != rune('-') {
						goto l778
					}
					position++
					goto l779
				l778:
					position, tokenIndex = position778, tokenIndex778
				}
			l779:
				{
					position780, tokenIndex780 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l781
					}
					position++
					{
						position782, tokenIndex782 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l783
						}
						position++
						goto l782
					l783:
						position, tokenIndex = position782, tokenIndex782
						if buffer[position] != rune('B') {
							goto l781
						}
						position++
					}
				l782:
					{
						position786, tokenIndex786 := position, tokenIndex
						if buffer[position] != rune('0') {
							goto l787
						}
						position++
						goto l786
					l787:
						position, tokenIndex = position786, tokenIndex786
						if buffer[position] != rune('1') {
							goto l781
						}
						position++
					}
				l786:
				l784:
					{
						position785, tokenIndex785 := position, tokenIndex
						{
							position788, tokenIndex788 := position, tokenIndex
							if buffer[position] != rune('0') {
								goto l789
							}
							position++
							goto l788
						l789:
							position, tokenIndex = position788, tokenIndex788
							if buffer[position] != rune('1') {
								goto l785
							}
							position++
						}
					l788:
						goto l784
					l785:
						position, tokenIndex = position785, tokenIndex785
					}
					goto l780
				l781:
					position, tokenIndex = position780, tokenIndex780
					if buffer[position] != rune('0') {
						goto l790
					}
					position++
					{
						position791, tokenIndex791 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l792
						}
						position++
						goto l791
					l792:
						position, tokenIndex = position791, tokenIndex791
						if buffer[position] != rune('X') {
							goto l790
						}
						position++
					}
				l791:
					{
						position795, tokenIndex795 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l796
						}
						position++
						goto l795
					l796:
						position, tokenIndex = position795, tokenIndex795
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l797
						}
						position++
						goto l795
					l797:
						position, tokenIndex = position795, tokenIndex795
						{
							position798, tokenIndex798 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('f') {
								goto l799
							}
							position++
							goto l798
						l799:
							position, tokenIndex = position798, tokenIndex798
							if c := buffer[position]; c < rune('A') || c > rune('F') {
								goto l790
							}
							position++
						}
					l798:
					}
				l795:
				l793:
					{
						position794, tokenIndex794 := position, tokenIndex
						{
							position800, tokenIndex800 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l801
							}
							position++
							goto l800
						l801:
							position, tokenIndex = position800, tokenIndex800
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l802
							}
							position++
							goto l800
						l802:
							position, tokenIndex = position800, tokenIndex800
							{
								position803, tokenIndex803 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('f') {
									goto l804
								}
								position++
								goto l803
							l804:
								position, tokenIndex = position803, tokenIndex803
								if c := buffer[position]; c < rune('A') || c > rune('F') {
									goto l794
								}
								position++
							}
						l803:
						}
					l800:
						goto l793
					l794:
						position, tokenIndex = position794, tokenIndex794
					}
					goto l780
				l790:
					position, tokenIndex = position780, tokenIndex780
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l774
					}
					position++
				l805:
					{
						position806, tokenIndex806 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l806
						}
						position++
						goto l805
					l806:
						position, tokenIndex = position806, tokenIndex806
					}
				}
			l780:
				add(ruleOffset, position775)
			}
			return true
		l774:
			position, tokenIndex = position774, tokenIndex774
			return false
		},
		/* 50 Section <- <([a-z] / [A-Z] / '@')+> */
		func() bool {
			position807, tokenIndex807 := position, tokenIndex
			{
				position808 := position
				{
					position811, tokenIndex811 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l812
					}
					position++
					goto l811
				l812:
					position, tokenIndex = position811, tokenIndex811
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l813
					}
					position++
					goto l811
				l813:
					position, tokenIndex = position811, tokenIndex811
					if buffer[position] != rune('@') {
						goto l807
					}
					position++
				}
			l811:
			l809:
				{
					position810, tokenIndex810 := position, tokenIndex
					{
						position814, tokenIndex814 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l815
						}
						position++
						goto l814
					l815:
						position, tokenIndex = position814, tokenIndex814
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l816
						}
						position++
						goto l814
					l816:
						position, tokenIndex = position814, tokenIndex814
						if buffer[position] != rune('@') {
							goto l810
						}
						position++
					}
				l814:
					goto l809
				l810:
					position, tokenIndex = position810, tokenIndex810
				}
				add(ruleSection, position808)
			}
			return true
		l807:
			position, tokenIndex = position807, tokenIndex807
			return false
		},
		/* 51 SegmentRegister <- <('%' ([c-g] / 's') ('s' ':'))> */
		func() bool {
			position817, tokenIndex817 := position, tokenIndex
			{
				position818 := position
				if buffer[position] != rune('%') {
					goto l817
				}
				position++
				{
					position819, tokenIndex819 := position, tokenIndex
					if c := buffer[position]; c < rune('c') || c > rune('g') {
						goto l820
					}
					position++
					goto l819
				l820:
					position, tokenIndex = position819, tokenIndex819
					if buffer[position] != rune('s') {
						goto l817
					}
					position++
				}
			l819:
				if buffer[position] != rune('s') {
					goto l817
				}
				position++
				if buffer[position] != rune(':') {
					goto l817
				}
				position++
				add(ruleSegmentRegister, position818)
			}
			return true
		l817:
			position, tokenIndex = position817, tokenIndex817
			return false
		},
	}
	p.rules = _rules
}
