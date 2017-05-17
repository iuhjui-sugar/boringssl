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
	ruleTOCRefHigh
	ruleTOCRefLow
	ruleIndirectionIndicator
	ruleRegisterOrConstant
	ruleMemoryRef
	ruleSymbolRef
	ruleBaseIndexScale
	ruleOperator
	ruleOffset
	ruleAbsolute
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
	"TOCRefHigh",
	"TOCRefLow",
	"IndirectionIndicator",
	"RegisterOrConstant",
	"MemoryRef",
	"SymbolRef",
	"BaseIndexScale",
	"Operator",
	"Offset",
	"Absolute",
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
	rules  [41]func() bool
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
		/* 5 LocationDirective <- <((('.' ('f' / 'F') ('i' / 'I') ('l' / 'L') ('e' / 'E')) / ('.' ('l' / 'L') ('o' / 'O') ('c' / 'C'))) WS (!('#' / '\n') .)+)> */
		func() bool {
			position70, tokenIndex70 := position, tokenIndex
			{
				position71 := position
				{
					position72, tokenIndex72 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l73
					}
					position++
					{
						position74, tokenIndex74 := position, tokenIndex
						if buffer[position] != rune('f') {
							goto l75
						}
						position++
						goto l74
					l75:
						position, tokenIndex = position74, tokenIndex74
						if buffer[position] != rune('F') {
							goto l73
						}
						position++
					}
				l74:
					{
						position76, tokenIndex76 := position, tokenIndex
						if buffer[position] != rune('i') {
							goto l77
						}
						position++
						goto l76
					l77:
						position, tokenIndex = position76, tokenIndex76
						if buffer[position] != rune('I') {
							goto l73
						}
						position++
					}
				l76:
					{
						position78, tokenIndex78 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l79
						}
						position++
						goto l78
					l79:
						position, tokenIndex = position78, tokenIndex78
						if buffer[position] != rune('L') {
							goto l73
						}
						position++
					}
				l78:
					{
						position80, tokenIndex80 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l81
						}
						position++
						goto l80
					l81:
						position, tokenIndex = position80, tokenIndex80
						if buffer[position] != rune('E') {
							goto l73
						}
						position++
					}
				l80:
					goto l72
				l73:
					position, tokenIndex = position72, tokenIndex72
					if buffer[position] != rune('.') {
						goto l70
					}
					position++
					{
						position82, tokenIndex82 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l83
						}
						position++
						goto l82
					l83:
						position, tokenIndex = position82, tokenIndex82
						if buffer[position] != rune('L') {
							goto l70
						}
						position++
					}
				l82:
					{
						position84, tokenIndex84 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l85
						}
						position++
						goto l84
					l85:
						position, tokenIndex = position84, tokenIndex84
						if buffer[position] != rune('O') {
							goto l70
						}
						position++
					}
				l84:
					{
						position86, tokenIndex86 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l87
						}
						position++
						goto l86
					l87:
						position, tokenIndex = position86, tokenIndex86
						if buffer[position] != rune('C') {
							goto l70
						}
						position++
					}
				l86:
				}
			l72:
				if !_rules[ruleWS]() {
					goto l70
				}
				{
					position90, tokenIndex90 := position, tokenIndex
					{
						position91, tokenIndex91 := position, tokenIndex
						if buffer[position] != rune('#') {
							goto l92
						}
						position++
						goto l91
					l92:
						position, tokenIndex = position91, tokenIndex91
						if buffer[position] != rune('\n') {
							goto l90
						}
						position++
					}
				l91:
					goto l70
				l90:
					position, tokenIndex = position90, tokenIndex90
				}
				if !matchDot() {
					goto l70
				}
			l88:
				{
					position89, tokenIndex89 := position, tokenIndex
					{
						position93, tokenIndex93 := position, tokenIndex
						{
							position94, tokenIndex94 := position, tokenIndex
							if buffer[position] != rune('#') {
								goto l95
							}
							position++
							goto l94
						l95:
							position, tokenIndex = position94, tokenIndex94
							if buffer[position] != rune('\n') {
								goto l93
							}
							position++
						}
					l94:
						goto l89
					l93:
						position, tokenIndex = position93, tokenIndex93
					}
					if !matchDot() {
						goto l89
					}
					goto l88
				l89:
					position, tokenIndex = position89, tokenIndex89
				}
				add(ruleLocationDirective, position71)
			}
			return true
		l70:
			position, tokenIndex = position70, tokenIndex70
			return false
		},
		/* 6 Args <- <(Arg (WS? ',' WS? Arg)*)> */
		func() bool {
			position96, tokenIndex96 := position, tokenIndex
			{
				position97 := position
				if !_rules[ruleArg]() {
					goto l96
				}
			l98:
				{
					position99, tokenIndex99 := position, tokenIndex
					{
						position100, tokenIndex100 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l100
						}
						goto l101
					l100:
						position, tokenIndex = position100, tokenIndex100
					}
				l101:
					if buffer[position] != rune(',') {
						goto l99
					}
					position++
					{
						position102, tokenIndex102 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l102
						}
						goto l103
					l102:
						position, tokenIndex = position102, tokenIndex102
					}
				l103:
					if !_rules[ruleArg]() {
						goto l99
					}
					goto l98
				l99:
					position, tokenIndex = position99, tokenIndex99
				}
				add(ruleArgs, position97)
			}
			return true
		l96:
			position, tokenIndex = position96, tokenIndex96
			return false
		},
		/* 7 Arg <- <(QuotedArg / ([0-9] / [0-9] / ([a-z] / [A-Z]) / '%' / '+' / '-' / '_' / '@' / '.')+)> */
		func() bool {
			position104, tokenIndex104 := position, tokenIndex
			{
				position105 := position
				{
					position106, tokenIndex106 := position, tokenIndex
					if !_rules[ruleQuotedArg]() {
						goto l107
					}
					goto l106
				l107:
					position, tokenIndex = position106, tokenIndex106
					{
						position110, tokenIndex110 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l111
						}
						position++
						goto l110
					l111:
						position, tokenIndex = position110, tokenIndex110
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l112
						}
						position++
						goto l110
					l112:
						position, tokenIndex = position110, tokenIndex110
						{
							position114, tokenIndex114 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l115
							}
							position++
							goto l114
						l115:
							position, tokenIndex = position114, tokenIndex114
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l113
							}
							position++
						}
					l114:
						goto l110
					l113:
						position, tokenIndex = position110, tokenIndex110
						if buffer[position] != rune('%') {
							goto l116
						}
						position++
						goto l110
					l116:
						position, tokenIndex = position110, tokenIndex110
						if buffer[position] != rune('+') {
							goto l117
						}
						position++
						goto l110
					l117:
						position, tokenIndex = position110, tokenIndex110
						if buffer[position] != rune('-') {
							goto l118
						}
						position++
						goto l110
					l118:
						position, tokenIndex = position110, tokenIndex110
						if buffer[position] != rune('_') {
							goto l119
						}
						position++
						goto l110
					l119:
						position, tokenIndex = position110, tokenIndex110
						if buffer[position] != rune('@') {
							goto l120
						}
						position++
						goto l110
					l120:
						position, tokenIndex = position110, tokenIndex110
						if buffer[position] != rune('.') {
							goto l104
						}
						position++
					}
				l110:
				l108:
					{
						position109, tokenIndex109 := position, tokenIndex
						{
							position121, tokenIndex121 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l122
							}
							position++
							goto l121
						l122:
							position, tokenIndex = position121, tokenIndex121
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l123
							}
							position++
							goto l121
						l123:
							position, tokenIndex = position121, tokenIndex121
							{
								position125, tokenIndex125 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('z') {
									goto l126
								}
								position++
								goto l125
							l126:
								position, tokenIndex = position125, tokenIndex125
								if c := buffer[position]; c < rune('A') || c > rune('Z') {
									goto l124
								}
								position++
							}
						l125:
							goto l121
						l124:
							position, tokenIndex = position121, tokenIndex121
							if buffer[position] != rune('%') {
								goto l127
							}
							position++
							goto l121
						l127:
							position, tokenIndex = position121, tokenIndex121
							if buffer[position] != rune('+') {
								goto l128
							}
							position++
							goto l121
						l128:
							position, tokenIndex = position121, tokenIndex121
							if buffer[position] != rune('-') {
								goto l129
							}
							position++
							goto l121
						l129:
							position, tokenIndex = position121, tokenIndex121
							if buffer[position] != rune('_') {
								goto l130
							}
							position++
							goto l121
						l130:
							position, tokenIndex = position121, tokenIndex121
							if buffer[position] != rune('@') {
								goto l131
							}
							position++
							goto l121
						l131:
							position, tokenIndex = position121, tokenIndex121
							if buffer[position] != rune('.') {
								goto l109
							}
							position++
						}
					l121:
						goto l108
					l109:
						position, tokenIndex = position109, tokenIndex109
					}
				}
			l106:
				add(ruleArg, position105)
			}
			return true
		l104:
			position, tokenIndex = position104, tokenIndex104
			return false
		},
		/* 8 QuotedArg <- <('"' QuotedText '"')> */
		func() bool {
			position132, tokenIndex132 := position, tokenIndex
			{
				position133 := position
				if buffer[position] != rune('"') {
					goto l132
				}
				position++
				if !_rules[ruleQuotedText]() {
					goto l132
				}
				if buffer[position] != rune('"') {
					goto l132
				}
				position++
				add(ruleQuotedArg, position133)
			}
			return true
		l132:
			position, tokenIndex = position132, tokenIndex132
			return false
		},
		/* 9 QuotedText <- <(EscapedChar / (!'"' .))*> */
		func() bool {
			{
				position135 := position
			l136:
				{
					position137, tokenIndex137 := position, tokenIndex
					{
						position138, tokenIndex138 := position, tokenIndex
						if !_rules[ruleEscapedChar]() {
							goto l139
						}
						goto l138
					l139:
						position, tokenIndex = position138, tokenIndex138
						{
							position140, tokenIndex140 := position, tokenIndex
							if buffer[position] != rune('"') {
								goto l140
							}
							position++
							goto l137
						l140:
							position, tokenIndex = position140, tokenIndex140
						}
						if !matchDot() {
							goto l137
						}
					}
				l138:
					goto l136
				l137:
					position, tokenIndex = position137, tokenIndex137
				}
				add(ruleQuotedText, position135)
			}
			return true
		},
		/* 10 LabelContainingDirective <- <(LabelContainingDirectiveName WS SymbolArgs)> */
		func() bool {
			position141, tokenIndex141 := position, tokenIndex
			{
				position142 := position
				if !_rules[ruleLabelContainingDirectiveName]() {
					goto l141
				}
				if !_rules[ruleWS]() {
					goto l141
				}
				if !_rules[ruleSymbolArgs]() {
					goto l141
				}
				add(ruleLabelContainingDirective, position142)
			}
			return true
		l141:
			position, tokenIndex = position141, tokenIndex141
			return false
		},
		/* 11 LabelContainingDirectiveName <- <(('.' ('l' / 'L') ('o' / 'O') ('n' / 'N') ('g' / 'G')) / ('.' ('s' / 'S') ('e' / 'E') ('t' / 'T')) / ('.' '8' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' '4' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' ('q' / 'Q') ('u' / 'U') ('a' / 'A') ('d' / 'D')) / ('.' ('t' / 'T') ('c' / 'C')) / ('.' ('l' / 'L') ('o' / 'O') ('c' / 'C') ('a' / 'A') ('l' / 'L') ('e' / 'E') ('n' / 'N') ('t' / 'T') ('r' / 'R') ('y' / 'Y')) / ('.' ('s' / 'S') ('i' / 'I') ('z' / 'Z') ('e' / 'E')) / ('.' ('t' / 'T') ('y' / 'Y') ('p' / 'P') ('e' / 'E')))> */
		func() bool {
			position143, tokenIndex143 := position, tokenIndex
			{
				position144 := position
				{
					position145, tokenIndex145 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l146
					}
					position++
					{
						position147, tokenIndex147 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l148
						}
						position++
						goto l147
					l148:
						position, tokenIndex = position147, tokenIndex147
						if buffer[position] != rune('L') {
							goto l146
						}
						position++
					}
				l147:
					{
						position149, tokenIndex149 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l150
						}
						position++
						goto l149
					l150:
						position, tokenIndex = position149, tokenIndex149
						if buffer[position] != rune('O') {
							goto l146
						}
						position++
					}
				l149:
					{
						position151, tokenIndex151 := position, tokenIndex
						if buffer[position] != rune('n') {
							goto l152
						}
						position++
						goto l151
					l152:
						position, tokenIndex = position151, tokenIndex151
						if buffer[position] != rune('N') {
							goto l146
						}
						position++
					}
				l151:
					{
						position153, tokenIndex153 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l154
						}
						position++
						goto l153
					l154:
						position, tokenIndex = position153, tokenIndex153
						if buffer[position] != rune('G') {
							goto l146
						}
						position++
					}
				l153:
					goto l145
				l146:
					position, tokenIndex = position145, tokenIndex145
					if buffer[position] != rune('.') {
						goto l155
					}
					position++
					{
						position156, tokenIndex156 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l157
						}
						position++
						goto l156
					l157:
						position, tokenIndex = position156, tokenIndex156
						if buffer[position] != rune('S') {
							goto l155
						}
						position++
					}
				l156:
					{
						position158, tokenIndex158 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l159
						}
						position++
						goto l158
					l159:
						position, tokenIndex = position158, tokenIndex158
						if buffer[position] != rune('E') {
							goto l155
						}
						position++
					}
				l158:
					{
						position160, tokenIndex160 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l161
						}
						position++
						goto l160
					l161:
						position, tokenIndex = position160, tokenIndex160
						if buffer[position] != rune('T') {
							goto l155
						}
						position++
					}
				l160:
					goto l145
				l155:
					position, tokenIndex = position145, tokenIndex145
					if buffer[position] != rune('.') {
						goto l162
					}
					position++
					if buffer[position] != rune('8') {
						goto l162
					}
					position++
					{
						position163, tokenIndex163 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l164
						}
						position++
						goto l163
					l164:
						position, tokenIndex = position163, tokenIndex163
						if buffer[position] != rune('B') {
							goto l162
						}
						position++
					}
				l163:
					{
						position165, tokenIndex165 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l166
						}
						position++
						goto l165
					l166:
						position, tokenIndex = position165, tokenIndex165
						if buffer[position] != rune('Y') {
							goto l162
						}
						position++
					}
				l165:
					{
						position167, tokenIndex167 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l168
						}
						position++
						goto l167
					l168:
						position, tokenIndex = position167, tokenIndex167
						if buffer[position] != rune('T') {
							goto l162
						}
						position++
					}
				l167:
					{
						position169, tokenIndex169 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l170
						}
						position++
						goto l169
					l170:
						position, tokenIndex = position169, tokenIndex169
						if buffer[position] != rune('E') {
							goto l162
						}
						position++
					}
				l169:
					goto l145
				l162:
					position, tokenIndex = position145, tokenIndex145
					if buffer[position] != rune('.') {
						goto l171
					}
					position++
					if buffer[position] != rune('4') {
						goto l171
					}
					position++
					{
						position172, tokenIndex172 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l173
						}
						position++
						goto l172
					l173:
						position, tokenIndex = position172, tokenIndex172
						if buffer[position] != rune('B') {
							goto l171
						}
						position++
					}
				l172:
					{
						position174, tokenIndex174 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l175
						}
						position++
						goto l174
					l175:
						position, tokenIndex = position174, tokenIndex174
						if buffer[position] != rune('Y') {
							goto l171
						}
						position++
					}
				l174:
					{
						position176, tokenIndex176 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l177
						}
						position++
						goto l176
					l177:
						position, tokenIndex = position176, tokenIndex176
						if buffer[position] != rune('T') {
							goto l171
						}
						position++
					}
				l176:
					{
						position178, tokenIndex178 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l179
						}
						position++
						goto l178
					l179:
						position, tokenIndex = position178, tokenIndex178
						if buffer[position] != rune('E') {
							goto l171
						}
						position++
					}
				l178:
					goto l145
				l171:
					position, tokenIndex = position145, tokenIndex145
					if buffer[position] != rune('.') {
						goto l180
					}
					position++
					{
						position181, tokenIndex181 := position, tokenIndex
						if buffer[position] != rune('q') {
							goto l182
						}
						position++
						goto l181
					l182:
						position, tokenIndex = position181, tokenIndex181
						if buffer[position] != rune('Q') {
							goto l180
						}
						position++
					}
				l181:
					{
						position183, tokenIndex183 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l184
						}
						position++
						goto l183
					l184:
						position, tokenIndex = position183, tokenIndex183
						if buffer[position] != rune('U') {
							goto l180
						}
						position++
					}
				l183:
					{
						position185, tokenIndex185 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l186
						}
						position++
						goto l185
					l186:
						position, tokenIndex = position185, tokenIndex185
						if buffer[position] != rune('A') {
							goto l180
						}
						position++
					}
				l185:
					{
						position187, tokenIndex187 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l188
						}
						position++
						goto l187
					l188:
						position, tokenIndex = position187, tokenIndex187
						if buffer[position] != rune('D') {
							goto l180
						}
						position++
					}
				l187:
					goto l145
				l180:
					position, tokenIndex = position145, tokenIndex145
					if buffer[position] != rune('.') {
						goto l189
					}
					position++
					{
						position190, tokenIndex190 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l191
						}
						position++
						goto l190
					l191:
						position, tokenIndex = position190, tokenIndex190
						if buffer[position] != rune('T') {
							goto l189
						}
						position++
					}
				l190:
					{
						position192, tokenIndex192 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l193
						}
						position++
						goto l192
					l193:
						position, tokenIndex = position192, tokenIndex192
						if buffer[position] != rune('C') {
							goto l189
						}
						position++
					}
				l192:
					goto l145
				l189:
					position, tokenIndex = position145, tokenIndex145
					if buffer[position] != rune('.') {
						goto l194
					}
					position++
					{
						position195, tokenIndex195 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l196
						}
						position++
						goto l195
					l196:
						position, tokenIndex = position195, tokenIndex195
						if buffer[position] != rune('L') {
							goto l194
						}
						position++
					}
				l195:
					{
						position197, tokenIndex197 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l198
						}
						position++
						goto l197
					l198:
						position, tokenIndex = position197, tokenIndex197
						if buffer[position] != rune('O') {
							goto l194
						}
						position++
					}
				l197:
					{
						position199, tokenIndex199 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l200
						}
						position++
						goto l199
					l200:
						position, tokenIndex = position199, tokenIndex199
						if buffer[position] != rune('C') {
							goto l194
						}
						position++
					}
				l199:
					{
						position201, tokenIndex201 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l202
						}
						position++
						goto l201
					l202:
						position, tokenIndex = position201, tokenIndex201
						if buffer[position] != rune('A') {
							goto l194
						}
						position++
					}
				l201:
					{
						position203, tokenIndex203 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l204
						}
						position++
						goto l203
					l204:
						position, tokenIndex = position203, tokenIndex203
						if buffer[position] != rune('L') {
							goto l194
						}
						position++
					}
				l203:
					{
						position205, tokenIndex205 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l206
						}
						position++
						goto l205
					l206:
						position, tokenIndex = position205, tokenIndex205
						if buffer[position] != rune('E') {
							goto l194
						}
						position++
					}
				l205:
					{
						position207, tokenIndex207 := position, tokenIndex
						if buffer[position] != rune('n') {
							goto l208
						}
						position++
						goto l207
					l208:
						position, tokenIndex = position207, tokenIndex207
						if buffer[position] != rune('N') {
							goto l194
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
							goto l194
						}
						position++
					}
				l209:
					{
						position211, tokenIndex211 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l212
						}
						position++
						goto l211
					l212:
						position, tokenIndex = position211, tokenIndex211
						if buffer[position] != rune('R') {
							goto l194
						}
						position++
					}
				l211:
					{
						position213, tokenIndex213 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l214
						}
						position++
						goto l213
					l214:
						position, tokenIndex = position213, tokenIndex213
						if buffer[position] != rune('Y') {
							goto l194
						}
						position++
					}
				l213:
					goto l145
				l194:
					position, tokenIndex = position145, tokenIndex145
					if buffer[position] != rune('.') {
						goto l215
					}
					position++
					{
						position216, tokenIndex216 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l217
						}
						position++
						goto l216
					l217:
						position, tokenIndex = position216, tokenIndex216
						if buffer[position] != rune('S') {
							goto l215
						}
						position++
					}
				l216:
					{
						position218, tokenIndex218 := position, tokenIndex
						if buffer[position] != rune('i') {
							goto l219
						}
						position++
						goto l218
					l219:
						position, tokenIndex = position218, tokenIndex218
						if buffer[position] != rune('I') {
							goto l215
						}
						position++
					}
				l218:
					{
						position220, tokenIndex220 := position, tokenIndex
						if buffer[position] != rune('z') {
							goto l221
						}
						position++
						goto l220
					l221:
						position, tokenIndex = position220, tokenIndex220
						if buffer[position] != rune('Z') {
							goto l215
						}
						position++
					}
				l220:
					{
						position222, tokenIndex222 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l223
						}
						position++
						goto l222
					l223:
						position, tokenIndex = position222, tokenIndex222
						if buffer[position] != rune('E') {
							goto l215
						}
						position++
					}
				l222:
					goto l145
				l215:
					position, tokenIndex = position145, tokenIndex145
					if buffer[position] != rune('.') {
						goto l143
					}
					position++
					{
						position224, tokenIndex224 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l225
						}
						position++
						goto l224
					l225:
						position, tokenIndex = position224, tokenIndex224
						if buffer[position] != rune('T') {
							goto l143
						}
						position++
					}
				l224:
					{
						position226, tokenIndex226 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l227
						}
						position++
						goto l226
					l227:
						position, tokenIndex = position226, tokenIndex226
						if buffer[position] != rune('Y') {
							goto l143
						}
						position++
					}
				l226:
					{
						position228, tokenIndex228 := position, tokenIndex
						if buffer[position] != rune('p') {
							goto l229
						}
						position++
						goto l228
					l229:
						position, tokenIndex = position228, tokenIndex228
						if buffer[position] != rune('P') {
							goto l143
						}
						position++
					}
				l228:
					{
						position230, tokenIndex230 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l231
						}
						position++
						goto l230
					l231:
						position, tokenIndex = position230, tokenIndex230
						if buffer[position] != rune('E') {
							goto l143
						}
						position++
					}
				l230:
				}
			l145:
				add(ruleLabelContainingDirectiveName, position144)
			}
			return true
		l143:
			position, tokenIndex = position143, tokenIndex143
			return false
		},
		/* 12 SymbolArgs <- <(SymbolArg (WS? ',' WS? SymbolArg)*)> */
		func() bool {
			position232, tokenIndex232 := position, tokenIndex
			{
				position233 := position
				if !_rules[ruleSymbolArg]() {
					goto l232
				}
			l234:
				{
					position235, tokenIndex235 := position, tokenIndex
					{
						position236, tokenIndex236 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l236
						}
						goto l237
					l236:
						position, tokenIndex = position236, tokenIndex236
					}
				l237:
					if buffer[position] != rune(',') {
						goto l235
					}
					position++
					{
						position238, tokenIndex238 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l238
						}
						goto l239
					l238:
						position, tokenIndex = position238, tokenIndex238
					}
				l239:
					if !_rules[ruleSymbolArg]() {
						goto l235
					}
					goto l234
				l235:
					position, tokenIndex = position235, tokenIndex235
				}
				add(ruleSymbolArgs, position233)
			}
			return true
		l232:
			position, tokenIndex = position232, tokenIndex232
			return false
		},
		/* 13 SymbolArg <- <(Offset / SymbolType / ((Offset / LocalSymbol / SymbolName / Dot) WS? Operator WS? (Offset / LocalSymbol / SymbolName)) / (LocalSymbol TCMarker?) / (SymbolName Offset) / (SymbolName TCMarker?))> */
		func() bool {
			position240, tokenIndex240 := position, tokenIndex
			{
				position241 := position
				{
					position242, tokenIndex242 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l243
					}
					goto l242
				l243:
					position, tokenIndex = position242, tokenIndex242
					if !_rules[ruleSymbolType]() {
						goto l244
					}
					goto l242
				l244:
					position, tokenIndex = position242, tokenIndex242
					{
						position246, tokenIndex246 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l247
						}
						goto l246
					l247:
						position, tokenIndex = position246, tokenIndex246
						if !_rules[ruleLocalSymbol]() {
							goto l248
						}
						goto l246
					l248:
						position, tokenIndex = position246, tokenIndex246
						if !_rules[ruleSymbolName]() {
							goto l249
						}
						goto l246
					l249:
						position, tokenIndex = position246, tokenIndex246
						if !_rules[ruleDot]() {
							goto l245
						}
					}
				l246:
					{
						position250, tokenIndex250 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l250
						}
						goto l251
					l250:
						position, tokenIndex = position250, tokenIndex250
					}
				l251:
					if !_rules[ruleOperator]() {
						goto l245
					}
					{
						position252, tokenIndex252 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l252
						}
						goto l253
					l252:
						position, tokenIndex = position252, tokenIndex252
					}
				l253:
					{
						position254, tokenIndex254 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l255
						}
						goto l254
					l255:
						position, tokenIndex = position254, tokenIndex254
						if !_rules[ruleLocalSymbol]() {
							goto l256
						}
						goto l254
					l256:
						position, tokenIndex = position254, tokenIndex254
						if !_rules[ruleSymbolName]() {
							goto l245
						}
					}
				l254:
					goto l242
				l245:
					position, tokenIndex = position242, tokenIndex242
					if !_rules[ruleLocalSymbol]() {
						goto l257
					}
					{
						position258, tokenIndex258 := position, tokenIndex
						if !_rules[ruleTCMarker]() {
							goto l258
						}
						goto l259
					l258:
						position, tokenIndex = position258, tokenIndex258
					}
				l259:
					goto l242
				l257:
					position, tokenIndex = position242, tokenIndex242
					if !_rules[ruleSymbolName]() {
						goto l260
					}
					if !_rules[ruleOffset]() {
						goto l260
					}
					goto l242
				l260:
					position, tokenIndex = position242, tokenIndex242
					if !_rules[ruleSymbolName]() {
						goto l240
					}
					{
						position261, tokenIndex261 := position, tokenIndex
						if !_rules[ruleTCMarker]() {
							goto l261
						}
						goto l262
					l261:
						position, tokenIndex = position261, tokenIndex261
					}
				l262:
				}
			l242:
				add(ruleSymbolArg, position241)
			}
			return true
		l240:
			position, tokenIndex = position240, tokenIndex240
			return false
		},
		/* 14 SymbolType <- <(('@' 'f' 'u' 'n' 'c' 't' 'i' 'o' 'n') / ('@' 'o' 'b' 'j' 'e' 'c' 't'))> */
		func() bool {
			position263, tokenIndex263 := position, tokenIndex
			{
				position264 := position
				{
					position265, tokenIndex265 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l266
					}
					position++
					if buffer[position] != rune('f') {
						goto l266
					}
					position++
					if buffer[position] != rune('u') {
						goto l266
					}
					position++
					if buffer[position] != rune('n') {
						goto l266
					}
					position++
					if buffer[position] != rune('c') {
						goto l266
					}
					position++
					if buffer[position] != rune('t') {
						goto l266
					}
					position++
					if buffer[position] != rune('i') {
						goto l266
					}
					position++
					if buffer[position] != rune('o') {
						goto l266
					}
					position++
					if buffer[position] != rune('n') {
						goto l266
					}
					position++
					goto l265
				l266:
					position, tokenIndex = position265, tokenIndex265
					if buffer[position] != rune('@') {
						goto l263
					}
					position++
					if buffer[position] != rune('o') {
						goto l263
					}
					position++
					if buffer[position] != rune('b') {
						goto l263
					}
					position++
					if buffer[position] != rune('j') {
						goto l263
					}
					position++
					if buffer[position] != rune('e') {
						goto l263
					}
					position++
					if buffer[position] != rune('c') {
						goto l263
					}
					position++
					if buffer[position] != rune('t') {
						goto l263
					}
					position++
				}
			l265:
				add(ruleSymbolType, position264)
			}
			return true
		l263:
			position, tokenIndex = position263, tokenIndex263
			return false
		},
		/* 15 Dot <- <'.'> */
		func() bool {
			position267, tokenIndex267 := position, tokenIndex
			{
				position268 := position
				if buffer[position] != rune('.') {
					goto l267
				}
				position++
				add(ruleDot, position268)
			}
			return true
		l267:
			position, tokenIndex = position267, tokenIndex267
			return false
		},
		/* 16 TCMarker <- <('[' 'T' 'C' ']')> */
		func() bool {
			position269, tokenIndex269 := position, tokenIndex
			{
				position270 := position
				if buffer[position] != rune('[') {
					goto l269
				}
				position++
				if buffer[position] != rune('T') {
					goto l269
				}
				position++
				if buffer[position] != rune('C') {
					goto l269
				}
				position++
				if buffer[position] != rune(']') {
					goto l269
				}
				position++
				add(ruleTCMarker, position270)
			}
			return true
		l269:
			position, tokenIndex = position269, tokenIndex269
			return false
		},
		/* 17 EscapedChar <- <('\\' .)> */
		func() bool {
			position271, tokenIndex271 := position, tokenIndex
			{
				position272 := position
				if buffer[position] != rune('\\') {
					goto l271
				}
				position++
				if !matchDot() {
					goto l271
				}
				add(ruleEscapedChar, position272)
			}
			return true
		l271:
			position, tokenIndex = position271, tokenIndex271
			return false
		},
		/* 18 WS <- <(' ' / '\t')+> */
		func() bool {
			position273, tokenIndex273 := position, tokenIndex
			{
				position274 := position
				{
					position277, tokenIndex277 := position, tokenIndex
					if buffer[position] != rune(' ') {
						goto l278
					}
					position++
					goto l277
				l278:
					position, tokenIndex = position277, tokenIndex277
					if buffer[position] != rune('\t') {
						goto l273
					}
					position++
				}
			l277:
			l275:
				{
					position276, tokenIndex276 := position, tokenIndex
					{
						position279, tokenIndex279 := position, tokenIndex
						if buffer[position] != rune(' ') {
							goto l280
						}
						position++
						goto l279
					l280:
						position, tokenIndex = position279, tokenIndex279
						if buffer[position] != rune('\t') {
							goto l276
						}
						position++
					}
				l279:
					goto l275
				l276:
					position, tokenIndex = position276, tokenIndex276
				}
				add(ruleWS, position274)
			}
			return true
		l273:
			position, tokenIndex = position273, tokenIndex273
			return false
		},
		/* 19 Comment <- <('#' (!'\n' .)*)> */
		func() bool {
			position281, tokenIndex281 := position, tokenIndex
			{
				position282 := position
				if buffer[position] != rune('#') {
					goto l281
				}
				position++
			l283:
				{
					position284, tokenIndex284 := position, tokenIndex
					{
						position285, tokenIndex285 := position, tokenIndex
						if buffer[position] != rune('\n') {
							goto l285
						}
						position++
						goto l284
					l285:
						position, tokenIndex = position285, tokenIndex285
					}
					if !matchDot() {
						goto l284
					}
					goto l283
				l284:
					position, tokenIndex = position284, tokenIndex284
				}
				add(ruleComment, position282)
			}
			return true
		l281:
			position, tokenIndex = position281, tokenIndex281
			return false
		},
		/* 20 Label <- <((LocalSymbol / LocalLabel / SymbolName) ':')> */
		func() bool {
			position286, tokenIndex286 := position, tokenIndex
			{
				position287 := position
				{
					position288, tokenIndex288 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l289
					}
					goto l288
				l289:
					position, tokenIndex = position288, tokenIndex288
					if !_rules[ruleLocalLabel]() {
						goto l290
					}
					goto l288
				l290:
					position, tokenIndex = position288, tokenIndex288
					if !_rules[ruleSymbolName]() {
						goto l286
					}
				}
			l288:
				if buffer[position] != rune(':') {
					goto l286
				}
				position++
				add(ruleLabel, position287)
			}
			return true
		l286:
			position, tokenIndex = position286, tokenIndex286
			return false
		},
		/* 21 SymbolName <- <(([a-z] / [A-Z] / '.' / '_') ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')*)> */
		func() bool {
			position291, tokenIndex291 := position, tokenIndex
			{
				position292 := position
				{
					position293, tokenIndex293 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l294
					}
					position++
					goto l293
				l294:
					position, tokenIndex = position293, tokenIndex293
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l295
					}
					position++
					goto l293
				l295:
					position, tokenIndex = position293, tokenIndex293
					if buffer[position] != rune('.') {
						goto l296
					}
					position++
					goto l293
				l296:
					position, tokenIndex = position293, tokenIndex293
					if buffer[position] != rune('_') {
						goto l291
					}
					position++
				}
			l293:
			l297:
				{
					position298, tokenIndex298 := position, tokenIndex
					{
						position299, tokenIndex299 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l300
						}
						position++
						goto l299
					l300:
						position, tokenIndex = position299, tokenIndex299
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l301
						}
						position++
						goto l299
					l301:
						position, tokenIndex = position299, tokenIndex299
						if buffer[position] != rune('.') {
							goto l302
						}
						position++
						goto l299
					l302:
						position, tokenIndex = position299, tokenIndex299
						{
							position304, tokenIndex304 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l305
							}
							position++
							goto l304
						l305:
							position, tokenIndex = position304, tokenIndex304
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l303
							}
							position++
						}
					l304:
						goto l299
					l303:
						position, tokenIndex = position299, tokenIndex299
						if buffer[position] != rune('$') {
							goto l306
						}
						position++
						goto l299
					l306:
						position, tokenIndex = position299, tokenIndex299
						if buffer[position] != rune('_') {
							goto l298
						}
						position++
					}
				l299:
					goto l297
				l298:
					position, tokenIndex = position298, tokenIndex298
				}
				add(ruleSymbolName, position292)
			}
			return true
		l291:
			position, tokenIndex = position291, tokenIndex291
			return false
		},
		/* 22 LocalSymbol <- <('.' 'L' ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')+)> */
		func() bool {
			position307, tokenIndex307 := position, tokenIndex
			{
				position308 := position
				if buffer[position] != rune('.') {
					goto l307
				}
				position++
				if buffer[position] != rune('L') {
					goto l307
				}
				position++
				{
					position311, tokenIndex311 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l312
					}
					position++
					goto l311
				l312:
					position, tokenIndex = position311, tokenIndex311
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l313
					}
					position++
					goto l311
				l313:
					position, tokenIndex = position311, tokenIndex311
					if buffer[position] != rune('.') {
						goto l314
					}
					position++
					goto l311
				l314:
					position, tokenIndex = position311, tokenIndex311
					{
						position316, tokenIndex316 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l317
						}
						position++
						goto l316
					l317:
						position, tokenIndex = position316, tokenIndex316
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l315
						}
						position++
					}
				l316:
					goto l311
				l315:
					position, tokenIndex = position311, tokenIndex311
					if buffer[position] != rune('$') {
						goto l318
					}
					position++
					goto l311
				l318:
					position, tokenIndex = position311, tokenIndex311
					if buffer[position] != rune('_') {
						goto l307
					}
					position++
				}
			l311:
			l309:
				{
					position310, tokenIndex310 := position, tokenIndex
					{
						position319, tokenIndex319 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l320
						}
						position++
						goto l319
					l320:
						position, tokenIndex = position319, tokenIndex319
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l321
						}
						position++
						goto l319
					l321:
						position, tokenIndex = position319, tokenIndex319
						if buffer[position] != rune('.') {
							goto l322
						}
						position++
						goto l319
					l322:
						position, tokenIndex = position319, tokenIndex319
						{
							position324, tokenIndex324 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l325
							}
							position++
							goto l324
						l325:
							position, tokenIndex = position324, tokenIndex324
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l323
							}
							position++
						}
					l324:
						goto l319
					l323:
						position, tokenIndex = position319, tokenIndex319
						if buffer[position] != rune('$') {
							goto l326
						}
						position++
						goto l319
					l326:
						position, tokenIndex = position319, tokenIndex319
						if buffer[position] != rune('_') {
							goto l310
						}
						position++
					}
				l319:
					goto l309
				l310:
					position, tokenIndex = position310, tokenIndex310
				}
				add(ruleLocalSymbol, position308)
			}
			return true
		l307:
			position, tokenIndex = position307, tokenIndex307
			return false
		},
		/* 23 LocalLabel <- <([0-9] ([0-9] / '$')*)> */
		func() bool {
			position327, tokenIndex327 := position, tokenIndex
			{
				position328 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l327
				}
				position++
			l329:
				{
					position330, tokenIndex330 := position, tokenIndex
					{
						position331, tokenIndex331 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l332
						}
						position++
						goto l331
					l332:
						position, tokenIndex = position331, tokenIndex331
						if buffer[position] != rune('$') {
							goto l330
						}
						position++
					}
				l331:
					goto l329
				l330:
					position, tokenIndex = position330, tokenIndex330
				}
				add(ruleLocalLabel, position328)
			}
			return true
		l327:
			position, tokenIndex = position327, tokenIndex327
			return false
		},
		/* 24 LocalLabelRef <- <([0-9] ([0-9] / '$')* ('b' / 'f'))> */
		func() bool {
			position333, tokenIndex333 := position, tokenIndex
			{
				position334 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l333
				}
				position++
			l335:
				{
					position336, tokenIndex336 := position, tokenIndex
					{
						position337, tokenIndex337 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l338
						}
						position++
						goto l337
					l338:
						position, tokenIndex = position337, tokenIndex337
						if buffer[position] != rune('$') {
							goto l336
						}
						position++
					}
				l337:
					goto l335
				l336:
					position, tokenIndex = position336, tokenIndex336
				}
				{
					position339, tokenIndex339 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l340
					}
					position++
					goto l339
				l340:
					position, tokenIndex = position339, tokenIndex339
					if buffer[position] != rune('f') {
						goto l333
					}
					position++
				}
			l339:
				add(ruleLocalLabelRef, position334)
			}
			return true
		l333:
			position, tokenIndex = position333, tokenIndex333
			return false
		},
		/* 25 Instruction <- <(InstructionName WS? InstructionArg? WS? (',' WS? InstructionArg)*)> */
		func() bool {
			position341, tokenIndex341 := position, tokenIndex
			{
				position342 := position
				if !_rules[ruleInstructionName]() {
					goto l341
				}
				{
					position343, tokenIndex343 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l343
					}
					goto l344
				l343:
					position, tokenIndex = position343, tokenIndex343
				}
			l344:
				{
					position345, tokenIndex345 := position, tokenIndex
					if !_rules[ruleInstructionArg]() {
						goto l345
					}
					goto l346
				l345:
					position, tokenIndex = position345, tokenIndex345
				}
			l346:
				{
					position347, tokenIndex347 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l347
					}
					goto l348
				l347:
					position, tokenIndex = position347, tokenIndex347
				}
			l348:
			l349:
				{
					position350, tokenIndex350 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l350
					}
					position++
					{
						position351, tokenIndex351 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l351
						}
						goto l352
					l351:
						position, tokenIndex = position351, tokenIndex351
					}
				l352:
					if !_rules[ruleInstructionArg]() {
						goto l350
					}
					goto l349
				l350:
					position, tokenIndex = position350, tokenIndex350
				}
				add(ruleInstruction, position342)
			}
			return true
		l341:
			position, tokenIndex = position341, tokenIndex341
			return false
		},
		/* 26 InstructionName <- <(([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* ('.' / '+' / '-')?)> */
		func() bool {
			position353, tokenIndex353 := position, tokenIndex
			{
				position354 := position
				{
					position355, tokenIndex355 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l356
					}
					position++
					goto l355
				l356:
					position, tokenIndex = position355, tokenIndex355
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l353
					}
					position++
				}
			l355:
			l357:
				{
					position358, tokenIndex358 := position, tokenIndex
					{
						position359, tokenIndex359 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l360
						}
						position++
						goto l359
					l360:
						position, tokenIndex = position359, tokenIndex359
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l361
						}
						position++
						goto l359
					l361:
						position, tokenIndex = position359, tokenIndex359
						{
							position362, tokenIndex362 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l363
							}
							position++
							goto l362
						l363:
							position, tokenIndex = position362, tokenIndex362
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l358
							}
							position++
						}
					l362:
					}
				l359:
					goto l357
				l358:
					position, tokenIndex = position358, tokenIndex358
				}
				{
					position364, tokenIndex364 := position, tokenIndex
					{
						position366, tokenIndex366 := position, tokenIndex
						if buffer[position] != rune('.') {
							goto l367
						}
						position++
						goto l366
					l367:
						position, tokenIndex = position366, tokenIndex366
						if buffer[position] != rune('+') {
							goto l368
						}
						position++
						goto l366
					l368:
						position, tokenIndex = position366, tokenIndex366
						if buffer[position] != rune('-') {
							goto l364
						}
						position++
					}
				l366:
					goto l365
				l364:
					position, tokenIndex = position364, tokenIndex364
				}
			l365:
				add(ruleInstructionName, position354)
			}
			return true
		l353:
			position, tokenIndex = position353, tokenIndex353
			return false
		},
		/* 27 InstructionArg <- <(IndirectionIndicator? (RegisterOrConstant / LocalLabelRef / TOCRefHigh / TOCRefLow / MemoryRef))> */
		func() bool {
			position369, tokenIndex369 := position, tokenIndex
			{
				position370 := position
				{
					position371, tokenIndex371 := position, tokenIndex
					if !_rules[ruleIndirectionIndicator]() {
						goto l371
					}
					goto l372
				l371:
					position, tokenIndex = position371, tokenIndex371
				}
			l372:
				{
					position373, tokenIndex373 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l374
					}
					goto l373
				l374:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleLocalLabelRef]() {
						goto l375
					}
					goto l373
				l375:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleTOCRefHigh]() {
						goto l376
					}
					goto l373
				l376:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleTOCRefLow]() {
						goto l377
					}
					goto l373
				l377:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleMemoryRef]() {
						goto l369
					}
				}
			l373:
				add(ruleInstructionArg, position370)
			}
			return true
		l369:
			position, tokenIndex = position369, tokenIndex369
			return false
		},
		/* 28 TOCRefHigh <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' 'f' 'u' 'n' 'c' '_' 'g' 'e' 'p' [0-9]+)) ('@' ('h' / 'H') ('a' / 'A')))> */
		func() bool {
			position378, tokenIndex378 := position, tokenIndex
			{
				position379 := position
				if buffer[position] != rune('.') {
					goto l378
				}
				position++
				if buffer[position] != rune('T') {
					goto l378
				}
				position++
				if buffer[position] != rune('O') {
					goto l378
				}
				position++
				if buffer[position] != rune('C') {
					goto l378
				}
				position++
				if buffer[position] != rune('.') {
					goto l378
				}
				position++
				if buffer[position] != rune('-') {
					goto l378
				}
				position++
				{
					position380, tokenIndex380 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l381
					}
					position++
					if buffer[position] != rune('b') {
						goto l381
					}
					position++
					goto l380
				l381:
					position, tokenIndex = position380, tokenIndex380
					if buffer[position] != rune('.') {
						goto l378
					}
					position++
					if buffer[position] != rune('L') {
						goto l378
					}
					position++
					if buffer[position] != rune('f') {
						goto l378
					}
					position++
					if buffer[position] != rune('u') {
						goto l378
					}
					position++
					if buffer[position] != rune('n') {
						goto l378
					}
					position++
					if buffer[position] != rune('c') {
						goto l378
					}
					position++
					if buffer[position] != rune('_') {
						goto l378
					}
					position++
					if buffer[position] != rune('g') {
						goto l378
					}
					position++
					if buffer[position] != rune('e') {
						goto l378
					}
					position++
					if buffer[position] != rune('p') {
						goto l378
					}
					position++
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l378
					}
					position++
				l382:
					{
						position383, tokenIndex383 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l383
						}
						position++
						goto l382
					l383:
						position, tokenIndex = position383, tokenIndex383
					}
				}
			l380:
				if buffer[position] != rune('@') {
					goto l378
				}
				position++
				{
					position384, tokenIndex384 := position, tokenIndex
					if buffer[position] != rune('h') {
						goto l385
					}
					position++
					goto l384
				l385:
					position, tokenIndex = position384, tokenIndex384
					if buffer[position] != rune('H') {
						goto l378
					}
					position++
				}
			l384:
				{
					position386, tokenIndex386 := position, tokenIndex
					if buffer[position] != rune('a') {
						goto l387
					}
					position++
					goto l386
				l387:
					position, tokenIndex = position386, tokenIndex386
					if buffer[position] != rune('A') {
						goto l378
					}
					position++
				}
			l386:
				add(ruleTOCRefHigh, position379)
			}
			return true
		l378:
			position, tokenIndex = position378, tokenIndex378
			return false
		},
		/* 29 TOCRefLow <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' 'f' 'u' 'n' 'c' '_' 'g' 'e' 'p' [0-9]+)) ('@' ('l' / 'L')))> */
		func() bool {
			position388, tokenIndex388 := position, tokenIndex
			{
				position389 := position
				if buffer[position] != rune('.') {
					goto l388
				}
				position++
				if buffer[position] != rune('T') {
					goto l388
				}
				position++
				if buffer[position] != rune('O') {
					goto l388
				}
				position++
				if buffer[position] != rune('C') {
					goto l388
				}
				position++
				if buffer[position] != rune('.') {
					goto l388
				}
				position++
				if buffer[position] != rune('-') {
					goto l388
				}
				position++
				{
					position390, tokenIndex390 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l391
					}
					position++
					if buffer[position] != rune('b') {
						goto l391
					}
					position++
					goto l390
				l391:
					position, tokenIndex = position390, tokenIndex390
					if buffer[position] != rune('.') {
						goto l388
					}
					position++
					if buffer[position] != rune('L') {
						goto l388
					}
					position++
					if buffer[position] != rune('f') {
						goto l388
					}
					position++
					if buffer[position] != rune('u') {
						goto l388
					}
					position++
					if buffer[position] != rune('n') {
						goto l388
					}
					position++
					if buffer[position] != rune('c') {
						goto l388
					}
					position++
					if buffer[position] != rune('_') {
						goto l388
					}
					position++
					if buffer[position] != rune('g') {
						goto l388
					}
					position++
					if buffer[position] != rune('e') {
						goto l388
					}
					position++
					if buffer[position] != rune('p') {
						goto l388
					}
					position++
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l388
					}
					position++
				l392:
					{
						position393, tokenIndex393 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l393
						}
						position++
						goto l392
					l393:
						position, tokenIndex = position393, tokenIndex393
					}
				}
			l390:
				if buffer[position] != rune('@') {
					goto l388
				}
				position++
				{
					position394, tokenIndex394 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l395
					}
					position++
					goto l394
				l395:
					position, tokenIndex = position394, tokenIndex394
					if buffer[position] != rune('L') {
						goto l388
					}
					position++
				}
			l394:
				add(ruleTOCRefLow, position389)
			}
			return true
		l388:
			position, tokenIndex = position388, tokenIndex388
			return false
		},
		/* 30 IndirectionIndicator <- <'*'> */
		func() bool {
			position396, tokenIndex396 := position, tokenIndex
			{
				position397 := position
				if buffer[position] != rune('*') {
					goto l396
				}
				position++
				add(ruleIndirectionIndicator, position397)
			}
			return true
		l396:
			position, tokenIndex = position396, tokenIndex396
			return false
		},
		/* 31 RegisterOrConstant <- <((('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))*) / ('$'? ((Offset Offset) / Offset))) !('f' / 'b' / ':' / '(' / '+' / '-'))> */
		func() bool {
			position398, tokenIndex398 := position, tokenIndex
			{
				position399 := position
				{
					position400, tokenIndex400 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l401
					}
					position++
					{
						position402, tokenIndex402 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l403
						}
						position++
						goto l402
					l403:
						position, tokenIndex = position402, tokenIndex402
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l401
						}
						position++
					}
				l402:
				l404:
					{
						position405, tokenIndex405 := position, tokenIndex
						{
							position406, tokenIndex406 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l407
							}
							position++
							goto l406
						l407:
							position, tokenIndex = position406, tokenIndex406
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l408
							}
							position++
							goto l406
						l408:
							position, tokenIndex = position406, tokenIndex406
							{
								position409, tokenIndex409 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l410
								}
								position++
								goto l409
							l410:
								position, tokenIndex = position409, tokenIndex409
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l405
								}
								position++
							}
						l409:
						}
					l406:
						goto l404
					l405:
						position, tokenIndex = position405, tokenIndex405
					}
					goto l400
				l401:
					position, tokenIndex = position400, tokenIndex400
					{
						position411, tokenIndex411 := position, tokenIndex
						if buffer[position] != rune('$') {
							goto l411
						}
						position++
						goto l412
					l411:
						position, tokenIndex = position411, tokenIndex411
					}
				l412:
					{
						position413, tokenIndex413 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l414
						}
						if !_rules[ruleOffset]() {
							goto l414
						}
						goto l413
					l414:
						position, tokenIndex = position413, tokenIndex413
						if !_rules[ruleOffset]() {
							goto l398
						}
					}
				l413:
				}
			l400:
				{
					position415, tokenIndex415 := position, tokenIndex
					{
						position416, tokenIndex416 := position, tokenIndex
						if buffer[position] != rune('f') {
							goto l417
						}
						position++
						goto l416
					l417:
						position, tokenIndex = position416, tokenIndex416
						if buffer[position] != rune('b') {
							goto l418
						}
						position++
						goto l416
					l418:
						position, tokenIndex = position416, tokenIndex416
						if buffer[position] != rune(':') {
							goto l419
						}
						position++
						goto l416
					l419:
						position, tokenIndex = position416, tokenIndex416
						if buffer[position] != rune('(') {
							goto l420
						}
						position++
						goto l416
					l420:
						position, tokenIndex = position416, tokenIndex416
						if buffer[position] != rune('+') {
							goto l421
						}
						position++
						goto l416
					l421:
						position, tokenIndex = position416, tokenIndex416
						if buffer[position] != rune('-') {
							goto l415
						}
						position++
					}
				l416:
					goto l398
				l415:
					position, tokenIndex = position415, tokenIndex415
				}
				add(ruleRegisterOrConstant, position399)
			}
			return true
		l398:
			position, tokenIndex = position398, tokenIndex398
			return false
		},
		/* 32 MemoryRef <- <((Offset Operator SymbolRef BaseIndexScale) / (SymbolRef Operator Offset BaseIndexScale) / (SymbolRef BaseIndexScale) / (Offset BaseIndexScale) / (Offset Operator Offset BaseIndexScale) / (SymbolRef Operator Offset Operator Offset BaseIndexScale) / (Offset Operator Offset Operator Offset BaseIndexScale) / SymbolRef / BaseIndexScale / (SegmentRegister Offset BaseIndexScale) / (SegmentRegister BaseIndexScale) / Absolute)> */
		func() bool {
			position422, tokenIndex422 := position, tokenIndex
			{
				position423 := position
				{
					position424, tokenIndex424 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l425
					}
					if !_rules[ruleOperator]() {
						goto l425
					}
					if !_rules[ruleSymbolRef]() {
						goto l425
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l425
					}
					goto l424
				l425:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleSymbolRef]() {
						goto l426
					}
					if !_rules[ruleOperator]() {
						goto l426
					}
					if !_rules[ruleOffset]() {
						goto l426
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l426
					}
					goto l424
				l426:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleSymbolRef]() {
						goto l427
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l427
					}
					goto l424
				l427:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleOffset]() {
						goto l428
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l428
					}
					goto l424
				l428:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleOffset]() {
						goto l429
					}
					if !_rules[ruleOperator]() {
						goto l429
					}
					if !_rules[ruleOffset]() {
						goto l429
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l429
					}
					goto l424
				l429:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleSymbolRef]() {
						goto l430
					}
					if !_rules[ruleOperator]() {
						goto l430
					}
					if !_rules[ruleOffset]() {
						goto l430
					}
					if !_rules[ruleOperator]() {
						goto l430
					}
					if !_rules[ruleOffset]() {
						goto l430
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l430
					}
					goto l424
				l430:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleOffset]() {
						goto l431
					}
					if !_rules[ruleOperator]() {
						goto l431
					}
					if !_rules[ruleOffset]() {
						goto l431
					}
					if !_rules[ruleOperator]() {
						goto l431
					}
					if !_rules[ruleOffset]() {
						goto l431
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l431
					}
					goto l424
				l431:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleSymbolRef]() {
						goto l432
					}
					goto l424
				l432:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleBaseIndexScale]() {
						goto l433
					}
					goto l424
				l433:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleSegmentRegister]() {
						goto l434
					}
					if !_rules[ruleOffset]() {
						goto l434
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l434
					}
					goto l424
				l434:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleSegmentRegister]() {
						goto l435
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l435
					}
					goto l424
				l435:
					position, tokenIndex = position424, tokenIndex424
					if !_rules[ruleAbsolute]() {
						goto l422
					}
				}
			l424:
				add(ruleMemoryRef, position423)
			}
			return true
		l422:
			position, tokenIndex = position422, tokenIndex422
			return false
		},
		/* 33 SymbolRef <- <((LocalSymbol / SymbolName) Offset? ('@' Section)?)> */
		func() bool {
			position436, tokenIndex436 := position, tokenIndex
			{
				position437 := position
				{
					position438, tokenIndex438 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l439
					}
					goto l438
				l439:
					position, tokenIndex = position438, tokenIndex438
					if !_rules[ruleSymbolName]() {
						goto l436
					}
				}
			l438:
				{
					position440, tokenIndex440 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l440
					}
					goto l441
				l440:
					position, tokenIndex = position440, tokenIndex440
				}
			l441:
				{
					position442, tokenIndex442 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l442
					}
					position++
					if !_rules[ruleSection]() {
						goto l442
					}
					goto l443
				l442:
					position, tokenIndex = position442, tokenIndex442
				}
			l443:
				add(ruleSymbolRef, position437)
			}
			return true
		l436:
			position, tokenIndex = position436, tokenIndex436
			return false
		},
		/* 34 BaseIndexScale <- <('(' RegisterOrConstant? WS? (',' WS? RegisterOrConstant WS? (',' [0-9]+)?)? ')')> */
		func() bool {
			position444, tokenIndex444 := position, tokenIndex
			{
				position445 := position
				if buffer[position] != rune('(') {
					goto l444
				}
				position++
				{
					position446, tokenIndex446 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l446
					}
					goto l447
				l446:
					position, tokenIndex = position446, tokenIndex446
				}
			l447:
				{
					position448, tokenIndex448 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l448
					}
					goto l449
				l448:
					position, tokenIndex = position448, tokenIndex448
				}
			l449:
				{
					position450, tokenIndex450 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l450
					}
					position++
					{
						position452, tokenIndex452 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l452
						}
						goto l453
					l452:
						position, tokenIndex = position452, tokenIndex452
					}
				l453:
					if !_rules[ruleRegisterOrConstant]() {
						goto l450
					}
					{
						position454, tokenIndex454 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l454
						}
						goto l455
					l454:
						position, tokenIndex = position454, tokenIndex454
					}
				l455:
					{
						position456, tokenIndex456 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l456
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l456
						}
						position++
					l458:
						{
							position459, tokenIndex459 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l459
							}
							position++
							goto l458
						l459:
							position, tokenIndex = position459, tokenIndex459
						}
						goto l457
					l456:
						position, tokenIndex = position456, tokenIndex456
					}
				l457:
					goto l451
				l450:
					position, tokenIndex = position450, tokenIndex450
				}
			l451:
				if buffer[position] != rune(')') {
					goto l444
				}
				position++
				add(ruleBaseIndexScale, position445)
			}
			return true
		l444:
			position, tokenIndex = position444, tokenIndex444
			return false
		},
		/* 35 Operator <- <('+' / '-')> */
		func() bool {
			position460, tokenIndex460 := position, tokenIndex
			{
				position461 := position
				{
					position462, tokenIndex462 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l463
					}
					position++
					goto l462
				l463:
					position, tokenIndex = position462, tokenIndex462
					if buffer[position] != rune('-') {
						goto l460
					}
					position++
				}
			l462:
				add(ruleOperator, position461)
			}
			return true
		l460:
			position, tokenIndex = position460, tokenIndex460
			return false
		},
		/* 36 Offset <- <(('+' / '-')? (('0' 'x' ([0-9] / [0-9] / ([a-f] / [A-F]))+) / [0-9]+))> */
		func() bool {
			position464, tokenIndex464 := position, tokenIndex
			{
				position465 := position
				{
					position466, tokenIndex466 := position, tokenIndex
					{
						position468, tokenIndex468 := position, tokenIndex
						if buffer[position] != rune('+') {
							goto l469
						}
						position++
						goto l468
					l469:
						position, tokenIndex = position468, tokenIndex468
						if buffer[position] != rune('-') {
							goto l466
						}
						position++
					}
				l468:
					goto l467
				l466:
					position, tokenIndex = position466, tokenIndex466
				}
			l467:
				{
					position470, tokenIndex470 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l471
					}
					position++
					if buffer[position] != rune('x') {
						goto l471
					}
					position++
					{
						position474, tokenIndex474 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l475
						}
						position++
						goto l474
					l475:
						position, tokenIndex = position474, tokenIndex474
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l476
						}
						position++
						goto l474
					l476:
						position, tokenIndex = position474, tokenIndex474
						{
							position477, tokenIndex477 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('f') {
								goto l478
							}
							position++
							goto l477
						l478:
							position, tokenIndex = position477, tokenIndex477
							if c := buffer[position]; c < rune('A') || c > rune('F') {
								goto l471
							}
							position++
						}
					l477:
					}
				l474:
				l472:
					{
						position473, tokenIndex473 := position, tokenIndex
						{
							position479, tokenIndex479 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l480
							}
							position++
							goto l479
						l480:
							position, tokenIndex = position479, tokenIndex479
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l481
							}
							position++
							goto l479
						l481:
							position, tokenIndex = position479, tokenIndex479
							{
								position482, tokenIndex482 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('f') {
									goto l483
								}
								position++
								goto l482
							l483:
								position, tokenIndex = position482, tokenIndex482
								if c := buffer[position]; c < rune('A') || c > rune('F') {
									goto l473
								}
								position++
							}
						l482:
						}
					l479:
						goto l472
					l473:
						position, tokenIndex = position473, tokenIndex473
					}
					goto l470
				l471:
					position, tokenIndex = position470, tokenIndex470
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l464
					}
					position++
				l484:
					{
						position485, tokenIndex485 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l485
						}
						position++
						goto l484
					l485:
						position, tokenIndex = position485, tokenIndex485
					}
				}
			l470:
				add(ruleOffset, position465)
			}
			return true
		l464:
			position, tokenIndex = position464, tokenIndex464
			return false
		},
		/* 37 Absolute <- <(('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* ':')? [0-9]+)> */
		func() bool {
			position486, tokenIndex486 := position, tokenIndex
			{
				position487 := position
				{
					position488, tokenIndex488 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l488
					}
					position++
					{
						position490, tokenIndex490 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l491
						}
						position++
						goto l490
					l491:
						position, tokenIndex = position490, tokenIndex490
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l488
						}
						position++
					}
				l490:
				l492:
					{
						position493, tokenIndex493 := position, tokenIndex
						{
							position494, tokenIndex494 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l495
							}
							position++
							goto l494
						l495:
							position, tokenIndex = position494, tokenIndex494
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l496
							}
							position++
							goto l494
						l496:
							position, tokenIndex = position494, tokenIndex494
							{
								position497, tokenIndex497 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l498
								}
								position++
								goto l497
							l498:
								position, tokenIndex = position497, tokenIndex497
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l493
								}
								position++
							}
						l497:
						}
					l494:
						goto l492
					l493:
						position, tokenIndex = position493, tokenIndex493
					}
					if buffer[position] != rune(':') {
						goto l488
					}
					position++
					goto l489
				l488:
					position, tokenIndex = position488, tokenIndex488
				}
			l489:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l486
				}
				position++
			l499:
				{
					position500, tokenIndex500 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l500
					}
					position++
					goto l499
				l500:
					position, tokenIndex = position500, tokenIndex500
				}
				add(ruleAbsolute, position487)
			}
			return true
		l486:
			position, tokenIndex = position486, tokenIndex486
			return false
		},
		/* 38 Section <- <([a-z] / [A-Z] / '@')+> */
		func() bool {
			position501, tokenIndex501 := position, tokenIndex
			{
				position502 := position
				{
					position505, tokenIndex505 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l506
					}
					position++
					goto l505
				l506:
					position, tokenIndex = position505, tokenIndex505
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l507
					}
					position++
					goto l505
				l507:
					position, tokenIndex = position505, tokenIndex505
					if buffer[position] != rune('@') {
						goto l501
					}
					position++
				}
			l505:
			l503:
				{
					position504, tokenIndex504 := position, tokenIndex
					{
						position508, tokenIndex508 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l509
						}
						position++
						goto l508
					l509:
						position, tokenIndex = position508, tokenIndex508
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l510
						}
						position++
						goto l508
					l510:
						position, tokenIndex = position508, tokenIndex508
						if buffer[position] != rune('@') {
							goto l504
						}
						position++
					}
				l508:
					goto l503
				l504:
					position, tokenIndex = position504, tokenIndex504
				}
				add(ruleSection, position502)
			}
			return true
		l501:
			position, tokenIndex = position501, tokenIndex501
			return false
		},
		/* 39 SegmentRegister <- <('%' ([c-g] / 's') ('s' ':'))> */
		func() bool {
			position511, tokenIndex511 := position, tokenIndex
			{
				position512 := position
				if buffer[position] != rune('%') {
					goto l511
				}
				position++
				{
					position513, tokenIndex513 := position, tokenIndex
					if c := buffer[position]; c < rune('c') || c > rune('g') {
						goto l514
					}
					position++
					goto l513
				l514:
					position, tokenIndex = position513, tokenIndex513
					if buffer[position] != rune('s') {
						goto l511
					}
					position++
				}
			l513:
				if buffer[position] != rune('s') {
					goto l511
				}
				position++
				if buffer[position] != rune(':') {
					goto l511
				}
				position++
				add(ruleSegmentRegister, position512)
			}
			return true
		l511:
			position, tokenIndex = position511, tokenIndex511
			return false
		},
	}
	p.rules = _rules
}
