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
	rules  [37]func() bool
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
		/* 1 Statement <- <(WS? (Label / (((GlobalDirective / LocationDirective / LabelContainingDirective / Instruction / Directive / Comment / ) WS? (Comment? '\n')) / ';')))> */
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
						{
							position13, tokenIndex13 := position, tokenIndex
							if !_rules[ruleGlobalDirective]() {
								goto l14
							}
							goto l13
						l14:
							position, tokenIndex = position13, tokenIndex13
							if !_rules[ruleLocationDirective]() {
								goto l15
							}
							goto l13
						l15:
							position, tokenIndex = position13, tokenIndex13
							if !_rules[ruleLabelContainingDirective]() {
								goto l16
							}
							goto l13
						l16:
							position, tokenIndex = position13, tokenIndex13
							if !_rules[ruleInstruction]() {
								goto l17
							}
							goto l13
						l17:
							position, tokenIndex = position13, tokenIndex13
							if !_rules[ruleDirective]() {
								goto l18
							}
							goto l13
						l18:
							position, tokenIndex = position13, tokenIndex13
							if !_rules[ruleComment]() {
								goto l19
							}
							goto l13
						l19:
							position, tokenIndex = position13, tokenIndex13
						}
					l13:
						{
							position20, tokenIndex20 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l20
							}
							goto l21
						l20:
							position, tokenIndex = position20, tokenIndex20
						}
					l21:
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
							goto l12
						}
						position++
						goto l11
					l12:
						position, tokenIndex = position11, tokenIndex11
						if buffer[position] != rune(';') {
							goto l5
						}
						position++
					}
				l11:
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
		/* 11 LabelContainingDirectiveName <- <(('.' ('l' / 'L') ('o' / 'O') ('n' / 'N') ('g' / 'G')) / ('.' ('s' / 'S') ('e' / 'E') ('t' / 'T')) / ('.' '8' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' '4' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' ('q' / 'Q') ('u' / 'U') ('a' / 'A') ('d' / 'D')))> */
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
						goto l143
					}
					position++
					{
						position180, tokenIndex180 := position, tokenIndex
						if buffer[position] != rune('q') {
							goto l181
						}
						position++
						goto l180
					l181:
						position, tokenIndex = position180, tokenIndex180
						if buffer[position] != rune('Q') {
							goto l143
						}
						position++
					}
				l180:
					{
						position182, tokenIndex182 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l183
						}
						position++
						goto l182
					l183:
						position, tokenIndex = position182, tokenIndex182
						if buffer[position] != rune('U') {
							goto l143
						}
						position++
					}
				l182:
					{
						position184, tokenIndex184 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l185
						}
						position++
						goto l184
					l185:
						position, tokenIndex = position184, tokenIndex184
						if buffer[position] != rune('A') {
							goto l143
						}
						position++
					}
				l184:
					{
						position186, tokenIndex186 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l187
						}
						position++
						goto l186
					l187:
						position, tokenIndex = position186, tokenIndex186
						if buffer[position] != rune('D') {
							goto l143
						}
						position++
					}
				l186:
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
			position188, tokenIndex188 := position, tokenIndex
			{
				position189 := position
				if !_rules[ruleSymbolArg]() {
					goto l188
				}
			l190:
				{
					position191, tokenIndex191 := position, tokenIndex
					{
						position192, tokenIndex192 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l192
						}
						goto l193
					l192:
						position, tokenIndex = position192, tokenIndex192
					}
				l193:
					if buffer[position] != rune(',') {
						goto l191
					}
					position++
					{
						position194, tokenIndex194 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l194
						}
						goto l195
					l194:
						position, tokenIndex = position194, tokenIndex194
					}
				l195:
					if !_rules[ruleSymbolArg]() {
						goto l191
					}
					goto l190
				l191:
					position, tokenIndex = position191, tokenIndex191
				}
				add(ruleSymbolArgs, position189)
			}
			return true
		l188:
			position, tokenIndex = position188, tokenIndex188
			return false
		},
		/* 13 SymbolArg <- <(Offset / (LocalSymbol Operator LocalSymbol) / (LocalSymbol Operator Offset) / (Offset Operator LocalSymbol) / LocalSymbol)> */
		func() bool {
			position196, tokenIndex196 := position, tokenIndex
			{
				position197 := position
				{
					position198, tokenIndex198 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l199
					}
					goto l198
				l199:
					position, tokenIndex = position198, tokenIndex198
					if !_rules[ruleLocalSymbol]() {
						goto l200
					}
					if !_rules[ruleOperator]() {
						goto l200
					}
					if !_rules[ruleLocalSymbol]() {
						goto l200
					}
					goto l198
				l200:
					position, tokenIndex = position198, tokenIndex198
					if !_rules[ruleLocalSymbol]() {
						goto l201
					}
					if !_rules[ruleOperator]() {
						goto l201
					}
					if !_rules[ruleOffset]() {
						goto l201
					}
					goto l198
				l201:
					position, tokenIndex = position198, tokenIndex198
					if !_rules[ruleOffset]() {
						goto l202
					}
					if !_rules[ruleOperator]() {
						goto l202
					}
					if !_rules[ruleLocalSymbol]() {
						goto l202
					}
					goto l198
				l202:
					position, tokenIndex = position198, tokenIndex198
					if !_rules[ruleLocalSymbol]() {
						goto l196
					}
				}
			l198:
				add(ruleSymbolArg, position197)
			}
			return true
		l196:
			position, tokenIndex = position196, tokenIndex196
			return false
		},
		/* 14 EscapedChar <- <('\\' .)> */
		func() bool {
			position203, tokenIndex203 := position, tokenIndex
			{
				position204 := position
				if buffer[position] != rune('\\') {
					goto l203
				}
				position++
				if !matchDot() {
					goto l203
				}
				add(ruleEscapedChar, position204)
			}
			return true
		l203:
			position, tokenIndex = position203, tokenIndex203
			return false
		},
		/* 15 WS <- <(' ' / '\t')+> */
		func() bool {
			position205, tokenIndex205 := position, tokenIndex
			{
				position206 := position
				{
					position209, tokenIndex209 := position, tokenIndex
					if buffer[position] != rune(' ') {
						goto l210
					}
					position++
					goto l209
				l210:
					position, tokenIndex = position209, tokenIndex209
					if buffer[position] != rune('\t') {
						goto l205
					}
					position++
				}
			l209:
			l207:
				{
					position208, tokenIndex208 := position, tokenIndex
					{
						position211, tokenIndex211 := position, tokenIndex
						if buffer[position] != rune(' ') {
							goto l212
						}
						position++
						goto l211
					l212:
						position, tokenIndex = position211, tokenIndex211
						if buffer[position] != rune('\t') {
							goto l208
						}
						position++
					}
				l211:
					goto l207
				l208:
					position, tokenIndex = position208, tokenIndex208
				}
				add(ruleWS, position206)
			}
			return true
		l205:
			position, tokenIndex = position205, tokenIndex205
			return false
		},
		/* 16 Comment <- <('#' (!'\n' .)*)> */
		func() bool {
			position213, tokenIndex213 := position, tokenIndex
			{
				position214 := position
				if buffer[position] != rune('#') {
					goto l213
				}
				position++
			l215:
				{
					position216, tokenIndex216 := position, tokenIndex
					{
						position217, tokenIndex217 := position, tokenIndex
						if buffer[position] != rune('\n') {
							goto l217
						}
						position++
						goto l216
					l217:
						position, tokenIndex = position217, tokenIndex217
					}
					if !matchDot() {
						goto l216
					}
					goto l215
				l216:
					position, tokenIndex = position216, tokenIndex216
				}
				add(ruleComment, position214)
			}
			return true
		l213:
			position, tokenIndex = position213, tokenIndex213
			return false
		},
		/* 17 Label <- <((LocalSymbol / LocalLabel / SymbolName) ':')> */
		func() bool {
			position218, tokenIndex218 := position, tokenIndex
			{
				position219 := position
				{
					position220, tokenIndex220 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l221
					}
					goto l220
				l221:
					position, tokenIndex = position220, tokenIndex220
					if !_rules[ruleLocalLabel]() {
						goto l222
					}
					goto l220
				l222:
					position, tokenIndex = position220, tokenIndex220
					if !_rules[ruleSymbolName]() {
						goto l218
					}
				}
			l220:
				if buffer[position] != rune(':') {
					goto l218
				}
				position++
				add(ruleLabel, position219)
			}
			return true
		l218:
			position, tokenIndex = position218, tokenIndex218
			return false
		},
		/* 18 SymbolName <- <(([a-z] / [A-Z] / '.' / '_') ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')*)> */
		func() bool {
			position223, tokenIndex223 := position, tokenIndex
			{
				position224 := position
				{
					position225, tokenIndex225 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l226
					}
					position++
					goto l225
				l226:
					position, tokenIndex = position225, tokenIndex225
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l227
					}
					position++
					goto l225
				l227:
					position, tokenIndex = position225, tokenIndex225
					if buffer[position] != rune('.') {
						goto l228
					}
					position++
					goto l225
				l228:
					position, tokenIndex = position225, tokenIndex225
					if buffer[position] != rune('_') {
						goto l223
					}
					position++
				}
			l225:
			l229:
				{
					position230, tokenIndex230 := position, tokenIndex
					{
						position231, tokenIndex231 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l232
						}
						position++
						goto l231
					l232:
						position, tokenIndex = position231, tokenIndex231
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l233
						}
						position++
						goto l231
					l233:
						position, tokenIndex = position231, tokenIndex231
						if buffer[position] != rune('.') {
							goto l234
						}
						position++
						goto l231
					l234:
						position, tokenIndex = position231, tokenIndex231
						{
							position236, tokenIndex236 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l237
							}
							position++
							goto l236
						l237:
							position, tokenIndex = position236, tokenIndex236
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l235
							}
							position++
						}
					l236:
						goto l231
					l235:
						position, tokenIndex = position231, tokenIndex231
						if buffer[position] != rune('$') {
							goto l238
						}
						position++
						goto l231
					l238:
						position, tokenIndex = position231, tokenIndex231
						if buffer[position] != rune('_') {
							goto l230
						}
						position++
					}
				l231:
					goto l229
				l230:
					position, tokenIndex = position230, tokenIndex230
				}
				add(ruleSymbolName, position224)
			}
			return true
		l223:
			position, tokenIndex = position223, tokenIndex223
			return false
		},
		/* 19 LocalSymbol <- <('.' 'L' ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')+)> */
		func() bool {
			position239, tokenIndex239 := position, tokenIndex
			{
				position240 := position
				if buffer[position] != rune('.') {
					goto l239
				}
				position++
				if buffer[position] != rune('L') {
					goto l239
				}
				position++
				{
					position243, tokenIndex243 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l244
					}
					position++
					goto l243
				l244:
					position, tokenIndex = position243, tokenIndex243
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l245
					}
					position++
					goto l243
				l245:
					position, tokenIndex = position243, tokenIndex243
					if buffer[position] != rune('.') {
						goto l246
					}
					position++
					goto l243
				l246:
					position, tokenIndex = position243, tokenIndex243
					{
						position248, tokenIndex248 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l249
						}
						position++
						goto l248
					l249:
						position, tokenIndex = position248, tokenIndex248
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l247
						}
						position++
					}
				l248:
					goto l243
				l247:
					position, tokenIndex = position243, tokenIndex243
					if buffer[position] != rune('$') {
						goto l250
					}
					position++
					goto l243
				l250:
					position, tokenIndex = position243, tokenIndex243
					if buffer[position] != rune('_') {
						goto l239
					}
					position++
				}
			l243:
			l241:
				{
					position242, tokenIndex242 := position, tokenIndex
					{
						position251, tokenIndex251 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l252
						}
						position++
						goto l251
					l252:
						position, tokenIndex = position251, tokenIndex251
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l253
						}
						position++
						goto l251
					l253:
						position, tokenIndex = position251, tokenIndex251
						if buffer[position] != rune('.') {
							goto l254
						}
						position++
						goto l251
					l254:
						position, tokenIndex = position251, tokenIndex251
						{
							position256, tokenIndex256 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l257
							}
							position++
							goto l256
						l257:
							position, tokenIndex = position256, tokenIndex256
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l255
							}
							position++
						}
					l256:
						goto l251
					l255:
						position, tokenIndex = position251, tokenIndex251
						if buffer[position] != rune('$') {
							goto l258
						}
						position++
						goto l251
					l258:
						position, tokenIndex = position251, tokenIndex251
						if buffer[position] != rune('_') {
							goto l242
						}
						position++
					}
				l251:
					goto l241
				l242:
					position, tokenIndex = position242, tokenIndex242
				}
				add(ruleLocalSymbol, position240)
			}
			return true
		l239:
			position, tokenIndex = position239, tokenIndex239
			return false
		},
		/* 20 LocalLabel <- <([0-9] ([0-9] / '$')*)> */
		func() bool {
			position259, tokenIndex259 := position, tokenIndex
			{
				position260 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l259
				}
				position++
			l261:
				{
					position262, tokenIndex262 := position, tokenIndex
					{
						position263, tokenIndex263 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l264
						}
						position++
						goto l263
					l264:
						position, tokenIndex = position263, tokenIndex263
						if buffer[position] != rune('$') {
							goto l262
						}
						position++
					}
				l263:
					goto l261
				l262:
					position, tokenIndex = position262, tokenIndex262
				}
				add(ruleLocalLabel, position260)
			}
			return true
		l259:
			position, tokenIndex = position259, tokenIndex259
			return false
		},
		/* 21 LocalLabelRef <- <([0-9] ([0-9] / '$')* ('b' / 'f'))> */
		func() bool {
			position265, tokenIndex265 := position, tokenIndex
			{
				position266 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l265
				}
				position++
			l267:
				{
					position268, tokenIndex268 := position, tokenIndex
					{
						position269, tokenIndex269 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l270
						}
						position++
						goto l269
					l270:
						position, tokenIndex = position269, tokenIndex269
						if buffer[position] != rune('$') {
							goto l268
						}
						position++
					}
				l269:
					goto l267
				l268:
					position, tokenIndex = position268, tokenIndex268
				}
				{
					position271, tokenIndex271 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l272
					}
					position++
					goto l271
				l272:
					position, tokenIndex = position271, tokenIndex271
					if buffer[position] != rune('f') {
						goto l265
					}
					position++
				}
			l271:
				add(ruleLocalLabelRef, position266)
			}
			return true
		l265:
			position, tokenIndex = position265, tokenIndex265
			return false
		},
		/* 22 Instruction <- <(InstructionName WS? InstructionArg? WS? (',' WS? InstructionArg)*)> */
		func() bool {
			position273, tokenIndex273 := position, tokenIndex
			{
				position274 := position
				if !_rules[ruleInstructionName]() {
					goto l273
				}
				{
					position275, tokenIndex275 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l275
					}
					goto l276
				l275:
					position, tokenIndex = position275, tokenIndex275
				}
			l276:
				{
					position277, tokenIndex277 := position, tokenIndex
					if !_rules[ruleInstructionArg]() {
						goto l277
					}
					goto l278
				l277:
					position, tokenIndex = position277, tokenIndex277
				}
			l278:
				{
					position279, tokenIndex279 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l279
					}
					goto l280
				l279:
					position, tokenIndex = position279, tokenIndex279
				}
			l280:
			l281:
				{
					position282, tokenIndex282 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l282
					}
					position++
					{
						position283, tokenIndex283 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l283
						}
						goto l284
					l283:
						position, tokenIndex = position283, tokenIndex283
					}
				l284:
					if !_rules[ruleInstructionArg]() {
						goto l282
					}
					goto l281
				l282:
					position, tokenIndex = position282, tokenIndex282
				}
				add(ruleInstruction, position274)
			}
			return true
		l273:
			position, tokenIndex = position273, tokenIndex273
			return false
		},
		/* 23 InstructionName <- <(([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* '.'?)> */
		func() bool {
			position285, tokenIndex285 := position, tokenIndex
			{
				position286 := position
				{
					position287, tokenIndex287 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l288
					}
					position++
					goto l287
				l288:
					position, tokenIndex = position287, tokenIndex287
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l285
					}
					position++
				}
			l287:
			l289:
				{
					position290, tokenIndex290 := position, tokenIndex
					{
						position291, tokenIndex291 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l292
						}
						position++
						goto l291
					l292:
						position, tokenIndex = position291, tokenIndex291
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l293
						}
						position++
						goto l291
					l293:
						position, tokenIndex = position291, tokenIndex291
						{
							position294, tokenIndex294 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l295
							}
							position++
							goto l294
						l295:
							position, tokenIndex = position294, tokenIndex294
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l290
							}
							position++
						}
					l294:
					}
				l291:
					goto l289
				l290:
					position, tokenIndex = position290, tokenIndex290
				}
				{
					position296, tokenIndex296 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l296
					}
					position++
					goto l297
				l296:
					position, tokenIndex = position296, tokenIndex296
				}
			l297:
				add(ruleInstructionName, position286)
			}
			return true
		l285:
			position, tokenIndex = position285, tokenIndex285
			return false
		},
		/* 24 InstructionArg <- <(IndirectionIndicator? (RegisterOrConstant / LocalLabelRef / TOCRefHigh / TOCRefLow / MemoryRef))> */
		func() bool {
			position298, tokenIndex298 := position, tokenIndex
			{
				position299 := position
				{
					position300, tokenIndex300 := position, tokenIndex
					if !_rules[ruleIndirectionIndicator]() {
						goto l300
					}
					goto l301
				l300:
					position, tokenIndex = position300, tokenIndex300
				}
			l301:
				{
					position302, tokenIndex302 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l303
					}
					goto l302
				l303:
					position, tokenIndex = position302, tokenIndex302
					if !_rules[ruleLocalLabelRef]() {
						goto l304
					}
					goto l302
				l304:
					position, tokenIndex = position302, tokenIndex302
					if !_rules[ruleTOCRefHigh]() {
						goto l305
					}
					goto l302
				l305:
					position, tokenIndex = position302, tokenIndex302
					if !_rules[ruleTOCRefLow]() {
						goto l306
					}
					goto l302
				l306:
					position, tokenIndex = position302, tokenIndex302
					if !_rules[ruleMemoryRef]() {
						goto l298
					}
				}
			l302:
				add(ruleInstructionArg, position299)
			}
			return true
		l298:
			position, tokenIndex = position298, tokenIndex298
			return false
		},
		/* 25 TOCRefHigh <- <('.' ('t' / 'T') ('o' / 'O') ('c' / 'C') '.' '-' '0' ('b' / 'B') '@' ('h' / 'H') ('a' / 'A'))> */
		func() bool {
			position307, tokenIndex307 := position, tokenIndex
			{
				position308 := position
				if buffer[position] != rune('.') {
					goto l307
				}
				position++
				{
					position309, tokenIndex309 := position, tokenIndex
					if buffer[position] != rune('t') {
						goto l310
					}
					position++
					goto l309
				l310:
					position, tokenIndex = position309, tokenIndex309
					if buffer[position] != rune('T') {
						goto l307
					}
					position++
				}
			l309:
				{
					position311, tokenIndex311 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l312
					}
					position++
					goto l311
				l312:
					position, tokenIndex = position311, tokenIndex311
					if buffer[position] != rune('O') {
						goto l307
					}
					position++
				}
			l311:
				{
					position313, tokenIndex313 := position, tokenIndex
					if buffer[position] != rune('c') {
						goto l314
					}
					position++
					goto l313
				l314:
					position, tokenIndex = position313, tokenIndex313
					if buffer[position] != rune('C') {
						goto l307
					}
					position++
				}
			l313:
				if buffer[position] != rune('.') {
					goto l307
				}
				position++
				if buffer[position] != rune('-') {
					goto l307
				}
				position++
				if buffer[position] != rune('0') {
					goto l307
				}
				position++
				{
					position315, tokenIndex315 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l316
					}
					position++
					goto l315
				l316:
					position, tokenIndex = position315, tokenIndex315
					if buffer[position] != rune('B') {
						goto l307
					}
					position++
				}
			l315:
				if buffer[position] != rune('@') {
					goto l307
				}
				position++
				{
					position317, tokenIndex317 := position, tokenIndex
					if buffer[position] != rune('h') {
						goto l318
					}
					position++
					goto l317
				l318:
					position, tokenIndex = position317, tokenIndex317
					if buffer[position] != rune('H') {
						goto l307
					}
					position++
				}
			l317:
				{
					position319, tokenIndex319 := position, tokenIndex
					if buffer[position] != rune('a') {
						goto l320
					}
					position++
					goto l319
				l320:
					position, tokenIndex = position319, tokenIndex319
					if buffer[position] != rune('A') {
						goto l307
					}
					position++
				}
			l319:
				add(ruleTOCRefHigh, position308)
			}
			return true
		l307:
			position, tokenIndex = position307, tokenIndex307
			return false
		},
		/* 26 TOCRefLow <- <('.' ('t' / 'T') ('o' / 'O') ('c' / 'C') '.' '-' '0' ('b' / 'B') '@' ('l' / 'L'))> */
		func() bool {
			position321, tokenIndex321 := position, tokenIndex
			{
				position322 := position
				if buffer[position] != rune('.') {
					goto l321
				}
				position++
				{
					position323, tokenIndex323 := position, tokenIndex
					if buffer[position] != rune('t') {
						goto l324
					}
					position++
					goto l323
				l324:
					position, tokenIndex = position323, tokenIndex323
					if buffer[position] != rune('T') {
						goto l321
					}
					position++
				}
			l323:
				{
					position325, tokenIndex325 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l326
					}
					position++
					goto l325
				l326:
					position, tokenIndex = position325, tokenIndex325
					if buffer[position] != rune('O') {
						goto l321
					}
					position++
				}
			l325:
				{
					position327, tokenIndex327 := position, tokenIndex
					if buffer[position] != rune('c') {
						goto l328
					}
					position++
					goto l327
				l328:
					position, tokenIndex = position327, tokenIndex327
					if buffer[position] != rune('C') {
						goto l321
					}
					position++
				}
			l327:
				if buffer[position] != rune('.') {
					goto l321
				}
				position++
				if buffer[position] != rune('-') {
					goto l321
				}
				position++
				if buffer[position] != rune('0') {
					goto l321
				}
				position++
				{
					position329, tokenIndex329 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l330
					}
					position++
					goto l329
				l330:
					position, tokenIndex = position329, tokenIndex329
					if buffer[position] != rune('B') {
						goto l321
					}
					position++
				}
			l329:
				if buffer[position] != rune('@') {
					goto l321
				}
				position++
				{
					position331, tokenIndex331 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l332
					}
					position++
					goto l331
				l332:
					position, tokenIndex = position331, tokenIndex331
					if buffer[position] != rune('L') {
						goto l321
					}
					position++
				}
			l331:
				add(ruleTOCRefLow, position322)
			}
			return true
		l321:
			position, tokenIndex = position321, tokenIndex321
			return false
		},
		/* 27 IndirectionIndicator <- <'*'> */
		func() bool {
			position333, tokenIndex333 := position, tokenIndex
			{
				position334 := position
				if buffer[position] != rune('*') {
					goto l333
				}
				position++
				add(ruleIndirectionIndicator, position334)
			}
			return true
		l333:
			position, tokenIndex = position333, tokenIndex333
			return false
		},
		/* 28 RegisterOrConstant <- <((('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))*) / ('$'? '-'? (('0' 'x' ([0-9] / [0-9] / ([a-f] / [A-F]))+) / [0-9]+))) !(':' / '('))> */
		func() bool {
			position335, tokenIndex335 := position, tokenIndex
			{
				position336 := position
				{
					position337, tokenIndex337 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l338
					}
					position++
					{
						position339, tokenIndex339 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l340
						}
						position++
						goto l339
					l340:
						position, tokenIndex = position339, tokenIndex339
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l338
						}
						position++
					}
				l339:
				l341:
					{
						position342, tokenIndex342 := position, tokenIndex
						{
							position343, tokenIndex343 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l344
							}
							position++
							goto l343
						l344:
							position, tokenIndex = position343, tokenIndex343
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l345
							}
							position++
							goto l343
						l345:
							position, tokenIndex = position343, tokenIndex343
							{
								position346, tokenIndex346 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l347
								}
								position++
								goto l346
							l347:
								position, tokenIndex = position346, tokenIndex346
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l342
								}
								position++
							}
						l346:
						}
					l343:
						goto l341
					l342:
						position, tokenIndex = position342, tokenIndex342
					}
					goto l337
				l338:
					position, tokenIndex = position337, tokenIndex337
					{
						position348, tokenIndex348 := position, tokenIndex
						if buffer[position] != rune('$') {
							goto l348
						}
						position++
						goto l349
					l348:
						position, tokenIndex = position348, tokenIndex348
					}
				l349:
					{
						position350, tokenIndex350 := position, tokenIndex
						if buffer[position] != rune('-') {
							goto l350
						}
						position++
						goto l351
					l350:
						position, tokenIndex = position350, tokenIndex350
					}
				l351:
					{
						position352, tokenIndex352 := position, tokenIndex
						if buffer[position] != rune('0') {
							goto l353
						}
						position++
						if buffer[position] != rune('x') {
							goto l353
						}
						position++
						{
							position356, tokenIndex356 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l357
							}
							position++
							goto l356
						l357:
							position, tokenIndex = position356, tokenIndex356
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l358
							}
							position++
							goto l356
						l358:
							position, tokenIndex = position356, tokenIndex356
							{
								position359, tokenIndex359 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('f') {
									goto l360
								}
								position++
								goto l359
							l360:
								position, tokenIndex = position359, tokenIndex359
								if c := buffer[position]; c < rune('A') || c > rune('F') {
									goto l353
								}
								position++
							}
						l359:
						}
					l356:
					l354:
						{
							position355, tokenIndex355 := position, tokenIndex
							{
								position361, tokenIndex361 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l362
								}
								position++
								goto l361
							l362:
								position, tokenIndex = position361, tokenIndex361
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l363
								}
								position++
								goto l361
							l363:
								position, tokenIndex = position361, tokenIndex361
								{
									position364, tokenIndex364 := position, tokenIndex
									if c := buffer[position]; c < rune('a') || c > rune('f') {
										goto l365
									}
									position++
									goto l364
								l365:
									position, tokenIndex = position364, tokenIndex364
									if c := buffer[position]; c < rune('A') || c > rune('F') {
										goto l355
									}
									position++
								}
							l364:
							}
						l361:
							goto l354
						l355:
							position, tokenIndex = position355, tokenIndex355
						}
						goto l352
					l353:
						position, tokenIndex = position352, tokenIndex352
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l335
						}
						position++
					l366:
						{
							position367, tokenIndex367 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l367
							}
							position++
							goto l366
						l367:
							position, tokenIndex = position367, tokenIndex367
						}
					}
				l352:
				}
			l337:
				{
					position368, tokenIndex368 := position, tokenIndex
					{
						position369, tokenIndex369 := position, tokenIndex
						if buffer[position] != rune(':') {
							goto l370
						}
						position++
						goto l369
					l370:
						position, tokenIndex = position369, tokenIndex369
						if buffer[position] != rune('(') {
							goto l368
						}
						position++
					}
				l369:
					goto l335
				l368:
					position, tokenIndex = position368, tokenIndex368
				}
				add(ruleRegisterOrConstant, position336)
			}
			return true
		l335:
			position, tokenIndex = position335, tokenIndex335
			return false
		},
		/* 29 MemoryRef <- <((Offset Operator SymbolRef BaseIndexScale) / (SymbolRef Operator Offset BaseIndexScale) / (SymbolRef BaseIndexScale) / (Offset BaseIndexScale) / (Offset Operator Offset BaseIndexScale) / (SymbolRef Operator Offset Operator Offset BaseIndexScale) / (Offset Operator Offset Operator Offset BaseIndexScale) / SymbolRef / BaseIndexScale / Absolute)> */
		func() bool {
			position371, tokenIndex371 := position, tokenIndex
			{
				position372 := position
				{
					position373, tokenIndex373 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l374
					}
					if !_rules[ruleOperator]() {
						goto l374
					}
					if !_rules[ruleSymbolRef]() {
						goto l374
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l374
					}
					goto l373
				l374:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleSymbolRef]() {
						goto l375
					}
					if !_rules[ruleOperator]() {
						goto l375
					}
					if !_rules[ruleOffset]() {
						goto l375
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l375
					}
					goto l373
				l375:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleSymbolRef]() {
						goto l376
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l376
					}
					goto l373
				l376:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleOffset]() {
						goto l377
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l377
					}
					goto l373
				l377:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleOffset]() {
						goto l378
					}
					if !_rules[ruleOperator]() {
						goto l378
					}
					if !_rules[ruleOffset]() {
						goto l378
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l378
					}
					goto l373
				l378:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleSymbolRef]() {
						goto l379
					}
					if !_rules[ruleOperator]() {
						goto l379
					}
					if !_rules[ruleOffset]() {
						goto l379
					}
					if !_rules[ruleOperator]() {
						goto l379
					}
					if !_rules[ruleOffset]() {
						goto l379
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l379
					}
					goto l373
				l379:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleOffset]() {
						goto l380
					}
					if !_rules[ruleOperator]() {
						goto l380
					}
					if !_rules[ruleOffset]() {
						goto l380
					}
					if !_rules[ruleOperator]() {
						goto l380
					}
					if !_rules[ruleOffset]() {
						goto l380
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l380
					}
					goto l373
				l380:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleSymbolRef]() {
						goto l381
					}
					goto l373
				l381:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleBaseIndexScale]() {
						goto l382
					}
					goto l373
				l382:
					position, tokenIndex = position373, tokenIndex373
					if !_rules[ruleAbsolute]() {
						goto l371
					}
				}
			l373:
				add(ruleMemoryRef, position372)
			}
			return true
		l371:
			position, tokenIndex = position371, tokenIndex371
			return false
		},
		/* 30 SymbolRef <- <((LocalSymbol / SymbolName) ('@' Section)?)> */
		func() bool {
			position383, tokenIndex383 := position, tokenIndex
			{
				position384 := position
				{
					position385, tokenIndex385 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l386
					}
					goto l385
				l386:
					position, tokenIndex = position385, tokenIndex385
					if !_rules[ruleSymbolName]() {
						goto l383
					}
				}
			l385:
				{
					position387, tokenIndex387 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l387
					}
					position++
					if !_rules[ruleSection]() {
						goto l387
					}
					goto l388
				l387:
					position, tokenIndex = position387, tokenIndex387
				}
			l388:
				add(ruleSymbolRef, position384)
			}
			return true
		l383:
			position, tokenIndex = position383, tokenIndex383
			return false
		},
		/* 31 BaseIndexScale <- <('(' RegisterOrConstant? WS? (',' WS? RegisterOrConstant WS? (',' [0-9]+)?)? ')')> */
		func() bool {
			position389, tokenIndex389 := position, tokenIndex
			{
				position390 := position
				if buffer[position] != rune('(') {
					goto l389
				}
				position++
				{
					position391, tokenIndex391 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l391
					}
					goto l392
				l391:
					position, tokenIndex = position391, tokenIndex391
				}
			l392:
				{
					position393, tokenIndex393 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l393
					}
					goto l394
				l393:
					position, tokenIndex = position393, tokenIndex393
				}
			l394:
				{
					position395, tokenIndex395 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l395
					}
					position++
					{
						position397, tokenIndex397 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l397
						}
						goto l398
					l397:
						position, tokenIndex = position397, tokenIndex397
					}
				l398:
					if !_rules[ruleRegisterOrConstant]() {
						goto l395
					}
					{
						position399, tokenIndex399 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l399
						}
						goto l400
					l399:
						position, tokenIndex = position399, tokenIndex399
					}
				l400:
					{
						position401, tokenIndex401 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l401
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l401
						}
						position++
					l403:
						{
							position404, tokenIndex404 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l404
							}
							position++
							goto l403
						l404:
							position, tokenIndex = position404, tokenIndex404
						}
						goto l402
					l401:
						position, tokenIndex = position401, tokenIndex401
					}
				l402:
					goto l396
				l395:
					position, tokenIndex = position395, tokenIndex395
				}
			l396:
				if buffer[position] != rune(')') {
					goto l389
				}
				position++
				add(ruleBaseIndexScale, position390)
			}
			return true
		l389:
			position, tokenIndex = position389, tokenIndex389
			return false
		},
		/* 32 Operator <- <('+' / '-')> */
		func() bool {
			position405, tokenIndex405 := position, tokenIndex
			{
				position406 := position
				{
					position407, tokenIndex407 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l408
					}
					position++
					goto l407
				l408:
					position, tokenIndex = position407, tokenIndex407
					if buffer[position] != rune('-') {
						goto l405
					}
					position++
				}
			l407:
				add(ruleOperator, position406)
			}
			return true
		l405:
			position, tokenIndex = position405, tokenIndex405
			return false
		},
		/* 33 Offset <- <('-'? (('0' 'x' ([0-9] / [0-9] / ([a-f] / [A-F]))+) / ([0-9] [0-9]*)))> */
		func() bool {
			position409, tokenIndex409 := position, tokenIndex
			{
				position410 := position
				{
					position411, tokenIndex411 := position, tokenIndex
					if buffer[position] != rune('-') {
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
					if buffer[position] != rune('0') {
						goto l414
					}
					position++
					if buffer[position] != rune('x') {
						goto l414
					}
					position++
					{
						position417, tokenIndex417 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l418
						}
						position++
						goto l417
					l418:
						position, tokenIndex = position417, tokenIndex417
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l419
						}
						position++
						goto l417
					l419:
						position, tokenIndex = position417, tokenIndex417
						{
							position420, tokenIndex420 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('f') {
								goto l421
							}
							position++
							goto l420
						l421:
							position, tokenIndex = position420, tokenIndex420
							if c := buffer[position]; c < rune('A') || c > rune('F') {
								goto l414
							}
							position++
						}
					l420:
					}
				l417:
				l415:
					{
						position416, tokenIndex416 := position, tokenIndex
						{
							position422, tokenIndex422 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l423
							}
							position++
							goto l422
						l423:
							position, tokenIndex = position422, tokenIndex422
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l424
							}
							position++
							goto l422
						l424:
							position, tokenIndex = position422, tokenIndex422
							{
								position425, tokenIndex425 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('f') {
									goto l426
								}
								position++
								goto l425
							l426:
								position, tokenIndex = position425, tokenIndex425
								if c := buffer[position]; c < rune('A') || c > rune('F') {
									goto l416
								}
								position++
							}
						l425:
						}
					l422:
						goto l415
					l416:
						position, tokenIndex = position416, tokenIndex416
					}
					goto l413
				l414:
					position, tokenIndex = position413, tokenIndex413
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l409
					}
					position++
				l427:
					{
						position428, tokenIndex428 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l428
						}
						position++
						goto l427
					l428:
						position, tokenIndex = position428, tokenIndex428
					}
				}
			l413:
				add(ruleOffset, position410)
			}
			return true
		l409:
			position, tokenIndex = position409, tokenIndex409
			return false
		},
		/* 34 Absolute <- <(('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* ':')? [0-9]+)> */
		func() bool {
			position429, tokenIndex429 := position, tokenIndex
			{
				position430 := position
				{
					position431, tokenIndex431 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l431
					}
					position++
					{
						position433, tokenIndex433 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l434
						}
						position++
						goto l433
					l434:
						position, tokenIndex = position433, tokenIndex433
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l431
						}
						position++
					}
				l433:
				l435:
					{
						position436, tokenIndex436 := position, tokenIndex
						{
							position437, tokenIndex437 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l438
							}
							position++
							goto l437
						l438:
							position, tokenIndex = position437, tokenIndex437
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l439
							}
							position++
							goto l437
						l439:
							position, tokenIndex = position437, tokenIndex437
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
									goto l436
								}
								position++
							}
						l440:
						}
					l437:
						goto l435
					l436:
						position, tokenIndex = position436, tokenIndex436
					}
					if buffer[position] != rune(':') {
						goto l431
					}
					position++
					goto l432
				l431:
					position, tokenIndex = position431, tokenIndex431
				}
			l432:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l429
				}
				position++
			l442:
				{
					position443, tokenIndex443 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l443
					}
					position++
					goto l442
				l443:
					position, tokenIndex = position443, tokenIndex443
				}
				add(ruleAbsolute, position430)
			}
			return true
		l429:
			position, tokenIndex = position429, tokenIndex429
			return false
		},
		/* 35 Section <- <([a-z] / [A-Z] / '@')+> */
		func() bool {
			position444, tokenIndex444 := position, tokenIndex
			{
				position445 := position
				{
					position448, tokenIndex448 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l449
					}
					position++
					goto l448
				l449:
					position, tokenIndex = position448, tokenIndex448
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l450
					}
					position++
					goto l448
				l450:
					position, tokenIndex = position448, tokenIndex448
					if buffer[position] != rune('@') {
						goto l444
					}
					position++
				}
			l448:
			l446:
				{
					position447, tokenIndex447 := position, tokenIndex
					{
						position451, tokenIndex451 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l452
						}
						position++
						goto l451
					l452:
						position, tokenIndex = position451, tokenIndex451
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l453
						}
						position++
						goto l451
					l453:
						position, tokenIndex = position451, tokenIndex451
						if buffer[position] != rune('@') {
							goto l447
						}
						position++
					}
				l451:
					goto l446
				l447:
					position, tokenIndex = position447, tokenIndex447
				}
				add(ruleSection, position445)
			}
			return true
		l444:
			position, tokenIndex = position444, tokenIndex444
			return false
		},
	}
	p.rules = _rules
}
