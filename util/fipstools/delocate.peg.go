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
	ruleDot
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
	"Dot",
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
	rules  [38]func() bool
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
		/* 7 Arg <- <(QuotedArg / ([0-9] / [0-9] / ([a-z] / [A-Z]) / '%' / '+' / '-' / '_' / '@' / '.')*)> */
		func() bool {
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
				l108:
					{
						position109, tokenIndex109 := position, tokenIndex
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
								goto l109
							}
							position++
						}
					l110:
						goto l108
					l109:
						position, tokenIndex = position109, tokenIndex109
					}
				}
			l106:
				add(ruleArg, position105)
			}
			return true
		},
		/* 8 QuotedArg <- <('"' QuotedText '"')> */
		func() bool {
			position121, tokenIndex121 := position, tokenIndex
			{
				position122 := position
				if buffer[position] != rune('"') {
					goto l121
				}
				position++
				if !_rules[ruleQuotedText]() {
					goto l121
				}
				if buffer[position] != rune('"') {
					goto l121
				}
				position++
				add(ruleQuotedArg, position122)
			}
			return true
		l121:
			position, tokenIndex = position121, tokenIndex121
			return false
		},
		/* 9 QuotedText <- <(EscapedChar / (!'"' .))*> */
		func() bool {
			{
				position124 := position
			l125:
				{
					position126, tokenIndex126 := position, tokenIndex
					{
						position127, tokenIndex127 := position, tokenIndex
						if !_rules[ruleEscapedChar]() {
							goto l128
						}
						goto l127
					l128:
						position, tokenIndex = position127, tokenIndex127
						{
							position129, tokenIndex129 := position, tokenIndex
							if buffer[position] != rune('"') {
								goto l129
							}
							position++
							goto l126
						l129:
							position, tokenIndex = position129, tokenIndex129
						}
						if !matchDot() {
							goto l126
						}
					}
				l127:
					goto l125
				l126:
					position, tokenIndex = position126, tokenIndex126
				}
				add(ruleQuotedText, position124)
			}
			return true
		},
		/* 10 LabelContainingDirective <- <(LabelContainingDirectiveName WS SymbolArgs)> */
		func() bool {
			position130, tokenIndex130 := position, tokenIndex
			{
				position131 := position
				if !_rules[ruleLabelContainingDirectiveName]() {
					goto l130
				}
				if !_rules[ruleWS]() {
					goto l130
				}
				if !_rules[ruleSymbolArgs]() {
					goto l130
				}
				add(ruleLabelContainingDirective, position131)
			}
			return true
		l130:
			position, tokenIndex = position130, tokenIndex130
			return false
		},
		/* 11 LabelContainingDirectiveName <- <(('.' ('l' / 'L') ('o' / 'O') ('n' / 'N') ('g' / 'G')) / ('.' ('s' / 'S') ('e' / 'E') ('t' / 'T')) / ('.' '8' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' '4' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' ('q' / 'Q') ('u' / 'U') ('a' / 'A') ('d' / 'D')))> */
		func() bool {
			position132, tokenIndex132 := position, tokenIndex
			{
				position133 := position
				{
					position134, tokenIndex134 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l135
					}
					position++
					{
						position136, tokenIndex136 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l137
						}
						position++
						goto l136
					l137:
						position, tokenIndex = position136, tokenIndex136
						if buffer[position] != rune('L') {
							goto l135
						}
						position++
					}
				l136:
					{
						position138, tokenIndex138 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l139
						}
						position++
						goto l138
					l139:
						position, tokenIndex = position138, tokenIndex138
						if buffer[position] != rune('O') {
							goto l135
						}
						position++
					}
				l138:
					{
						position140, tokenIndex140 := position, tokenIndex
						if buffer[position] != rune('n') {
							goto l141
						}
						position++
						goto l140
					l141:
						position, tokenIndex = position140, tokenIndex140
						if buffer[position] != rune('N') {
							goto l135
						}
						position++
					}
				l140:
					{
						position142, tokenIndex142 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l143
						}
						position++
						goto l142
					l143:
						position, tokenIndex = position142, tokenIndex142
						if buffer[position] != rune('G') {
							goto l135
						}
						position++
					}
				l142:
					goto l134
				l135:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l144
					}
					position++
					{
						position145, tokenIndex145 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l146
						}
						position++
						goto l145
					l146:
						position, tokenIndex = position145, tokenIndex145
						if buffer[position] != rune('S') {
							goto l144
						}
						position++
					}
				l145:
					{
						position147, tokenIndex147 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l148
						}
						position++
						goto l147
					l148:
						position, tokenIndex = position147, tokenIndex147
						if buffer[position] != rune('E') {
							goto l144
						}
						position++
					}
				l147:
					{
						position149, tokenIndex149 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l150
						}
						position++
						goto l149
					l150:
						position, tokenIndex = position149, tokenIndex149
						if buffer[position] != rune('T') {
							goto l144
						}
						position++
					}
				l149:
					goto l134
				l144:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l151
					}
					position++
					if buffer[position] != rune('8') {
						goto l151
					}
					position++
					{
						position152, tokenIndex152 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l153
						}
						position++
						goto l152
					l153:
						position, tokenIndex = position152, tokenIndex152
						if buffer[position] != rune('B') {
							goto l151
						}
						position++
					}
				l152:
					{
						position154, tokenIndex154 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l155
						}
						position++
						goto l154
					l155:
						position, tokenIndex = position154, tokenIndex154
						if buffer[position] != rune('Y') {
							goto l151
						}
						position++
					}
				l154:
					{
						position156, tokenIndex156 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l157
						}
						position++
						goto l156
					l157:
						position, tokenIndex = position156, tokenIndex156
						if buffer[position] != rune('T') {
							goto l151
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
							goto l151
						}
						position++
					}
				l158:
					goto l134
				l151:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l160
					}
					position++
					if buffer[position] != rune('4') {
						goto l160
					}
					position++
					{
						position161, tokenIndex161 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l162
						}
						position++
						goto l161
					l162:
						position, tokenIndex = position161, tokenIndex161
						if buffer[position] != rune('B') {
							goto l160
						}
						position++
					}
				l161:
					{
						position163, tokenIndex163 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l164
						}
						position++
						goto l163
					l164:
						position, tokenIndex = position163, tokenIndex163
						if buffer[position] != rune('Y') {
							goto l160
						}
						position++
					}
				l163:
					{
						position165, tokenIndex165 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l166
						}
						position++
						goto l165
					l166:
						position, tokenIndex = position165, tokenIndex165
						if buffer[position] != rune('T') {
							goto l160
						}
						position++
					}
				l165:
					{
						position167, tokenIndex167 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l168
						}
						position++
						goto l167
					l168:
						position, tokenIndex = position167, tokenIndex167
						if buffer[position] != rune('E') {
							goto l160
						}
						position++
					}
				l167:
					goto l134
				l160:
					position, tokenIndex = position134, tokenIndex134
					if buffer[position] != rune('.') {
						goto l132
					}
					position++
					{
						position169, tokenIndex169 := position, tokenIndex
						if buffer[position] != rune('q') {
							goto l170
						}
						position++
						goto l169
					l170:
						position, tokenIndex = position169, tokenIndex169
						if buffer[position] != rune('Q') {
							goto l132
						}
						position++
					}
				l169:
					{
						position171, tokenIndex171 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l172
						}
						position++
						goto l171
					l172:
						position, tokenIndex = position171, tokenIndex171
						if buffer[position] != rune('U') {
							goto l132
						}
						position++
					}
				l171:
					{
						position173, tokenIndex173 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l174
						}
						position++
						goto l173
					l174:
						position, tokenIndex = position173, tokenIndex173
						if buffer[position] != rune('A') {
							goto l132
						}
						position++
					}
				l173:
					{
						position175, tokenIndex175 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l176
						}
						position++
						goto l175
					l176:
						position, tokenIndex = position175, tokenIndex175
						if buffer[position] != rune('D') {
							goto l132
						}
						position++
					}
				l175:
				}
			l134:
				add(ruleLabelContainingDirectiveName, position133)
			}
			return true
		l132:
			position, tokenIndex = position132, tokenIndex132
			return false
		},
		/* 12 SymbolArgs <- <(SymbolArg (WS? ',' WS? SymbolArg)*)> */
		func() bool {
			position177, tokenIndex177 := position, tokenIndex
			{
				position178 := position
				if !_rules[ruleSymbolArg]() {
					goto l177
				}
			l179:
				{
					position180, tokenIndex180 := position, tokenIndex
					{
						position181, tokenIndex181 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l181
						}
						goto l182
					l181:
						position, tokenIndex = position181, tokenIndex181
					}
				l182:
					if buffer[position] != rune(',') {
						goto l180
					}
					position++
					{
						position183, tokenIndex183 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l183
						}
						goto l184
					l183:
						position, tokenIndex = position183, tokenIndex183
					}
				l184:
					if !_rules[ruleSymbolArg]() {
						goto l180
					}
					goto l179
				l180:
					position, tokenIndex = position180, tokenIndex180
				}
				add(ruleSymbolArgs, position178)
			}
			return true
		l177:
			position, tokenIndex = position177, tokenIndex177
			return false
		},
		/* 13 SymbolArg <- <(Offset / (LocalSymbol Operator LocalSymbol) / (LocalSymbol Operator Offset) / (Dot WS? Operator WS? Offset) / (Offset Operator LocalSymbol) / LocalSymbol)> */
		func() bool {
			position185, tokenIndex185 := position, tokenIndex
			{
				position186 := position
				{
					position187, tokenIndex187 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l188
					}
					goto l187
				l188:
					position, tokenIndex = position187, tokenIndex187
					if !_rules[ruleLocalSymbol]() {
						goto l189
					}
					if !_rules[ruleOperator]() {
						goto l189
					}
					if !_rules[ruleLocalSymbol]() {
						goto l189
					}
					goto l187
				l189:
					position, tokenIndex = position187, tokenIndex187
					if !_rules[ruleLocalSymbol]() {
						goto l190
					}
					if !_rules[ruleOperator]() {
						goto l190
					}
					if !_rules[ruleOffset]() {
						goto l190
					}
					goto l187
				l190:
					position, tokenIndex = position187, tokenIndex187
					if !_rules[ruleDot]() {
						goto l191
					}
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
					if !_rules[ruleOperator]() {
						goto l191
					}
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
					if !_rules[ruleOffset]() {
						goto l191
					}
					goto l187
				l191:
					position, tokenIndex = position187, tokenIndex187
					if !_rules[ruleOffset]() {
						goto l196
					}
					if !_rules[ruleOperator]() {
						goto l196
					}
					if !_rules[ruleLocalSymbol]() {
						goto l196
					}
					goto l187
				l196:
					position, tokenIndex = position187, tokenIndex187
					if !_rules[ruleLocalSymbol]() {
						goto l185
					}
				}
			l187:
				add(ruleSymbolArg, position186)
			}
			return true
		l185:
			position, tokenIndex = position185, tokenIndex185
			return false
		},
		/* 14 Dot <- <'.'> */
		func() bool {
			position197, tokenIndex197 := position, tokenIndex
			{
				position198 := position
				if buffer[position] != rune('.') {
					goto l197
				}
				position++
				add(ruleDot, position198)
			}
			return true
		l197:
			position, tokenIndex = position197, tokenIndex197
			return false
		},
		/* 15 EscapedChar <- <('\\' .)> */
		func() bool {
			position199, tokenIndex199 := position, tokenIndex
			{
				position200 := position
				if buffer[position] != rune('\\') {
					goto l199
				}
				position++
				if !matchDot() {
					goto l199
				}
				add(ruleEscapedChar, position200)
			}
			return true
		l199:
			position, tokenIndex = position199, tokenIndex199
			return false
		},
		/* 16 WS <- <(' ' / '\t')+> */
		func() bool {
			position201, tokenIndex201 := position, tokenIndex
			{
				position202 := position
				{
					position205, tokenIndex205 := position, tokenIndex
					if buffer[position] != rune(' ') {
						goto l206
					}
					position++
					goto l205
				l206:
					position, tokenIndex = position205, tokenIndex205
					if buffer[position] != rune('\t') {
						goto l201
					}
					position++
				}
			l205:
			l203:
				{
					position204, tokenIndex204 := position, tokenIndex
					{
						position207, tokenIndex207 := position, tokenIndex
						if buffer[position] != rune(' ') {
							goto l208
						}
						position++
						goto l207
					l208:
						position, tokenIndex = position207, tokenIndex207
						if buffer[position] != rune('\t') {
							goto l204
						}
						position++
					}
				l207:
					goto l203
				l204:
					position, tokenIndex = position204, tokenIndex204
				}
				add(ruleWS, position202)
			}
			return true
		l201:
			position, tokenIndex = position201, tokenIndex201
			return false
		},
		/* 17 Comment <- <('#' (!'\n' .)*)> */
		func() bool {
			position209, tokenIndex209 := position, tokenIndex
			{
				position210 := position
				if buffer[position] != rune('#') {
					goto l209
				}
				position++
			l211:
				{
					position212, tokenIndex212 := position, tokenIndex
					{
						position213, tokenIndex213 := position, tokenIndex
						if buffer[position] != rune('\n') {
							goto l213
						}
						position++
						goto l212
					l213:
						position, tokenIndex = position213, tokenIndex213
					}
					if !matchDot() {
						goto l212
					}
					goto l211
				l212:
					position, tokenIndex = position212, tokenIndex212
				}
				add(ruleComment, position210)
			}
			return true
		l209:
			position, tokenIndex = position209, tokenIndex209
			return false
		},
		/* 18 Label <- <((LocalSymbol / LocalLabel / SymbolName) ':')> */
		func() bool {
			position214, tokenIndex214 := position, tokenIndex
			{
				position215 := position
				{
					position216, tokenIndex216 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l217
					}
					goto l216
				l217:
					position, tokenIndex = position216, tokenIndex216
					if !_rules[ruleLocalLabel]() {
						goto l218
					}
					goto l216
				l218:
					position, tokenIndex = position216, tokenIndex216
					if !_rules[ruleSymbolName]() {
						goto l214
					}
				}
			l216:
				if buffer[position] != rune(':') {
					goto l214
				}
				position++
				add(ruleLabel, position215)
			}
			return true
		l214:
			position, tokenIndex = position214, tokenIndex214
			return false
		},
		/* 19 SymbolName <- <(([a-z] / [A-Z] / '.' / '_') ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')*)> */
		func() bool {
			position219, tokenIndex219 := position, tokenIndex
			{
				position220 := position
				{
					position221, tokenIndex221 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l222
					}
					position++
					goto l221
				l222:
					position, tokenIndex = position221, tokenIndex221
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l223
					}
					position++
					goto l221
				l223:
					position, tokenIndex = position221, tokenIndex221
					if buffer[position] != rune('.') {
						goto l224
					}
					position++
					goto l221
				l224:
					position, tokenIndex = position221, tokenIndex221
					if buffer[position] != rune('_') {
						goto l219
					}
					position++
				}
			l221:
			l225:
				{
					position226, tokenIndex226 := position, tokenIndex
					{
						position227, tokenIndex227 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l228
						}
						position++
						goto l227
					l228:
						position, tokenIndex = position227, tokenIndex227
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l229
						}
						position++
						goto l227
					l229:
						position, tokenIndex = position227, tokenIndex227
						if buffer[position] != rune('.') {
							goto l230
						}
						position++
						goto l227
					l230:
						position, tokenIndex = position227, tokenIndex227
						{
							position232, tokenIndex232 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l233
							}
							position++
							goto l232
						l233:
							position, tokenIndex = position232, tokenIndex232
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l231
							}
							position++
						}
					l232:
						goto l227
					l231:
						position, tokenIndex = position227, tokenIndex227
						if buffer[position] != rune('$') {
							goto l234
						}
						position++
						goto l227
					l234:
						position, tokenIndex = position227, tokenIndex227
						if buffer[position] != rune('_') {
							goto l226
						}
						position++
					}
				l227:
					goto l225
				l226:
					position, tokenIndex = position226, tokenIndex226
				}
				add(ruleSymbolName, position220)
			}
			return true
		l219:
			position, tokenIndex = position219, tokenIndex219
			return false
		},
		/* 20 LocalSymbol <- <('.' 'L' ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')+)> */
		func() bool {
			position235, tokenIndex235 := position, tokenIndex
			{
				position236 := position
				if buffer[position] != rune('.') {
					goto l235
				}
				position++
				if buffer[position] != rune('L') {
					goto l235
				}
				position++
				{
					position239, tokenIndex239 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l240
					}
					position++
					goto l239
				l240:
					position, tokenIndex = position239, tokenIndex239
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l241
					}
					position++
					goto l239
				l241:
					position, tokenIndex = position239, tokenIndex239
					if buffer[position] != rune('.') {
						goto l242
					}
					position++
					goto l239
				l242:
					position, tokenIndex = position239, tokenIndex239
					{
						position244, tokenIndex244 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l245
						}
						position++
						goto l244
					l245:
						position, tokenIndex = position244, tokenIndex244
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l243
						}
						position++
					}
				l244:
					goto l239
				l243:
					position, tokenIndex = position239, tokenIndex239
					if buffer[position] != rune('$') {
						goto l246
					}
					position++
					goto l239
				l246:
					position, tokenIndex = position239, tokenIndex239
					if buffer[position] != rune('_') {
						goto l235
					}
					position++
				}
			l239:
			l237:
				{
					position238, tokenIndex238 := position, tokenIndex
					{
						position247, tokenIndex247 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l248
						}
						position++
						goto l247
					l248:
						position, tokenIndex = position247, tokenIndex247
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l249
						}
						position++
						goto l247
					l249:
						position, tokenIndex = position247, tokenIndex247
						if buffer[position] != rune('.') {
							goto l250
						}
						position++
						goto l247
					l250:
						position, tokenIndex = position247, tokenIndex247
						{
							position252, tokenIndex252 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l253
							}
							position++
							goto l252
						l253:
							position, tokenIndex = position252, tokenIndex252
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l251
							}
							position++
						}
					l252:
						goto l247
					l251:
						position, tokenIndex = position247, tokenIndex247
						if buffer[position] != rune('$') {
							goto l254
						}
						position++
						goto l247
					l254:
						position, tokenIndex = position247, tokenIndex247
						if buffer[position] != rune('_') {
							goto l238
						}
						position++
					}
				l247:
					goto l237
				l238:
					position, tokenIndex = position238, tokenIndex238
				}
				add(ruleLocalSymbol, position236)
			}
			return true
		l235:
			position, tokenIndex = position235, tokenIndex235
			return false
		},
		/* 21 LocalLabel <- <([0-9] ([0-9] / '$')*)> */
		func() bool {
			position255, tokenIndex255 := position, tokenIndex
			{
				position256 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l255
				}
				position++
			l257:
				{
					position258, tokenIndex258 := position, tokenIndex
					{
						position259, tokenIndex259 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l260
						}
						position++
						goto l259
					l260:
						position, tokenIndex = position259, tokenIndex259
						if buffer[position] != rune('$') {
							goto l258
						}
						position++
					}
				l259:
					goto l257
				l258:
					position, tokenIndex = position258, tokenIndex258
				}
				add(ruleLocalLabel, position256)
			}
			return true
		l255:
			position, tokenIndex = position255, tokenIndex255
			return false
		},
		/* 22 LocalLabelRef <- <([0-9] ([0-9] / '$')* ('b' / 'f'))> */
		func() bool {
			position261, tokenIndex261 := position, tokenIndex
			{
				position262 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l261
				}
				position++
			l263:
				{
					position264, tokenIndex264 := position, tokenIndex
					{
						position265, tokenIndex265 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l266
						}
						position++
						goto l265
					l266:
						position, tokenIndex = position265, tokenIndex265
						if buffer[position] != rune('$') {
							goto l264
						}
						position++
					}
				l265:
					goto l263
				l264:
					position, tokenIndex = position264, tokenIndex264
				}
				{
					position267, tokenIndex267 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l268
					}
					position++
					goto l267
				l268:
					position, tokenIndex = position267, tokenIndex267
					if buffer[position] != rune('f') {
						goto l261
					}
					position++
				}
			l267:
				add(ruleLocalLabelRef, position262)
			}
			return true
		l261:
			position, tokenIndex = position261, tokenIndex261
			return false
		},
		/* 23 Instruction <- <(InstructionName WS? InstructionArg? WS? (',' WS? InstructionArg)*)> */
		func() bool {
			position269, tokenIndex269 := position, tokenIndex
			{
				position270 := position
				if !_rules[ruleInstructionName]() {
					goto l269
				}
				{
					position271, tokenIndex271 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l271
					}
					goto l272
				l271:
					position, tokenIndex = position271, tokenIndex271
				}
			l272:
				{
					position273, tokenIndex273 := position, tokenIndex
					if !_rules[ruleInstructionArg]() {
						goto l273
					}
					goto l274
				l273:
					position, tokenIndex = position273, tokenIndex273
				}
			l274:
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
			l277:
				{
					position278, tokenIndex278 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l278
					}
					position++
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
					if !_rules[ruleInstructionArg]() {
						goto l278
					}
					goto l277
				l278:
					position, tokenIndex = position278, tokenIndex278
				}
				add(ruleInstruction, position270)
			}
			return true
		l269:
			position, tokenIndex = position269, tokenIndex269
			return false
		},
		/* 24 InstructionName <- <(([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* ('.' / '+' / '-')?)> */
		func() bool {
			position281, tokenIndex281 := position, tokenIndex
			{
				position282 := position
				{
					position283, tokenIndex283 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l284
					}
					position++
					goto l283
				l284:
					position, tokenIndex = position283, tokenIndex283
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l281
					}
					position++
				}
			l283:
			l285:
				{
					position286, tokenIndex286 := position, tokenIndex
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
							goto l289
						}
						position++
						goto l287
					l289:
						position, tokenIndex = position287, tokenIndex287
						{
							position290, tokenIndex290 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l291
							}
							position++
							goto l290
						l291:
							position, tokenIndex = position290, tokenIndex290
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l286
							}
							position++
						}
					l290:
					}
				l287:
					goto l285
				l286:
					position, tokenIndex = position286, tokenIndex286
				}
				{
					position292, tokenIndex292 := position, tokenIndex
					{
						position294, tokenIndex294 := position, tokenIndex
						if buffer[position] != rune('.') {
							goto l295
						}
						position++
						goto l294
					l295:
						position, tokenIndex = position294, tokenIndex294
						if buffer[position] != rune('+') {
							goto l296
						}
						position++
						goto l294
					l296:
						position, tokenIndex = position294, tokenIndex294
						if buffer[position] != rune('-') {
							goto l292
						}
						position++
					}
				l294:
					goto l293
				l292:
					position, tokenIndex = position292, tokenIndex292
				}
			l293:
				add(ruleInstructionName, position282)
			}
			return true
		l281:
			position, tokenIndex = position281, tokenIndex281
			return false
		},
		/* 25 InstructionArg <- <(IndirectionIndicator? (RegisterOrConstant / LocalLabelRef / TOCRefHigh / TOCRefLow / MemoryRef))> */
		func() bool {
			position297, tokenIndex297 := position, tokenIndex
			{
				position298 := position
				{
					position299, tokenIndex299 := position, tokenIndex
					if !_rules[ruleIndirectionIndicator]() {
						goto l299
					}
					goto l300
				l299:
					position, tokenIndex = position299, tokenIndex299
				}
			l300:
				{
					position301, tokenIndex301 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l302
					}
					goto l301
				l302:
					position, tokenIndex = position301, tokenIndex301
					if !_rules[ruleLocalLabelRef]() {
						goto l303
					}
					goto l301
				l303:
					position, tokenIndex = position301, tokenIndex301
					if !_rules[ruleTOCRefHigh]() {
						goto l304
					}
					goto l301
				l304:
					position, tokenIndex = position301, tokenIndex301
					if !_rules[ruleTOCRefLow]() {
						goto l305
					}
					goto l301
				l305:
					position, tokenIndex = position301, tokenIndex301
					if !_rules[ruleMemoryRef]() {
						goto l297
					}
				}
			l301:
				add(ruleInstructionArg, position298)
			}
			return true
		l297:
			position, tokenIndex = position297, tokenIndex297
			return false
		},
		/* 26 TOCRefHigh <- <('.' ('t' / 'T') ('o' / 'O') ('c' / 'C') '.' '-' '0' ('b' / 'B') '@' ('h' / 'H') ('a' / 'A'))> */
		func() bool {
			position306, tokenIndex306 := position, tokenIndex
			{
				position307 := position
				if buffer[position] != rune('.') {
					goto l306
				}
				position++
				{
					position308, tokenIndex308 := position, tokenIndex
					if buffer[position] != rune('t') {
						goto l309
					}
					position++
					goto l308
				l309:
					position, tokenIndex = position308, tokenIndex308
					if buffer[position] != rune('T') {
						goto l306
					}
					position++
				}
			l308:
				{
					position310, tokenIndex310 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l311
					}
					position++
					goto l310
				l311:
					position, tokenIndex = position310, tokenIndex310
					if buffer[position] != rune('O') {
						goto l306
					}
					position++
				}
			l310:
				{
					position312, tokenIndex312 := position, tokenIndex
					if buffer[position] != rune('c') {
						goto l313
					}
					position++
					goto l312
				l313:
					position, tokenIndex = position312, tokenIndex312
					if buffer[position] != rune('C') {
						goto l306
					}
					position++
				}
			l312:
				if buffer[position] != rune('.') {
					goto l306
				}
				position++
				if buffer[position] != rune('-') {
					goto l306
				}
				position++
				if buffer[position] != rune('0') {
					goto l306
				}
				position++
				{
					position314, tokenIndex314 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l315
					}
					position++
					goto l314
				l315:
					position, tokenIndex = position314, tokenIndex314
					if buffer[position] != rune('B') {
						goto l306
					}
					position++
				}
			l314:
				if buffer[position] != rune('@') {
					goto l306
				}
				position++
				{
					position316, tokenIndex316 := position, tokenIndex
					if buffer[position] != rune('h') {
						goto l317
					}
					position++
					goto l316
				l317:
					position, tokenIndex = position316, tokenIndex316
					if buffer[position] != rune('H') {
						goto l306
					}
					position++
				}
			l316:
				{
					position318, tokenIndex318 := position, tokenIndex
					if buffer[position] != rune('a') {
						goto l319
					}
					position++
					goto l318
				l319:
					position, tokenIndex = position318, tokenIndex318
					if buffer[position] != rune('A') {
						goto l306
					}
					position++
				}
			l318:
				add(ruleTOCRefHigh, position307)
			}
			return true
		l306:
			position, tokenIndex = position306, tokenIndex306
			return false
		},
		/* 27 TOCRefLow <- <('.' ('t' / 'T') ('o' / 'O') ('c' / 'C') '.' '-' '0' ('b' / 'B') '@' ('l' / 'L'))> */
		func() bool {
			position320, tokenIndex320 := position, tokenIndex
			{
				position321 := position
				if buffer[position] != rune('.') {
					goto l320
				}
				position++
				{
					position322, tokenIndex322 := position, tokenIndex
					if buffer[position] != rune('t') {
						goto l323
					}
					position++
					goto l322
				l323:
					position, tokenIndex = position322, tokenIndex322
					if buffer[position] != rune('T') {
						goto l320
					}
					position++
				}
			l322:
				{
					position324, tokenIndex324 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l325
					}
					position++
					goto l324
				l325:
					position, tokenIndex = position324, tokenIndex324
					if buffer[position] != rune('O') {
						goto l320
					}
					position++
				}
			l324:
				{
					position326, tokenIndex326 := position, tokenIndex
					if buffer[position] != rune('c') {
						goto l327
					}
					position++
					goto l326
				l327:
					position, tokenIndex = position326, tokenIndex326
					if buffer[position] != rune('C') {
						goto l320
					}
					position++
				}
			l326:
				if buffer[position] != rune('.') {
					goto l320
				}
				position++
				if buffer[position] != rune('-') {
					goto l320
				}
				position++
				if buffer[position] != rune('0') {
					goto l320
				}
				position++
				{
					position328, tokenIndex328 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l329
					}
					position++
					goto l328
				l329:
					position, tokenIndex = position328, tokenIndex328
					if buffer[position] != rune('B') {
						goto l320
					}
					position++
				}
			l328:
				if buffer[position] != rune('@') {
					goto l320
				}
				position++
				{
					position330, tokenIndex330 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l331
					}
					position++
					goto l330
				l331:
					position, tokenIndex = position330, tokenIndex330
					if buffer[position] != rune('L') {
						goto l320
					}
					position++
				}
			l330:
				add(ruleTOCRefLow, position321)
			}
			return true
		l320:
			position, tokenIndex = position320, tokenIndex320
			return false
		},
		/* 28 IndirectionIndicator <- <'*'> */
		func() bool {
			position332, tokenIndex332 := position, tokenIndex
			{
				position333 := position
				if buffer[position] != rune('*') {
					goto l332
				}
				position++
				add(ruleIndirectionIndicator, position333)
			}
			return true
		l332:
			position, tokenIndex = position332, tokenIndex332
			return false
		},
		/* 29 RegisterOrConstant <- <((('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))*) / ('$'? ((Offset Offset) / Offset))) !('f' / 'b' / ':' / '(' / '+' / '-'))> */
		func() bool {
			position334, tokenIndex334 := position, tokenIndex
			{
				position335 := position
				{
					position336, tokenIndex336 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l337
					}
					position++
					{
						position338, tokenIndex338 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l339
						}
						position++
						goto l338
					l339:
						position, tokenIndex = position338, tokenIndex338
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l337
						}
						position++
					}
				l338:
				l340:
					{
						position341, tokenIndex341 := position, tokenIndex
						{
							position342, tokenIndex342 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l343
							}
							position++
							goto l342
						l343:
							position, tokenIndex = position342, tokenIndex342
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l344
							}
							position++
							goto l342
						l344:
							position, tokenIndex = position342, tokenIndex342
							{
								position345, tokenIndex345 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l346
								}
								position++
								goto l345
							l346:
								position, tokenIndex = position345, tokenIndex345
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l341
								}
								position++
							}
						l345:
						}
					l342:
						goto l340
					l341:
						position, tokenIndex = position341, tokenIndex341
					}
					goto l336
				l337:
					position, tokenIndex = position336, tokenIndex336
					{
						position347, tokenIndex347 := position, tokenIndex
						if buffer[position] != rune('$') {
							goto l347
						}
						position++
						goto l348
					l347:
						position, tokenIndex = position347, tokenIndex347
					}
				l348:
					{
						position349, tokenIndex349 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l350
						}
						if !_rules[ruleOffset]() {
							goto l350
						}
						goto l349
					l350:
						position, tokenIndex = position349, tokenIndex349
						if !_rules[ruleOffset]() {
							goto l334
						}
					}
				l349:
				}
			l336:
				{
					position351, tokenIndex351 := position, tokenIndex
					{
						position352, tokenIndex352 := position, tokenIndex
						if buffer[position] != rune('f') {
							goto l353
						}
						position++
						goto l352
					l353:
						position, tokenIndex = position352, tokenIndex352
						if buffer[position] != rune('b') {
							goto l354
						}
						position++
						goto l352
					l354:
						position, tokenIndex = position352, tokenIndex352
						if buffer[position] != rune(':') {
							goto l355
						}
						position++
						goto l352
					l355:
						position, tokenIndex = position352, tokenIndex352
						if buffer[position] != rune('(') {
							goto l356
						}
						position++
						goto l352
					l356:
						position, tokenIndex = position352, tokenIndex352
						if buffer[position] != rune('+') {
							goto l357
						}
						position++
						goto l352
					l357:
						position, tokenIndex = position352, tokenIndex352
						if buffer[position] != rune('-') {
							goto l351
						}
						position++
					}
				l352:
					goto l334
				l351:
					position, tokenIndex = position351, tokenIndex351
				}
				add(ruleRegisterOrConstant, position335)
			}
			return true
		l334:
			position, tokenIndex = position334, tokenIndex334
			return false
		},
		/* 30 MemoryRef <- <((Offset Operator SymbolRef BaseIndexScale) / (SymbolRef Operator Offset BaseIndexScale) / (SymbolRef BaseIndexScale) / (Offset BaseIndexScale) / (Offset Operator Offset BaseIndexScale) / (SymbolRef Operator Offset Operator Offset BaseIndexScale) / (Offset Operator Offset Operator Offset BaseIndexScale) / SymbolRef / BaseIndexScale / Absolute)> */
		func() bool {
			position358, tokenIndex358 := position, tokenIndex
			{
				position359 := position
				{
					position360, tokenIndex360 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l361
					}
					if !_rules[ruleOperator]() {
						goto l361
					}
					if !_rules[ruleSymbolRef]() {
						goto l361
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l361
					}
					goto l360
				l361:
					position, tokenIndex = position360, tokenIndex360
					if !_rules[ruleSymbolRef]() {
						goto l362
					}
					if !_rules[ruleOperator]() {
						goto l362
					}
					if !_rules[ruleOffset]() {
						goto l362
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l362
					}
					goto l360
				l362:
					position, tokenIndex = position360, tokenIndex360
					if !_rules[ruleSymbolRef]() {
						goto l363
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l363
					}
					goto l360
				l363:
					position, tokenIndex = position360, tokenIndex360
					if !_rules[ruleOffset]() {
						goto l364
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l364
					}
					goto l360
				l364:
					position, tokenIndex = position360, tokenIndex360
					if !_rules[ruleOffset]() {
						goto l365
					}
					if !_rules[ruleOperator]() {
						goto l365
					}
					if !_rules[ruleOffset]() {
						goto l365
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l365
					}
					goto l360
				l365:
					position, tokenIndex = position360, tokenIndex360
					if !_rules[ruleSymbolRef]() {
						goto l366
					}
					if !_rules[ruleOperator]() {
						goto l366
					}
					if !_rules[ruleOffset]() {
						goto l366
					}
					if !_rules[ruleOperator]() {
						goto l366
					}
					if !_rules[ruleOffset]() {
						goto l366
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l366
					}
					goto l360
				l366:
					position, tokenIndex = position360, tokenIndex360
					if !_rules[ruleOffset]() {
						goto l367
					}
					if !_rules[ruleOperator]() {
						goto l367
					}
					if !_rules[ruleOffset]() {
						goto l367
					}
					if !_rules[ruleOperator]() {
						goto l367
					}
					if !_rules[ruleOffset]() {
						goto l367
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l367
					}
					goto l360
				l367:
					position, tokenIndex = position360, tokenIndex360
					if !_rules[ruleSymbolRef]() {
						goto l368
					}
					goto l360
				l368:
					position, tokenIndex = position360, tokenIndex360
					if !_rules[ruleBaseIndexScale]() {
						goto l369
					}
					goto l360
				l369:
					position, tokenIndex = position360, tokenIndex360
					if !_rules[ruleAbsolute]() {
						goto l358
					}
				}
			l360:
				add(ruleMemoryRef, position359)
			}
			return true
		l358:
			position, tokenIndex = position358, tokenIndex358
			return false
		},
		/* 31 SymbolRef <- <((LocalSymbol / SymbolName) Offset? ('@' Section)?)> */
		func() bool {
			position370, tokenIndex370 := position, tokenIndex
			{
				position371 := position
				{
					position372, tokenIndex372 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l373
					}
					goto l372
				l373:
					position, tokenIndex = position372, tokenIndex372
					if !_rules[ruleSymbolName]() {
						goto l370
					}
				}
			l372:
				{
					position374, tokenIndex374 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l374
					}
					goto l375
				l374:
					position, tokenIndex = position374, tokenIndex374
				}
			l375:
				{
					position376, tokenIndex376 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l376
					}
					position++
					if !_rules[ruleSection]() {
						goto l376
					}
					goto l377
				l376:
					position, tokenIndex = position376, tokenIndex376
				}
			l377:
				add(ruleSymbolRef, position371)
			}
			return true
		l370:
			position, tokenIndex = position370, tokenIndex370
			return false
		},
		/* 32 BaseIndexScale <- <('(' RegisterOrConstant? WS? (',' WS? RegisterOrConstant WS? (',' [0-9]+)?)? ')')> */
		func() bool {
			position378, tokenIndex378 := position, tokenIndex
			{
				position379 := position
				if buffer[position] != rune('(') {
					goto l378
				}
				position++
				{
					position380, tokenIndex380 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l380
					}
					goto l381
				l380:
					position, tokenIndex = position380, tokenIndex380
				}
			l381:
				{
					position382, tokenIndex382 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l382
					}
					goto l383
				l382:
					position, tokenIndex = position382, tokenIndex382
				}
			l383:
				{
					position384, tokenIndex384 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l384
					}
					position++
					{
						position386, tokenIndex386 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l386
						}
						goto l387
					l386:
						position, tokenIndex = position386, tokenIndex386
					}
				l387:
					if !_rules[ruleRegisterOrConstant]() {
						goto l384
					}
					{
						position388, tokenIndex388 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l388
						}
						goto l389
					l388:
						position, tokenIndex = position388, tokenIndex388
					}
				l389:
					{
						position390, tokenIndex390 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l390
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l390
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
						goto l391
					l390:
						position, tokenIndex = position390, tokenIndex390
					}
				l391:
					goto l385
				l384:
					position, tokenIndex = position384, tokenIndex384
				}
			l385:
				if buffer[position] != rune(')') {
					goto l378
				}
				position++
				add(ruleBaseIndexScale, position379)
			}
			return true
		l378:
			position, tokenIndex = position378, tokenIndex378
			return false
		},
		/* 33 Operator <- <('+' / '-')> */
		func() bool {
			position394, tokenIndex394 := position, tokenIndex
			{
				position395 := position
				{
					position396, tokenIndex396 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l397
					}
					position++
					goto l396
				l397:
					position, tokenIndex = position396, tokenIndex396
					if buffer[position] != rune('-') {
						goto l394
					}
					position++
				}
			l396:
				add(ruleOperator, position395)
			}
			return true
		l394:
			position, tokenIndex = position394, tokenIndex394
			return false
		},
		/* 34 Offset <- <(('+' / '-')? (('0' 'x' ([0-9] / [0-9] / ([a-f] / [A-F]))+) / [0-9]+))> */
		func() bool {
			position398, tokenIndex398 := position, tokenIndex
			{
				position399 := position
				{
					position400, tokenIndex400 := position, tokenIndex
					{
						position402, tokenIndex402 := position, tokenIndex
						if buffer[position] != rune('+') {
							goto l403
						}
						position++
						goto l402
					l403:
						position, tokenIndex = position402, tokenIndex402
						if buffer[position] != rune('-') {
							goto l400
						}
						position++
					}
				l402:
					goto l401
				l400:
					position, tokenIndex = position400, tokenIndex400
				}
			l401:
				{
					position404, tokenIndex404 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l405
					}
					position++
					if buffer[position] != rune('x') {
						goto l405
					}
					position++
					{
						position408, tokenIndex408 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l409
						}
						position++
						goto l408
					l409:
						position, tokenIndex = position408, tokenIndex408
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l410
						}
						position++
						goto l408
					l410:
						position, tokenIndex = position408, tokenIndex408
						{
							position411, tokenIndex411 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('f') {
								goto l412
							}
							position++
							goto l411
						l412:
							position, tokenIndex = position411, tokenIndex411
							if c := buffer[position]; c < rune('A') || c > rune('F') {
								goto l405
							}
							position++
						}
					l411:
					}
				l408:
				l406:
					{
						position407, tokenIndex407 := position, tokenIndex
						{
							position413, tokenIndex413 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l414
							}
							position++
							goto l413
						l414:
							position, tokenIndex = position413, tokenIndex413
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l415
							}
							position++
							goto l413
						l415:
							position, tokenIndex = position413, tokenIndex413
							{
								position416, tokenIndex416 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('f') {
									goto l417
								}
								position++
								goto l416
							l417:
								position, tokenIndex = position416, tokenIndex416
								if c := buffer[position]; c < rune('A') || c > rune('F') {
									goto l407
								}
								position++
							}
						l416:
						}
					l413:
						goto l406
					l407:
						position, tokenIndex = position407, tokenIndex407
					}
					goto l404
				l405:
					position, tokenIndex = position404, tokenIndex404
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l398
					}
					position++
				l418:
					{
						position419, tokenIndex419 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l419
						}
						position++
						goto l418
					l419:
						position, tokenIndex = position419, tokenIndex419
					}
				}
			l404:
				add(ruleOffset, position399)
			}
			return true
		l398:
			position, tokenIndex = position398, tokenIndex398
			return false
		},
		/* 35 Absolute <- <(('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* ':')? [0-9]+)> */
		func() bool {
			position420, tokenIndex420 := position, tokenIndex
			{
				position421 := position
				{
					position422, tokenIndex422 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l422
					}
					position++
					{
						position424, tokenIndex424 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l425
						}
						position++
						goto l424
					l425:
						position, tokenIndex = position424, tokenIndex424
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l422
						}
						position++
					}
				l424:
				l426:
					{
						position427, tokenIndex427 := position, tokenIndex
						{
							position428, tokenIndex428 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l429
							}
							position++
							goto l428
						l429:
							position, tokenIndex = position428, tokenIndex428
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l430
							}
							position++
							goto l428
						l430:
							position, tokenIndex = position428, tokenIndex428
							{
								position431, tokenIndex431 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l432
								}
								position++
								goto l431
							l432:
								position, tokenIndex = position431, tokenIndex431
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l427
								}
								position++
							}
						l431:
						}
					l428:
						goto l426
					l427:
						position, tokenIndex = position427, tokenIndex427
					}
					if buffer[position] != rune(':') {
						goto l422
					}
					position++
					goto l423
				l422:
					position, tokenIndex = position422, tokenIndex422
				}
			l423:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l420
				}
				position++
			l433:
				{
					position434, tokenIndex434 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l434
					}
					position++
					goto l433
				l434:
					position, tokenIndex = position434, tokenIndex434
				}
				add(ruleAbsolute, position421)
			}
			return true
		l420:
			position, tokenIndex = position420, tokenIndex420
			return false
		},
		/* 36 Section <- <([a-z] / [A-Z] / '@')+> */
		func() bool {
			position435, tokenIndex435 := position, tokenIndex
			{
				position436 := position
				{
					position439, tokenIndex439 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l440
					}
					position++
					goto l439
				l440:
					position, tokenIndex = position439, tokenIndex439
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l441
					}
					position++
					goto l439
				l441:
					position, tokenIndex = position439, tokenIndex439
					if buffer[position] != rune('@') {
						goto l435
					}
					position++
				}
			l439:
			l437:
				{
					position438, tokenIndex438 := position, tokenIndex
					{
						position442, tokenIndex442 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l443
						}
						position++
						goto l442
					l443:
						position, tokenIndex = position442, tokenIndex442
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l444
						}
						position++
						goto l442
					l444:
						position, tokenIndex = position442, tokenIndex442
						if buffer[position] != rune('@') {
							goto l438
						}
						position++
					}
				l442:
					goto l437
				l438:
					position, tokenIndex = position438, tokenIndex438
				}
				add(ruleSection, position436)
			}
			return true
		l435:
			position, tokenIndex = position435, tokenIndex435
			return false
		},
	}
	p.rules = _rules
}
