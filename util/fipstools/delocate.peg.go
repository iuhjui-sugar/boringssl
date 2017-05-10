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
		/* 13 SymbolArg <- <(Offset / (LocalSymbol Operator LocalSymbol) / (LocalSymbol Operator Offset) / ('.' WS? Operator WS? Offset) / (Offset Operator LocalSymbol) / LocalSymbol)> */
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
					if buffer[position] != rune('.') {
						goto l191
					}
					position++
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
		/* 14 EscapedChar <- <('\\' .)> */
		func() bool {
			position197, tokenIndex197 := position, tokenIndex
			{
				position198 := position
				if buffer[position] != rune('\\') {
					goto l197
				}
				position++
				if !matchDot() {
					goto l197
				}
				add(ruleEscapedChar, position198)
			}
			return true
		l197:
			position, tokenIndex = position197, tokenIndex197
			return false
		},
		/* 15 WS <- <(' ' / '\t')+> */
		func() bool {
			position199, tokenIndex199 := position, tokenIndex
			{
				position200 := position
				{
					position203, tokenIndex203 := position, tokenIndex
					if buffer[position] != rune(' ') {
						goto l204
					}
					position++
					goto l203
				l204:
					position, tokenIndex = position203, tokenIndex203
					if buffer[position] != rune('\t') {
						goto l199
					}
					position++
				}
			l203:
			l201:
				{
					position202, tokenIndex202 := position, tokenIndex
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
							goto l202
						}
						position++
					}
				l205:
					goto l201
				l202:
					position, tokenIndex = position202, tokenIndex202
				}
				add(ruleWS, position200)
			}
			return true
		l199:
			position, tokenIndex = position199, tokenIndex199
			return false
		},
		/* 16 Comment <- <('#' (!'\n' .)*)> */
		func() bool {
			position207, tokenIndex207 := position, tokenIndex
			{
				position208 := position
				if buffer[position] != rune('#') {
					goto l207
				}
				position++
			l209:
				{
					position210, tokenIndex210 := position, tokenIndex
					{
						position211, tokenIndex211 := position, tokenIndex
						if buffer[position] != rune('\n') {
							goto l211
						}
						position++
						goto l210
					l211:
						position, tokenIndex = position211, tokenIndex211
					}
					if !matchDot() {
						goto l210
					}
					goto l209
				l210:
					position, tokenIndex = position210, tokenIndex210
				}
				add(ruleComment, position208)
			}
			return true
		l207:
			position, tokenIndex = position207, tokenIndex207
			return false
		},
		/* 17 Label <- <((LocalSymbol / LocalLabel / SymbolName) ':')> */
		func() bool {
			position212, tokenIndex212 := position, tokenIndex
			{
				position213 := position
				{
					position214, tokenIndex214 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l215
					}
					goto l214
				l215:
					position, tokenIndex = position214, tokenIndex214
					if !_rules[ruleLocalLabel]() {
						goto l216
					}
					goto l214
				l216:
					position, tokenIndex = position214, tokenIndex214
					if !_rules[ruleSymbolName]() {
						goto l212
					}
				}
			l214:
				if buffer[position] != rune(':') {
					goto l212
				}
				position++
				add(ruleLabel, position213)
			}
			return true
		l212:
			position, tokenIndex = position212, tokenIndex212
			return false
		},
		/* 18 SymbolName <- <(([a-z] / [A-Z] / '.' / '_') ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')*)> */
		func() bool {
			position217, tokenIndex217 := position, tokenIndex
			{
				position218 := position
				{
					position219, tokenIndex219 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l220
					}
					position++
					goto l219
				l220:
					position, tokenIndex = position219, tokenIndex219
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l221
					}
					position++
					goto l219
				l221:
					position, tokenIndex = position219, tokenIndex219
					if buffer[position] != rune('.') {
						goto l222
					}
					position++
					goto l219
				l222:
					position, tokenIndex = position219, tokenIndex219
					if buffer[position] != rune('_') {
						goto l217
					}
					position++
				}
			l219:
			l223:
				{
					position224, tokenIndex224 := position, tokenIndex
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
						{
							position230, tokenIndex230 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l231
							}
							position++
							goto l230
						l231:
							position, tokenIndex = position230, tokenIndex230
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l229
							}
							position++
						}
					l230:
						goto l225
					l229:
						position, tokenIndex = position225, tokenIndex225
						if buffer[position] != rune('$') {
							goto l232
						}
						position++
						goto l225
					l232:
						position, tokenIndex = position225, tokenIndex225
						if buffer[position] != rune('_') {
							goto l224
						}
						position++
					}
				l225:
					goto l223
				l224:
					position, tokenIndex = position224, tokenIndex224
				}
				add(ruleSymbolName, position218)
			}
			return true
		l217:
			position, tokenIndex = position217, tokenIndex217
			return false
		},
		/* 19 LocalSymbol <- <('.' 'L' ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')+)> */
		func() bool {
			position233, tokenIndex233 := position, tokenIndex
			{
				position234 := position
				if buffer[position] != rune('.') {
					goto l233
				}
				position++
				if buffer[position] != rune('L') {
					goto l233
				}
				position++
				{
					position237, tokenIndex237 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l238
					}
					position++
					goto l237
				l238:
					position, tokenIndex = position237, tokenIndex237
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l239
					}
					position++
					goto l237
				l239:
					position, tokenIndex = position237, tokenIndex237
					if buffer[position] != rune('.') {
						goto l240
					}
					position++
					goto l237
				l240:
					position, tokenIndex = position237, tokenIndex237
					{
						position242, tokenIndex242 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l243
						}
						position++
						goto l242
					l243:
						position, tokenIndex = position242, tokenIndex242
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l241
						}
						position++
					}
				l242:
					goto l237
				l241:
					position, tokenIndex = position237, tokenIndex237
					if buffer[position] != rune('$') {
						goto l244
					}
					position++
					goto l237
				l244:
					position, tokenIndex = position237, tokenIndex237
					if buffer[position] != rune('_') {
						goto l233
					}
					position++
				}
			l237:
			l235:
				{
					position236, tokenIndex236 := position, tokenIndex
					{
						position245, tokenIndex245 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l246
						}
						position++
						goto l245
					l246:
						position, tokenIndex = position245, tokenIndex245
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l247
						}
						position++
						goto l245
					l247:
						position, tokenIndex = position245, tokenIndex245
						if buffer[position] != rune('.') {
							goto l248
						}
						position++
						goto l245
					l248:
						position, tokenIndex = position245, tokenIndex245
						{
							position250, tokenIndex250 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l251
							}
							position++
							goto l250
						l251:
							position, tokenIndex = position250, tokenIndex250
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l249
							}
							position++
						}
					l250:
						goto l245
					l249:
						position, tokenIndex = position245, tokenIndex245
						if buffer[position] != rune('$') {
							goto l252
						}
						position++
						goto l245
					l252:
						position, tokenIndex = position245, tokenIndex245
						if buffer[position] != rune('_') {
							goto l236
						}
						position++
					}
				l245:
					goto l235
				l236:
					position, tokenIndex = position236, tokenIndex236
				}
				add(ruleLocalSymbol, position234)
			}
			return true
		l233:
			position, tokenIndex = position233, tokenIndex233
			return false
		},
		/* 20 LocalLabel <- <([0-9] ([0-9] / '$')*)> */
		func() bool {
			position253, tokenIndex253 := position, tokenIndex
			{
				position254 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l253
				}
				position++
			l255:
				{
					position256, tokenIndex256 := position, tokenIndex
					{
						position257, tokenIndex257 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l258
						}
						position++
						goto l257
					l258:
						position, tokenIndex = position257, tokenIndex257
						if buffer[position] != rune('$') {
							goto l256
						}
						position++
					}
				l257:
					goto l255
				l256:
					position, tokenIndex = position256, tokenIndex256
				}
				add(ruleLocalLabel, position254)
			}
			return true
		l253:
			position, tokenIndex = position253, tokenIndex253
			return false
		},
		/* 21 LocalLabelRef <- <([0-9] ([0-9] / '$')* ('b' / 'f'))> */
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
				{
					position265, tokenIndex265 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l266
					}
					position++
					goto l265
				l266:
					position, tokenIndex = position265, tokenIndex265
					if buffer[position] != rune('f') {
						goto l259
					}
					position++
				}
			l265:
				add(ruleLocalLabelRef, position260)
			}
			return true
		l259:
			position, tokenIndex = position259, tokenIndex259
			return false
		},
		/* 22 Instruction <- <(InstructionName WS? InstructionArg? WS? (',' WS? InstructionArg)*)> */
		func() bool {
			position267, tokenIndex267 := position, tokenIndex
			{
				position268 := position
				if !_rules[ruleInstructionName]() {
					goto l267
				}
				{
					position269, tokenIndex269 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l269
					}
					goto l270
				l269:
					position, tokenIndex = position269, tokenIndex269
				}
			l270:
				{
					position271, tokenIndex271 := position, tokenIndex
					if !_rules[ruleInstructionArg]() {
						goto l271
					}
					goto l272
				l271:
					position, tokenIndex = position271, tokenIndex271
				}
			l272:
				{
					position273, tokenIndex273 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l273
					}
					goto l274
				l273:
					position, tokenIndex = position273, tokenIndex273
				}
			l274:
			l275:
				{
					position276, tokenIndex276 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l276
					}
					position++
					{
						position277, tokenIndex277 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l277
						}
						goto l278
					l277:
						position, tokenIndex = position277, tokenIndex277
					}
				l278:
					if !_rules[ruleInstructionArg]() {
						goto l276
					}
					goto l275
				l276:
					position, tokenIndex = position276, tokenIndex276
				}
				add(ruleInstruction, position268)
			}
			return true
		l267:
			position, tokenIndex = position267, tokenIndex267
			return false
		},
		/* 23 InstructionName <- <(([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* ('.' / '+' / '-')?)> */
		func() bool {
			position279, tokenIndex279 := position, tokenIndex
			{
				position280 := position
				{
					position281, tokenIndex281 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l282
					}
					position++
					goto l281
				l282:
					position, tokenIndex = position281, tokenIndex281
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l279
					}
					position++
				}
			l281:
			l283:
				{
					position284, tokenIndex284 := position, tokenIndex
					{
						position285, tokenIndex285 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l286
						}
						position++
						goto l285
					l286:
						position, tokenIndex = position285, tokenIndex285
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l287
						}
						position++
						goto l285
					l287:
						position, tokenIndex = position285, tokenIndex285
						{
							position288, tokenIndex288 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l289
							}
							position++
							goto l288
						l289:
							position, tokenIndex = position288, tokenIndex288
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l284
							}
							position++
						}
					l288:
					}
				l285:
					goto l283
				l284:
					position, tokenIndex = position284, tokenIndex284
				}
				{
					position290, tokenIndex290 := position, tokenIndex
					{
						position292, tokenIndex292 := position, tokenIndex
						if buffer[position] != rune('.') {
							goto l293
						}
						position++
						goto l292
					l293:
						position, tokenIndex = position292, tokenIndex292
						if buffer[position] != rune('+') {
							goto l294
						}
						position++
						goto l292
					l294:
						position, tokenIndex = position292, tokenIndex292
						if buffer[position] != rune('-') {
							goto l290
						}
						position++
					}
				l292:
					goto l291
				l290:
					position, tokenIndex = position290, tokenIndex290
				}
			l291:
				add(ruleInstructionName, position280)
			}
			return true
		l279:
			position, tokenIndex = position279, tokenIndex279
			return false
		},
		/* 24 InstructionArg <- <(IndirectionIndicator? (RegisterOrConstant / LocalLabelRef / TOCRefHigh / TOCRefLow / MemoryRef))> */
		func() bool {
			position295, tokenIndex295 := position, tokenIndex
			{
				position296 := position
				{
					position297, tokenIndex297 := position, tokenIndex
					if !_rules[ruleIndirectionIndicator]() {
						goto l297
					}
					goto l298
				l297:
					position, tokenIndex = position297, tokenIndex297
				}
			l298:
				{
					position299, tokenIndex299 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l300
					}
					goto l299
				l300:
					position, tokenIndex = position299, tokenIndex299
					if !_rules[ruleLocalLabelRef]() {
						goto l301
					}
					goto l299
				l301:
					position, tokenIndex = position299, tokenIndex299
					if !_rules[ruleTOCRefHigh]() {
						goto l302
					}
					goto l299
				l302:
					position, tokenIndex = position299, tokenIndex299
					if !_rules[ruleTOCRefLow]() {
						goto l303
					}
					goto l299
				l303:
					position, tokenIndex = position299, tokenIndex299
					if !_rules[ruleMemoryRef]() {
						goto l295
					}
				}
			l299:
				add(ruleInstructionArg, position296)
			}
			return true
		l295:
			position, tokenIndex = position295, tokenIndex295
			return false
		},
		/* 25 TOCRefHigh <- <('.' ('t' / 'T') ('o' / 'O') ('c' / 'C') '.' '-' '0' ('b' / 'B') '@' ('h' / 'H') ('a' / 'A'))> */
		func() bool {
			position304, tokenIndex304 := position, tokenIndex
			{
				position305 := position
				if buffer[position] != rune('.') {
					goto l304
				}
				position++
				{
					position306, tokenIndex306 := position, tokenIndex
					if buffer[position] != rune('t') {
						goto l307
					}
					position++
					goto l306
				l307:
					position, tokenIndex = position306, tokenIndex306
					if buffer[position] != rune('T') {
						goto l304
					}
					position++
				}
			l306:
				{
					position308, tokenIndex308 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l309
					}
					position++
					goto l308
				l309:
					position, tokenIndex = position308, tokenIndex308
					if buffer[position] != rune('O') {
						goto l304
					}
					position++
				}
			l308:
				{
					position310, tokenIndex310 := position, tokenIndex
					if buffer[position] != rune('c') {
						goto l311
					}
					position++
					goto l310
				l311:
					position, tokenIndex = position310, tokenIndex310
					if buffer[position] != rune('C') {
						goto l304
					}
					position++
				}
			l310:
				if buffer[position] != rune('.') {
					goto l304
				}
				position++
				if buffer[position] != rune('-') {
					goto l304
				}
				position++
				if buffer[position] != rune('0') {
					goto l304
				}
				position++
				{
					position312, tokenIndex312 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l313
					}
					position++
					goto l312
				l313:
					position, tokenIndex = position312, tokenIndex312
					if buffer[position] != rune('B') {
						goto l304
					}
					position++
				}
			l312:
				if buffer[position] != rune('@') {
					goto l304
				}
				position++
				{
					position314, tokenIndex314 := position, tokenIndex
					if buffer[position] != rune('h') {
						goto l315
					}
					position++
					goto l314
				l315:
					position, tokenIndex = position314, tokenIndex314
					if buffer[position] != rune('H') {
						goto l304
					}
					position++
				}
			l314:
				{
					position316, tokenIndex316 := position, tokenIndex
					if buffer[position] != rune('a') {
						goto l317
					}
					position++
					goto l316
				l317:
					position, tokenIndex = position316, tokenIndex316
					if buffer[position] != rune('A') {
						goto l304
					}
					position++
				}
			l316:
				add(ruleTOCRefHigh, position305)
			}
			return true
		l304:
			position, tokenIndex = position304, tokenIndex304
			return false
		},
		/* 26 TOCRefLow <- <('.' ('t' / 'T') ('o' / 'O') ('c' / 'C') '.' '-' '0' ('b' / 'B') '@' ('l' / 'L'))> */
		func() bool {
			position318, tokenIndex318 := position, tokenIndex
			{
				position319 := position
				if buffer[position] != rune('.') {
					goto l318
				}
				position++
				{
					position320, tokenIndex320 := position, tokenIndex
					if buffer[position] != rune('t') {
						goto l321
					}
					position++
					goto l320
				l321:
					position, tokenIndex = position320, tokenIndex320
					if buffer[position] != rune('T') {
						goto l318
					}
					position++
				}
			l320:
				{
					position322, tokenIndex322 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l323
					}
					position++
					goto l322
				l323:
					position, tokenIndex = position322, tokenIndex322
					if buffer[position] != rune('O') {
						goto l318
					}
					position++
				}
			l322:
				{
					position324, tokenIndex324 := position, tokenIndex
					if buffer[position] != rune('c') {
						goto l325
					}
					position++
					goto l324
				l325:
					position, tokenIndex = position324, tokenIndex324
					if buffer[position] != rune('C') {
						goto l318
					}
					position++
				}
			l324:
				if buffer[position] != rune('.') {
					goto l318
				}
				position++
				if buffer[position] != rune('-') {
					goto l318
				}
				position++
				if buffer[position] != rune('0') {
					goto l318
				}
				position++
				{
					position326, tokenIndex326 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l327
					}
					position++
					goto l326
				l327:
					position, tokenIndex = position326, tokenIndex326
					if buffer[position] != rune('B') {
						goto l318
					}
					position++
				}
			l326:
				if buffer[position] != rune('@') {
					goto l318
				}
				position++
				{
					position328, tokenIndex328 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l329
					}
					position++
					goto l328
				l329:
					position, tokenIndex = position328, tokenIndex328
					if buffer[position] != rune('L') {
						goto l318
					}
					position++
				}
			l328:
				add(ruleTOCRefLow, position319)
			}
			return true
		l318:
			position, tokenIndex = position318, tokenIndex318
			return false
		},
		/* 27 IndirectionIndicator <- <'*'> */
		func() bool {
			position330, tokenIndex330 := position, tokenIndex
			{
				position331 := position
				if buffer[position] != rune('*') {
					goto l330
				}
				position++
				add(ruleIndirectionIndicator, position331)
			}
			return true
		l330:
			position, tokenIndex = position330, tokenIndex330
			return false
		},
		/* 28 RegisterOrConstant <- <((('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))*) / ('$'? ((Offset Offset) / Offset))) !('f' / 'b' / ':' / '(' / '+' / '-'))> */
		func() bool {
			position332, tokenIndex332 := position, tokenIndex
			{
				position333 := position
				{
					position334, tokenIndex334 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l335
					}
					position++
					{
						position336, tokenIndex336 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l337
						}
						position++
						goto l336
					l337:
						position, tokenIndex = position336, tokenIndex336
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l335
						}
						position++
					}
				l336:
				l338:
					{
						position339, tokenIndex339 := position, tokenIndex
						{
							position340, tokenIndex340 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l341
							}
							position++
							goto l340
						l341:
							position, tokenIndex = position340, tokenIndex340
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l342
							}
							position++
							goto l340
						l342:
							position, tokenIndex = position340, tokenIndex340
							{
								position343, tokenIndex343 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l344
								}
								position++
								goto l343
							l344:
								position, tokenIndex = position343, tokenIndex343
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l339
								}
								position++
							}
						l343:
						}
					l340:
						goto l338
					l339:
						position, tokenIndex = position339, tokenIndex339
					}
					goto l334
				l335:
					position, tokenIndex = position334, tokenIndex334
					{
						position345, tokenIndex345 := position, tokenIndex
						if buffer[position] != rune('$') {
							goto l345
						}
						position++
						goto l346
					l345:
						position, tokenIndex = position345, tokenIndex345
					}
				l346:
					{
						position347, tokenIndex347 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l348
						}
						if !_rules[ruleOffset]() {
							goto l348
						}
						goto l347
					l348:
						position, tokenIndex = position347, tokenIndex347
						if !_rules[ruleOffset]() {
							goto l332
						}
					}
				l347:
				}
			l334:
				{
					position349, tokenIndex349 := position, tokenIndex
					{
						position350, tokenIndex350 := position, tokenIndex
						if buffer[position] != rune('f') {
							goto l351
						}
						position++
						goto l350
					l351:
						position, tokenIndex = position350, tokenIndex350
						if buffer[position] != rune('b') {
							goto l352
						}
						position++
						goto l350
					l352:
						position, tokenIndex = position350, tokenIndex350
						if buffer[position] != rune(':') {
							goto l353
						}
						position++
						goto l350
					l353:
						position, tokenIndex = position350, tokenIndex350
						if buffer[position] != rune('(') {
							goto l354
						}
						position++
						goto l350
					l354:
						position, tokenIndex = position350, tokenIndex350
						if buffer[position] != rune('+') {
							goto l355
						}
						position++
						goto l350
					l355:
						position, tokenIndex = position350, tokenIndex350
						if buffer[position] != rune('-') {
							goto l349
						}
						position++
					}
				l350:
					goto l332
				l349:
					position, tokenIndex = position349, tokenIndex349
				}
				add(ruleRegisterOrConstant, position333)
			}
			return true
		l332:
			position, tokenIndex = position332, tokenIndex332
			return false
		},
		/* 29 MemoryRef <- <((Offset Operator SymbolRef BaseIndexScale) / (SymbolRef Operator Offset BaseIndexScale) / (SymbolRef BaseIndexScale) / (Offset BaseIndexScale) / (Offset Operator Offset BaseIndexScale) / (SymbolRef Operator Offset Operator Offset BaseIndexScale) / (Offset Operator Offset Operator Offset BaseIndexScale) / SymbolRef / BaseIndexScale / Absolute)> */
		func() bool {
			position356, tokenIndex356 := position, tokenIndex
			{
				position357 := position
				{
					position358, tokenIndex358 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l359
					}
					if !_rules[ruleOperator]() {
						goto l359
					}
					if !_rules[ruleSymbolRef]() {
						goto l359
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l359
					}
					goto l358
				l359:
					position, tokenIndex = position358, tokenIndex358
					if !_rules[ruleSymbolRef]() {
						goto l360
					}
					if !_rules[ruleOperator]() {
						goto l360
					}
					if !_rules[ruleOffset]() {
						goto l360
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l360
					}
					goto l358
				l360:
					position, tokenIndex = position358, tokenIndex358
					if !_rules[ruleSymbolRef]() {
						goto l361
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l361
					}
					goto l358
				l361:
					position, tokenIndex = position358, tokenIndex358
					if !_rules[ruleOffset]() {
						goto l362
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l362
					}
					goto l358
				l362:
					position, tokenIndex = position358, tokenIndex358
					if !_rules[ruleOffset]() {
						goto l363
					}
					if !_rules[ruleOperator]() {
						goto l363
					}
					if !_rules[ruleOffset]() {
						goto l363
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l363
					}
					goto l358
				l363:
					position, tokenIndex = position358, tokenIndex358
					if !_rules[ruleSymbolRef]() {
						goto l364
					}
					if !_rules[ruleOperator]() {
						goto l364
					}
					if !_rules[ruleOffset]() {
						goto l364
					}
					if !_rules[ruleOperator]() {
						goto l364
					}
					if !_rules[ruleOffset]() {
						goto l364
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l364
					}
					goto l358
				l364:
					position, tokenIndex = position358, tokenIndex358
					if !_rules[ruleOffset]() {
						goto l365
					}
					if !_rules[ruleOperator]() {
						goto l365
					}
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
					goto l358
				l365:
					position, tokenIndex = position358, tokenIndex358
					if !_rules[ruleSymbolRef]() {
						goto l366
					}
					goto l358
				l366:
					position, tokenIndex = position358, tokenIndex358
					if !_rules[ruleBaseIndexScale]() {
						goto l367
					}
					goto l358
				l367:
					position, tokenIndex = position358, tokenIndex358
					if !_rules[ruleAbsolute]() {
						goto l356
					}
				}
			l358:
				add(ruleMemoryRef, position357)
			}
			return true
		l356:
			position, tokenIndex = position356, tokenIndex356
			return false
		},
		/* 30 SymbolRef <- <((LocalSymbol / SymbolName) Offset? ('@' Section)?)> */
		func() bool {
			position368, tokenIndex368 := position, tokenIndex
			{
				position369 := position
				{
					position370, tokenIndex370 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l371
					}
					goto l370
				l371:
					position, tokenIndex = position370, tokenIndex370
					if !_rules[ruleSymbolName]() {
						goto l368
					}
				}
			l370:
				{
					position372, tokenIndex372 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l372
					}
					goto l373
				l372:
					position, tokenIndex = position372, tokenIndex372
				}
			l373:
				{
					position374, tokenIndex374 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l374
					}
					position++
					if !_rules[ruleSection]() {
						goto l374
					}
					goto l375
				l374:
					position, tokenIndex = position374, tokenIndex374
				}
			l375:
				add(ruleSymbolRef, position369)
			}
			return true
		l368:
			position, tokenIndex = position368, tokenIndex368
			return false
		},
		/* 31 BaseIndexScale <- <('(' RegisterOrConstant? WS? (',' WS? RegisterOrConstant WS? (',' [0-9]+)?)? ')')> */
		func() bool {
			position376, tokenIndex376 := position, tokenIndex
			{
				position377 := position
				if buffer[position] != rune('(') {
					goto l376
				}
				position++
				{
					position378, tokenIndex378 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l378
					}
					goto l379
				l378:
					position, tokenIndex = position378, tokenIndex378
				}
			l379:
				{
					position380, tokenIndex380 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l380
					}
					goto l381
				l380:
					position, tokenIndex = position380, tokenIndex380
				}
			l381:
				{
					position382, tokenIndex382 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l382
					}
					position++
					{
						position384, tokenIndex384 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l384
						}
						goto l385
					l384:
						position, tokenIndex = position384, tokenIndex384
					}
				l385:
					if !_rules[ruleRegisterOrConstant]() {
						goto l382
					}
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
					{
						position388, tokenIndex388 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l388
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l388
						}
						position++
					l390:
						{
							position391, tokenIndex391 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l391
							}
							position++
							goto l390
						l391:
							position, tokenIndex = position391, tokenIndex391
						}
						goto l389
					l388:
						position, tokenIndex = position388, tokenIndex388
					}
				l389:
					goto l383
				l382:
					position, tokenIndex = position382, tokenIndex382
				}
			l383:
				if buffer[position] != rune(')') {
					goto l376
				}
				position++
				add(ruleBaseIndexScale, position377)
			}
			return true
		l376:
			position, tokenIndex = position376, tokenIndex376
			return false
		},
		/* 32 Operator <- <('+' / '-')> */
		func() bool {
			position392, tokenIndex392 := position, tokenIndex
			{
				position393 := position
				{
					position394, tokenIndex394 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l395
					}
					position++
					goto l394
				l395:
					position, tokenIndex = position394, tokenIndex394
					if buffer[position] != rune('-') {
						goto l392
					}
					position++
				}
			l394:
				add(ruleOperator, position393)
			}
			return true
		l392:
			position, tokenIndex = position392, tokenIndex392
			return false
		},
		/* 33 Offset <- <(('+' / '-')? (('0' 'x' ([0-9] / [0-9] / ([a-f] / [A-F]))+) / [0-9]+))> */
		func() bool {
			position396, tokenIndex396 := position, tokenIndex
			{
				position397 := position
				{
					position398, tokenIndex398 := position, tokenIndex
					{
						position400, tokenIndex400 := position, tokenIndex
						if buffer[position] != rune('+') {
							goto l401
						}
						position++
						goto l400
					l401:
						position, tokenIndex = position400, tokenIndex400
						if buffer[position] != rune('-') {
							goto l398
						}
						position++
					}
				l400:
					goto l399
				l398:
					position, tokenIndex = position398, tokenIndex398
				}
			l399:
				{
					position402, tokenIndex402 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l403
					}
					position++
					if buffer[position] != rune('x') {
						goto l403
					}
					position++
					{
						position406, tokenIndex406 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l407
						}
						position++
						goto l406
					l407:
						position, tokenIndex = position406, tokenIndex406
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l408
						}
						position++
						goto l406
					l408:
						position, tokenIndex = position406, tokenIndex406
						{
							position409, tokenIndex409 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('f') {
								goto l410
							}
							position++
							goto l409
						l410:
							position, tokenIndex = position409, tokenIndex409
							if c := buffer[position]; c < rune('A') || c > rune('F') {
								goto l403
							}
							position++
						}
					l409:
					}
				l406:
				l404:
					{
						position405, tokenIndex405 := position, tokenIndex
						{
							position411, tokenIndex411 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l412
							}
							position++
							goto l411
						l412:
							position, tokenIndex = position411, tokenIndex411
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l413
							}
							position++
							goto l411
						l413:
							position, tokenIndex = position411, tokenIndex411
							{
								position414, tokenIndex414 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('f') {
									goto l415
								}
								position++
								goto l414
							l415:
								position, tokenIndex = position414, tokenIndex414
								if c := buffer[position]; c < rune('A') || c > rune('F') {
									goto l405
								}
								position++
							}
						l414:
						}
					l411:
						goto l404
					l405:
						position, tokenIndex = position405, tokenIndex405
					}
					goto l402
				l403:
					position, tokenIndex = position402, tokenIndex402
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l396
					}
					position++
				l416:
					{
						position417, tokenIndex417 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l417
						}
						position++
						goto l416
					l417:
						position, tokenIndex = position417, tokenIndex417
					}
				}
			l402:
				add(ruleOffset, position397)
			}
			return true
		l396:
			position, tokenIndex = position396, tokenIndex396
			return false
		},
		/* 34 Absolute <- <(('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* ':')? [0-9]+)> */
		func() bool {
			position418, tokenIndex418 := position, tokenIndex
			{
				position419 := position
				{
					position420, tokenIndex420 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l420
					}
					position++
					{
						position422, tokenIndex422 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l423
						}
						position++
						goto l422
					l423:
						position, tokenIndex = position422, tokenIndex422
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l420
						}
						position++
					}
				l422:
				l424:
					{
						position425, tokenIndex425 := position, tokenIndex
						{
							position426, tokenIndex426 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l427
							}
							position++
							goto l426
						l427:
							position, tokenIndex = position426, tokenIndex426
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l428
							}
							position++
							goto l426
						l428:
							position, tokenIndex = position426, tokenIndex426
							{
								position429, tokenIndex429 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l430
								}
								position++
								goto l429
							l430:
								position, tokenIndex = position429, tokenIndex429
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l425
								}
								position++
							}
						l429:
						}
					l426:
						goto l424
					l425:
						position, tokenIndex = position425, tokenIndex425
					}
					if buffer[position] != rune(':') {
						goto l420
					}
					position++
					goto l421
				l420:
					position, tokenIndex = position420, tokenIndex420
				}
			l421:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l418
				}
				position++
			l431:
				{
					position432, tokenIndex432 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l432
					}
					position++
					goto l431
				l432:
					position, tokenIndex = position432, tokenIndex432
				}
				add(ruleAbsolute, position419)
			}
			return true
		l418:
			position, tokenIndex = position418, tokenIndex418
			return false
		},
		/* 35 Section <- <([a-z] / [A-Z] / '@')+> */
		func() bool {
			position433, tokenIndex433 := position, tokenIndex
			{
				position434 := position
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
					if buffer[position] != rune('@') {
						goto l433
					}
					position++
				}
			l437:
			l435:
				{
					position436, tokenIndex436 := position, tokenIndex
					{
						position440, tokenIndex440 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l441
						}
						position++
						goto l440
					l441:
						position, tokenIndex = position440, tokenIndex440
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l442
						}
						position++
						goto l440
					l442:
						position, tokenIndex = position440, tokenIndex440
						if buffer[position] != rune('@') {
							goto l436
						}
						position++
					}
				l440:
					goto l435
				l436:
					position, tokenIndex = position436, tokenIndex436
				}
				add(ruleSection, position434)
			}
			return true
		l433:
			position, tokenIndex = position433, tokenIndex433
			return false
		},
	}
	p.rules = _rules
}
