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
	ruleArgs
	ruleArg
	ruleQuotedArg
	ruleQuotedText
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
	ruleIndirectionIndicator
	ruleRegister
	ruleConstant
	ruleMemoryRef
	ruleSymbolRef
	ruleBaseIndexScale
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
	"Args",
	"Arg",
	"QuotedArg",
	"QuotedText",
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
	"IndirectionIndicator",
	"Register",
	"Constant",
	"MemoryRef",
	"SymbolRef",
	"BaseIndexScale",
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
	rules  [30]func() bool
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
		/* 1 Statement <- <(WS? (GlobalDirective / Label / Instruction / Directive / ) WS? ((Comment? '\n') / ';'))> */
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
					if !_rules[ruleGlobalDirective]() {
						goto l10
					}
					goto l9
				l10:
					position, tokenIndex = position9, tokenIndex9
					if !_rules[ruleLabel]() {
						goto l11
					}
					goto l9
				l11:
					position, tokenIndex = position9, tokenIndex9
					if !_rules[ruleInstruction]() {
						goto l12
					}
					goto l9
				l12:
					position, tokenIndex = position9, tokenIndex9
					if !_rules[ruleDirective]() {
						goto l13
					}
					goto l9
				l13:
					position, tokenIndex = position9, tokenIndex9
				}
			l9:
				{
					position14, tokenIndex14 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l14
					}
					goto l15
				l14:
					position, tokenIndex = position14, tokenIndex14
				}
			l15:
				{
					position16, tokenIndex16 := position, tokenIndex
					{
						position18, tokenIndex18 := position, tokenIndex
						if !_rules[ruleComment]() {
							goto l18
						}
						goto l19
					l18:
						position, tokenIndex = position18, tokenIndex18
					}
				l19:
					if buffer[position] != rune('\n') {
						goto l17
					}
					position++
					goto l16
				l17:
					position, tokenIndex = position16, tokenIndex16
					if buffer[position] != rune(';') {
						goto l5
					}
					position++
				}
			l16:
				add(ruleStatement, position6)
			}
			return true
		l5:
			position, tokenIndex = position5, tokenIndex5
			return false
		},
		/* 2 GlobalDirective <- <((('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('a' / 'A') ('l' / 'L')) / ('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('l' / 'L'))) WS SymbolName)> */
		func() bool {
			position20, tokenIndex20 := position, tokenIndex
			{
				position21 := position
				{
					position22, tokenIndex22 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l23
					}
					position++
					{
						position24, tokenIndex24 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l25
						}
						position++
						goto l24
					l25:
						position, tokenIndex = position24, tokenIndex24
						if buffer[position] != rune('G') {
							goto l23
						}
						position++
					}
				l24:
					{
						position26, tokenIndex26 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l27
						}
						position++
						goto l26
					l27:
						position, tokenIndex = position26, tokenIndex26
						if buffer[position] != rune('L') {
							goto l23
						}
						position++
					}
				l26:
					{
						position28, tokenIndex28 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l29
						}
						position++
						goto l28
					l29:
						position, tokenIndex = position28, tokenIndex28
						if buffer[position] != rune('O') {
							goto l23
						}
						position++
					}
				l28:
					{
						position30, tokenIndex30 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l31
						}
						position++
						goto l30
					l31:
						position, tokenIndex = position30, tokenIndex30
						if buffer[position] != rune('B') {
							goto l23
						}
						position++
					}
				l30:
					{
						position32, tokenIndex32 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l33
						}
						position++
						goto l32
					l33:
						position, tokenIndex = position32, tokenIndex32
						if buffer[position] != rune('A') {
							goto l23
						}
						position++
					}
				l32:
					{
						position34, tokenIndex34 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l35
						}
						position++
						goto l34
					l35:
						position, tokenIndex = position34, tokenIndex34
						if buffer[position] != rune('L') {
							goto l23
						}
						position++
					}
				l34:
					goto l22
				l23:
					position, tokenIndex = position22, tokenIndex22
					if buffer[position] != rune('.') {
						goto l20
					}
					position++
					{
						position36, tokenIndex36 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l37
						}
						position++
						goto l36
					l37:
						position, tokenIndex = position36, tokenIndex36
						if buffer[position] != rune('G') {
							goto l20
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
							goto l20
						}
						position++
					}
				l38:
					{
						position40, tokenIndex40 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l41
						}
						position++
						goto l40
					l41:
						position, tokenIndex = position40, tokenIndex40
						if buffer[position] != rune('O') {
							goto l20
						}
						position++
					}
				l40:
					{
						position42, tokenIndex42 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l43
						}
						position++
						goto l42
					l43:
						position, tokenIndex = position42, tokenIndex42
						if buffer[position] != rune('B') {
							goto l20
						}
						position++
					}
				l42:
					{
						position44, tokenIndex44 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l45
						}
						position++
						goto l44
					l45:
						position, tokenIndex = position44, tokenIndex44
						if buffer[position] != rune('L') {
							goto l20
						}
						position++
					}
				l44:
				}
			l22:
				if !_rules[ruleWS]() {
					goto l20
				}
				if !_rules[ruleSymbolName]() {
					goto l20
				}
				add(ruleGlobalDirective, position21)
			}
			return true
		l20:
			position, tokenIndex = position20, tokenIndex20
			return false
		},
		/* 3 Directive <- <('.' DirectiveName (WS Args)?)> */
		func() bool {
			position46, tokenIndex46 := position, tokenIndex
			{
				position47 := position
				if buffer[position] != rune('.') {
					goto l46
				}
				position++
				if !_rules[ruleDirectiveName]() {
					goto l46
				}
				{
					position48, tokenIndex48 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l48
					}
					if !_rules[ruleArgs]() {
						goto l48
					}
					goto l49
				l48:
					position, tokenIndex = position48, tokenIndex48
				}
			l49:
				add(ruleDirective, position47)
			}
			return true
		l46:
			position, tokenIndex = position46, tokenIndex46
			return false
		},
		/* 4 DirectiveName <- <([a-z] / [A-Z] / ([0-9] / [0-9]) / '_')+> */
		func() bool {
			position50, tokenIndex50 := position, tokenIndex
			{
				position51 := position
				{
					position54, tokenIndex54 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l55
					}
					position++
					goto l54
				l55:
					position, tokenIndex = position54, tokenIndex54
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l56
					}
					position++
					goto l54
				l56:
					position, tokenIndex = position54, tokenIndex54
					{
						position58, tokenIndex58 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l59
						}
						position++
						goto l58
					l59:
						position, tokenIndex = position58, tokenIndex58
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l57
						}
						position++
					}
				l58:
					goto l54
				l57:
					position, tokenIndex = position54, tokenIndex54
					if buffer[position] != rune('_') {
						goto l50
					}
					position++
				}
			l54:
			l52:
				{
					position53, tokenIndex53 := position, tokenIndex
					{
						position60, tokenIndex60 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l61
						}
						position++
						goto l60
					l61:
						position, tokenIndex = position60, tokenIndex60
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l62
						}
						position++
						goto l60
					l62:
						position, tokenIndex = position60, tokenIndex60
						{
							position64, tokenIndex64 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l65
							}
							position++
							goto l64
						l65:
							position, tokenIndex = position64, tokenIndex64
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l63
							}
							position++
						}
					l64:
						goto l60
					l63:
						position, tokenIndex = position60, tokenIndex60
						if buffer[position] != rune('_') {
							goto l53
						}
						position++
					}
				l60:
					goto l52
				l53:
					position, tokenIndex = position53, tokenIndex53
				}
				add(ruleDirectiveName, position51)
			}
			return true
		l50:
			position, tokenIndex = position50, tokenIndex50
			return false
		},
		/* 5 Args <- <(Arg ((WS / (WS? ',' WS?)) Arg)*)> */
		func() bool {
			position66, tokenIndex66 := position, tokenIndex
			{
				position67 := position
				if !_rules[ruleArg]() {
					goto l66
				}
			l68:
				{
					position69, tokenIndex69 := position, tokenIndex
					{
						position70, tokenIndex70 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l71
						}
						goto l70
					l71:
						position, tokenIndex = position70, tokenIndex70
						{
							position72, tokenIndex72 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l72
							}
							goto l73
						l72:
							position, tokenIndex = position72, tokenIndex72
						}
					l73:
						if buffer[position] != rune(',') {
							goto l69
						}
						position++
						{
							position74, tokenIndex74 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l74
							}
							goto l75
						l74:
							position, tokenIndex = position74, tokenIndex74
						}
					l75:
					}
				l70:
					if !_rules[ruleArg]() {
						goto l69
					}
					goto l68
				l69:
					position, tokenIndex = position69, tokenIndex69
				}
				add(ruleArgs, position67)
			}
			return true
		l66:
			position, tokenIndex = position66, tokenIndex66
			return false
		},
		/* 6 Arg <- <(QuotedArg / ([0-9] / [0-9] / ([a-z] / [A-Z]) / '%' / '-' / '_' / '@' / '.')+)> */
		func() bool {
			position76, tokenIndex76 := position, tokenIndex
			{
				position77 := position
				{
					position78, tokenIndex78 := position, tokenIndex
					if !_rules[ruleQuotedArg]() {
						goto l79
					}
					goto l78
				l79:
					position, tokenIndex = position78, tokenIndex78
					{
						position82, tokenIndex82 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l83
						}
						position++
						goto l82
					l83:
						position, tokenIndex = position82, tokenIndex82
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l84
						}
						position++
						goto l82
					l84:
						position, tokenIndex = position82, tokenIndex82
						{
							position86, tokenIndex86 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l87
							}
							position++
							goto l86
						l87:
							position, tokenIndex = position86, tokenIndex86
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l85
							}
							position++
						}
					l86:
						goto l82
					l85:
						position, tokenIndex = position82, tokenIndex82
						if buffer[position] != rune('%') {
							goto l88
						}
						position++
						goto l82
					l88:
						position, tokenIndex = position82, tokenIndex82
						if buffer[position] != rune('-') {
							goto l89
						}
						position++
						goto l82
					l89:
						position, tokenIndex = position82, tokenIndex82
						if buffer[position] != rune('_') {
							goto l90
						}
						position++
						goto l82
					l90:
						position, tokenIndex = position82, tokenIndex82
						if buffer[position] != rune('@') {
							goto l91
						}
						position++
						goto l82
					l91:
						position, tokenIndex = position82, tokenIndex82
						if buffer[position] != rune('.') {
							goto l76
						}
						position++
					}
				l82:
				l80:
					{
						position81, tokenIndex81 := position, tokenIndex
						{
							position92, tokenIndex92 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l93
							}
							position++
							goto l92
						l93:
							position, tokenIndex = position92, tokenIndex92
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l94
							}
							position++
							goto l92
						l94:
							position, tokenIndex = position92, tokenIndex92
							{
								position96, tokenIndex96 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('z') {
									goto l97
								}
								position++
								goto l96
							l97:
								position, tokenIndex = position96, tokenIndex96
								if c := buffer[position]; c < rune('A') || c > rune('Z') {
									goto l95
								}
								position++
							}
						l96:
							goto l92
						l95:
							position, tokenIndex = position92, tokenIndex92
							if buffer[position] != rune('%') {
								goto l98
							}
							position++
							goto l92
						l98:
							position, tokenIndex = position92, tokenIndex92
							if buffer[position] != rune('-') {
								goto l99
							}
							position++
							goto l92
						l99:
							position, tokenIndex = position92, tokenIndex92
							if buffer[position] != rune('_') {
								goto l100
							}
							position++
							goto l92
						l100:
							position, tokenIndex = position92, tokenIndex92
							if buffer[position] != rune('@') {
								goto l101
							}
							position++
							goto l92
						l101:
							position, tokenIndex = position92, tokenIndex92
							if buffer[position] != rune('.') {
								goto l81
							}
							position++
						}
					l92:
						goto l80
					l81:
						position, tokenIndex = position81, tokenIndex81
					}
				}
			l78:
				add(ruleArg, position77)
			}
			return true
		l76:
			position, tokenIndex = position76, tokenIndex76
			return false
		},
		/* 7 QuotedArg <- <('"' QuotedText '"')> */
		func() bool {
			position102, tokenIndex102 := position, tokenIndex
			{
				position103 := position
				if buffer[position] != rune('"') {
					goto l102
				}
				position++
				if !_rules[ruleQuotedText]() {
					goto l102
				}
				if buffer[position] != rune('"') {
					goto l102
				}
				position++
				add(ruleQuotedArg, position103)
			}
			return true
		l102:
			position, tokenIndex = position102, tokenIndex102
			return false
		},
		/* 8 QuotedText <- <(EscapedChar / (!'"' .))*> */
		func() bool {
			{
				position105 := position
			l106:
				{
					position107, tokenIndex107 := position, tokenIndex
					{
						position108, tokenIndex108 := position, tokenIndex
						if !_rules[ruleEscapedChar]() {
							goto l109
						}
						goto l108
					l109:
						position, tokenIndex = position108, tokenIndex108
						{
							position110, tokenIndex110 := position, tokenIndex
							if buffer[position] != rune('"') {
								goto l110
							}
							position++
							goto l107
						l110:
							position, tokenIndex = position110, tokenIndex110
						}
						if !matchDot() {
							goto l107
						}
					}
				l108:
					goto l106
				l107:
					position, tokenIndex = position107, tokenIndex107
				}
				add(ruleQuotedText, position105)
			}
			return true
		},
		/* 9 EscapedChar <- <('\\' .)> */
		func() bool {
			position111, tokenIndex111 := position, tokenIndex
			{
				position112 := position
				if buffer[position] != rune('\\') {
					goto l111
				}
				position++
				if !matchDot() {
					goto l111
				}
				add(ruleEscapedChar, position112)
			}
			return true
		l111:
			position, tokenIndex = position111, tokenIndex111
			return false
		},
		/* 10 WS <- <(' ' / '\t')+> */
		func() bool {
			position113, tokenIndex113 := position, tokenIndex
			{
				position114 := position
				{
					position117, tokenIndex117 := position, tokenIndex
					if buffer[position] != rune(' ') {
						goto l118
					}
					position++
					goto l117
				l118:
					position, tokenIndex = position117, tokenIndex117
					if buffer[position] != rune('\t') {
						goto l113
					}
					position++
				}
			l117:
			l115:
				{
					position116, tokenIndex116 := position, tokenIndex
					{
						position119, tokenIndex119 := position, tokenIndex
						if buffer[position] != rune(' ') {
							goto l120
						}
						position++
						goto l119
					l120:
						position, tokenIndex = position119, tokenIndex119
						if buffer[position] != rune('\t') {
							goto l116
						}
						position++
					}
				l119:
					goto l115
				l116:
					position, tokenIndex = position116, tokenIndex116
				}
				add(ruleWS, position114)
			}
			return true
		l113:
			position, tokenIndex = position113, tokenIndex113
			return false
		},
		/* 11 Comment <- <('#' (!'\n' .)*)> */
		func() bool {
			position121, tokenIndex121 := position, tokenIndex
			{
				position122 := position
				if buffer[position] != rune('#') {
					goto l121
				}
				position++
			l123:
				{
					position124, tokenIndex124 := position, tokenIndex
					{
						position125, tokenIndex125 := position, tokenIndex
						if buffer[position] != rune('\n') {
							goto l125
						}
						position++
						goto l124
					l125:
						position, tokenIndex = position125, tokenIndex125
					}
					if !matchDot() {
						goto l124
					}
					goto l123
				l124:
					position, tokenIndex = position124, tokenIndex124
				}
				add(ruleComment, position122)
			}
			return true
		l121:
			position, tokenIndex = position121, tokenIndex121
			return false
		},
		/* 12 Label <- <((LocalSymbol / LocalLabel / SymbolName) ':')> */
		func() bool {
			position126, tokenIndex126 := position, tokenIndex
			{
				position127 := position
				{
					position128, tokenIndex128 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l129
					}
					goto l128
				l129:
					position, tokenIndex = position128, tokenIndex128
					if !_rules[ruleLocalLabel]() {
						goto l130
					}
					goto l128
				l130:
					position, tokenIndex = position128, tokenIndex128
					if !_rules[ruleSymbolName]() {
						goto l126
					}
				}
			l128:
				if buffer[position] != rune(':') {
					goto l126
				}
				position++
				add(ruleLabel, position127)
			}
			return true
		l126:
			position, tokenIndex = position126, tokenIndex126
			return false
		},
		/* 13 SymbolName <- <(([a-z] / [A-Z] / '.' / '_') ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')*)> */
		func() bool {
			position131, tokenIndex131 := position, tokenIndex
			{
				position132 := position
				{
					position133, tokenIndex133 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l134
					}
					position++
					goto l133
				l134:
					position, tokenIndex = position133, tokenIndex133
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l135
					}
					position++
					goto l133
				l135:
					position, tokenIndex = position133, tokenIndex133
					if buffer[position] != rune('.') {
						goto l136
					}
					position++
					goto l133
				l136:
					position, tokenIndex = position133, tokenIndex133
					if buffer[position] != rune('_') {
						goto l131
					}
					position++
				}
			l133:
			l137:
				{
					position138, tokenIndex138 := position, tokenIndex
					{
						position139, tokenIndex139 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l140
						}
						position++
						goto l139
					l140:
						position, tokenIndex = position139, tokenIndex139
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l141
						}
						position++
						goto l139
					l141:
						position, tokenIndex = position139, tokenIndex139
						if buffer[position] != rune('.') {
							goto l142
						}
						position++
						goto l139
					l142:
						position, tokenIndex = position139, tokenIndex139
						{
							position144, tokenIndex144 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l145
							}
							position++
							goto l144
						l145:
							position, tokenIndex = position144, tokenIndex144
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l143
							}
							position++
						}
					l144:
						goto l139
					l143:
						position, tokenIndex = position139, tokenIndex139
						if buffer[position] != rune('$') {
							goto l146
						}
						position++
						goto l139
					l146:
						position, tokenIndex = position139, tokenIndex139
						if buffer[position] != rune('_') {
							goto l138
						}
						position++
					}
				l139:
					goto l137
				l138:
					position, tokenIndex = position138, tokenIndex138
				}
				add(ruleSymbolName, position132)
			}
			return true
		l131:
			position, tokenIndex = position131, tokenIndex131
			return false
		},
		/* 14 LocalSymbol <- <('.' 'L' ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')+)> */
		func() bool {
			position147, tokenIndex147 := position, tokenIndex
			{
				position148 := position
				if buffer[position] != rune('.') {
					goto l147
				}
				position++
				if buffer[position] != rune('L') {
					goto l147
				}
				position++
				{
					position151, tokenIndex151 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l152
					}
					position++
					goto l151
				l152:
					position, tokenIndex = position151, tokenIndex151
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l153
					}
					position++
					goto l151
				l153:
					position, tokenIndex = position151, tokenIndex151
					if buffer[position] != rune('.') {
						goto l154
					}
					position++
					goto l151
				l154:
					position, tokenIndex = position151, tokenIndex151
					{
						position156, tokenIndex156 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l157
						}
						position++
						goto l156
					l157:
						position, tokenIndex = position156, tokenIndex156
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l155
						}
						position++
					}
				l156:
					goto l151
				l155:
					position, tokenIndex = position151, tokenIndex151
					if buffer[position] != rune('$') {
						goto l158
					}
					position++
					goto l151
				l158:
					position, tokenIndex = position151, tokenIndex151
					if buffer[position] != rune('_') {
						goto l147
					}
					position++
				}
			l151:
			l149:
				{
					position150, tokenIndex150 := position, tokenIndex
					{
						position159, tokenIndex159 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l160
						}
						position++
						goto l159
					l160:
						position, tokenIndex = position159, tokenIndex159
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l161
						}
						position++
						goto l159
					l161:
						position, tokenIndex = position159, tokenIndex159
						if buffer[position] != rune('.') {
							goto l162
						}
						position++
						goto l159
					l162:
						position, tokenIndex = position159, tokenIndex159
						{
							position164, tokenIndex164 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l165
							}
							position++
							goto l164
						l165:
							position, tokenIndex = position164, tokenIndex164
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l163
							}
							position++
						}
					l164:
						goto l159
					l163:
						position, tokenIndex = position159, tokenIndex159
						if buffer[position] != rune('$') {
							goto l166
						}
						position++
						goto l159
					l166:
						position, tokenIndex = position159, tokenIndex159
						if buffer[position] != rune('_') {
							goto l150
						}
						position++
					}
				l159:
					goto l149
				l150:
					position, tokenIndex = position150, tokenIndex150
				}
				add(ruleLocalSymbol, position148)
			}
			return true
		l147:
			position, tokenIndex = position147, tokenIndex147
			return false
		},
		/* 15 LocalLabel <- <([0-9] ([0-9] / '$')*)> */
		func() bool {
			position167, tokenIndex167 := position, tokenIndex
			{
				position168 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l167
				}
				position++
			l169:
				{
					position170, tokenIndex170 := position, tokenIndex
					{
						position171, tokenIndex171 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l172
						}
						position++
						goto l171
					l172:
						position, tokenIndex = position171, tokenIndex171
						if buffer[position] != rune('$') {
							goto l170
						}
						position++
					}
				l171:
					goto l169
				l170:
					position, tokenIndex = position170, tokenIndex170
				}
				add(ruleLocalLabel, position168)
			}
			return true
		l167:
			position, tokenIndex = position167, tokenIndex167
			return false
		},
		/* 16 LocalLabelRef <- <([0-9] ([0-9] / '$')* ('b' / 'f'))> */
		func() bool {
			position173, tokenIndex173 := position, tokenIndex
			{
				position174 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l173
				}
				position++
			l175:
				{
					position176, tokenIndex176 := position, tokenIndex
					{
						position177, tokenIndex177 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l178
						}
						position++
						goto l177
					l178:
						position, tokenIndex = position177, tokenIndex177
						if buffer[position] != rune('$') {
							goto l176
						}
						position++
					}
				l177:
					goto l175
				l176:
					position, tokenIndex = position176, tokenIndex176
				}
				{
					position179, tokenIndex179 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l180
					}
					position++
					goto l179
				l180:
					position, tokenIndex = position179, tokenIndex179
					if buffer[position] != rune('f') {
						goto l173
					}
					position++
				}
			l179:
				add(ruleLocalLabelRef, position174)
			}
			return true
		l173:
			position, tokenIndex = position173, tokenIndex173
			return false
		},
		/* 17 Instruction <- <(InstructionName WS? InstructionArg? WS? (',' WS? InstructionArg)*)> */
		func() bool {
			position181, tokenIndex181 := position, tokenIndex
			{
				position182 := position
				if !_rules[ruleInstructionName]() {
					goto l181
				}
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
				{
					position185, tokenIndex185 := position, tokenIndex
					if !_rules[ruleInstructionArg]() {
						goto l185
					}
					goto l186
				l185:
					position, tokenIndex = position185, tokenIndex185
				}
			l186:
				{
					position187, tokenIndex187 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l187
					}
					goto l188
				l187:
					position, tokenIndex = position187, tokenIndex187
				}
			l188:
			l189:
				{
					position190, tokenIndex190 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l190
					}
					position++
					{
						position191, tokenIndex191 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l191
						}
						goto l192
					l191:
						position, tokenIndex = position191, tokenIndex191
					}
				l192:
					if !_rules[ruleInstructionArg]() {
						goto l190
					}
					goto l189
				l190:
					position, tokenIndex = position190, tokenIndex190
				}
				add(ruleInstruction, position182)
			}
			return true
		l181:
			position, tokenIndex = position181, tokenIndex181
			return false
		},
		/* 18 InstructionName <- <(([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))+)> */
		func() bool {
			position193, tokenIndex193 := position, tokenIndex
			{
				position194 := position
				{
					position195, tokenIndex195 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l196
					}
					position++
					goto l195
				l196:
					position, tokenIndex = position195, tokenIndex195
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l193
					}
					position++
				}
			l195:
				{
					position199, tokenIndex199 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l200
					}
					position++
					goto l199
				l200:
					position, tokenIndex = position199, tokenIndex199
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l201
					}
					position++
					goto l199
				l201:
					position, tokenIndex = position199, tokenIndex199
					{
						position202, tokenIndex202 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l203
						}
						position++
						goto l202
					l203:
						position, tokenIndex = position202, tokenIndex202
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l193
						}
						position++
					}
				l202:
				}
			l199:
			l197:
				{
					position198, tokenIndex198 := position, tokenIndex
					{
						position204, tokenIndex204 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l205
						}
						position++
						goto l204
					l205:
						position, tokenIndex = position204, tokenIndex204
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l206
						}
						position++
						goto l204
					l206:
						position, tokenIndex = position204, tokenIndex204
						{
							position207, tokenIndex207 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l208
							}
							position++
							goto l207
						l208:
							position, tokenIndex = position207, tokenIndex207
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l198
							}
							position++
						}
					l207:
					}
				l204:
					goto l197
				l198:
					position, tokenIndex = position198, tokenIndex198
				}
				add(ruleInstructionName, position194)
			}
			return true
		l193:
			position, tokenIndex = position193, tokenIndex193
			return false
		},
		/* 19 InstructionArg <- <(IndirectionIndicator? (Register / Constant / LocalLabelRef / MemoryRef))> */
		func() bool {
			position209, tokenIndex209 := position, tokenIndex
			{
				position210 := position
				{
					position211, tokenIndex211 := position, tokenIndex
					if !_rules[ruleIndirectionIndicator]() {
						goto l211
					}
					goto l212
				l211:
					position, tokenIndex = position211, tokenIndex211
				}
			l212:
				{
					position213, tokenIndex213 := position, tokenIndex
					if !_rules[ruleRegister]() {
						goto l214
					}
					goto l213
				l214:
					position, tokenIndex = position213, tokenIndex213
					if !_rules[ruleConstant]() {
						goto l215
					}
					goto l213
				l215:
					position, tokenIndex = position213, tokenIndex213
					if !_rules[ruleLocalLabelRef]() {
						goto l216
					}
					goto l213
				l216:
					position, tokenIndex = position213, tokenIndex213
					if !_rules[ruleMemoryRef]() {
						goto l209
					}
				}
			l213:
				add(ruleInstructionArg, position210)
			}
			return true
		l209:
			position, tokenIndex = position209, tokenIndex209
			return false
		},
		/* 20 IndirectionIndicator <- <'*'> */
		func() bool {
			position217, tokenIndex217 := position, tokenIndex
			{
				position218 := position
				if buffer[position] != rune('*') {
					goto l217
				}
				position++
				add(ruleIndirectionIndicator, position218)
			}
			return true
		l217:
			position, tokenIndex = position217, tokenIndex217
			return false
		},
		/* 21 Register <- <('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* !':')> */
		func() bool {
			position219, tokenIndex219 := position, tokenIndex
			{
				position220 := position
				if buffer[position] != rune('%') {
					goto l219
				}
				position++
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
						goto l219
					}
					position++
				}
			l221:
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
						{
							position228, tokenIndex228 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l229
							}
							position++
							goto l228
						l229:
							position, tokenIndex = position228, tokenIndex228
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l224
							}
							position++
						}
					l228:
					}
				l225:
					goto l223
				l224:
					position, tokenIndex = position224, tokenIndex224
				}
				{
					position230, tokenIndex230 := position, tokenIndex
					if buffer[position] != rune(':') {
						goto l230
					}
					position++
					goto l219
				l230:
					position, tokenIndex = position230, tokenIndex230
				}
				add(ruleRegister, position220)
			}
			return true
		l219:
			position, tokenIndex = position219, tokenIndex219
			return false
		},
		/* 22 Constant <- <('$' ([a-z] / [A-Z] / ([0-9] / [0-9]) / '-' / '*' / '+')+)> */
		func() bool {
			position231, tokenIndex231 := position, tokenIndex
			{
				position232 := position
				if buffer[position] != rune('$') {
					goto l231
				}
				position++
				{
					position235, tokenIndex235 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l236
					}
					position++
					goto l235
				l236:
					position, tokenIndex = position235, tokenIndex235
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l237
					}
					position++
					goto l235
				l237:
					position, tokenIndex = position235, tokenIndex235
					{
						position239, tokenIndex239 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l240
						}
						position++
						goto l239
					l240:
						position, tokenIndex = position239, tokenIndex239
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l238
						}
						position++
					}
				l239:
					goto l235
				l238:
					position, tokenIndex = position235, tokenIndex235
					if buffer[position] != rune('-') {
						goto l241
					}
					position++
					goto l235
				l241:
					position, tokenIndex = position235, tokenIndex235
					if buffer[position] != rune('*') {
						goto l242
					}
					position++
					goto l235
				l242:
					position, tokenIndex = position235, tokenIndex235
					if buffer[position] != rune('+') {
						goto l231
					}
					position++
				}
			l235:
			l233:
				{
					position234, tokenIndex234 := position, tokenIndex
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
						{
							position247, tokenIndex247 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l248
							}
							position++
							goto l247
						l248:
							position, tokenIndex = position247, tokenIndex247
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l246
							}
							position++
						}
					l247:
						goto l243
					l246:
						position, tokenIndex = position243, tokenIndex243
						if buffer[position] != rune('-') {
							goto l249
						}
						position++
						goto l243
					l249:
						position, tokenIndex = position243, tokenIndex243
						if buffer[position] != rune('*') {
							goto l250
						}
						position++
						goto l243
					l250:
						position, tokenIndex = position243, tokenIndex243
						if buffer[position] != rune('+') {
							goto l234
						}
						position++
					}
				l243:
					goto l233
				l234:
					position, tokenIndex = position234, tokenIndex234
				}
				add(ruleConstant, position232)
			}
			return true
		l231:
			position, tokenIndex = position231, tokenIndex231
			return false
		},
		/* 23 MemoryRef <- <((SymbolRef Offset BaseIndexScale) / (SymbolRef BaseIndexScale) / (Offset BaseIndexScale) / SymbolRef / BaseIndexScale / Absolute)> */
		func() bool {
			position251, tokenIndex251 := position, tokenIndex
			{
				position252 := position
				{
					position253, tokenIndex253 := position, tokenIndex
					if !_rules[ruleSymbolRef]() {
						goto l254
					}
					if !_rules[ruleOffset]() {
						goto l254
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l254
					}
					goto l253
				l254:
					position, tokenIndex = position253, tokenIndex253
					if !_rules[ruleSymbolRef]() {
						goto l255
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l255
					}
					goto l253
				l255:
					position, tokenIndex = position253, tokenIndex253
					if !_rules[ruleOffset]() {
						goto l256
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l256
					}
					goto l253
				l256:
					position, tokenIndex = position253, tokenIndex253
					if !_rules[ruleSymbolRef]() {
						goto l257
					}
					goto l253
				l257:
					position, tokenIndex = position253, tokenIndex253
					if !_rules[ruleBaseIndexScale]() {
						goto l258
					}
					goto l253
				l258:
					position, tokenIndex = position253, tokenIndex253
					if !_rules[ruleAbsolute]() {
						goto l251
					}
				}
			l253:
				add(ruleMemoryRef, position252)
			}
			return true
		l251:
			position, tokenIndex = position251, tokenIndex251
			return false
		},
		/* 24 SymbolRef <- <((LocalSymbol / SymbolName) ('@' Section)?)> */
		func() bool {
			position259, tokenIndex259 := position, tokenIndex
			{
				position260 := position
				{
					position261, tokenIndex261 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l262
					}
					goto l261
				l262:
					position, tokenIndex = position261, tokenIndex261
					if !_rules[ruleSymbolName]() {
						goto l259
					}
				}
			l261:
				{
					position263, tokenIndex263 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l263
					}
					position++
					if !_rules[ruleSection]() {
						goto l263
					}
					goto l264
				l263:
					position, tokenIndex = position263, tokenIndex263
				}
			l264:
				add(ruleSymbolRef, position260)
			}
			return true
		l259:
			position, tokenIndex = position259, tokenIndex259
			return false
		},
		/* 25 BaseIndexScale <- <('(' Register? WS? (',' WS? Register WS? (',' [0-9]+)?)? ')')> */
		func() bool {
			position265, tokenIndex265 := position, tokenIndex
			{
				position266 := position
				if buffer[position] != rune('(') {
					goto l265
				}
				position++
				{
					position267, tokenIndex267 := position, tokenIndex
					if !_rules[ruleRegister]() {
						goto l267
					}
					goto l268
				l267:
					position, tokenIndex = position267, tokenIndex267
				}
			l268:
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
					if buffer[position] != rune(',') {
						goto l271
					}
					position++
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
					if !_rules[ruleRegister]() {
						goto l271
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
						if buffer[position] != rune(',') {
							goto l277
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l277
						}
						position++
					l279:
						{
							position280, tokenIndex280 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l280
							}
							position++
							goto l279
						l280:
							position, tokenIndex = position280, tokenIndex280
						}
						goto l278
					l277:
						position, tokenIndex = position277, tokenIndex277
					}
				l278:
					goto l272
				l271:
					position, tokenIndex = position271, tokenIndex271
				}
			l272:
				if buffer[position] != rune(')') {
					goto l265
				}
				position++
				add(ruleBaseIndexScale, position266)
			}
			return true
		l265:
			position, tokenIndex = position265, tokenIndex265
			return false
		},
		/* 26 Offset <- <(('+' / '-')? [0-9] ([0-9] / '*' / '+' / '-')*)> */
		func() bool {
			position281, tokenIndex281 := position, tokenIndex
			{
				position282 := position
				{
					position283, tokenIndex283 := position, tokenIndex
					{
						position285, tokenIndex285 := position, tokenIndex
						if buffer[position] != rune('+') {
							goto l286
						}
						position++
						goto l285
					l286:
						position, tokenIndex = position285, tokenIndex285
						if buffer[position] != rune('-') {
							goto l283
						}
						position++
					}
				l285:
					goto l284
				l283:
					position, tokenIndex = position283, tokenIndex283
				}
			l284:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l281
				}
				position++
			l287:
				{
					position288, tokenIndex288 := position, tokenIndex
					{
						position289, tokenIndex289 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l290
						}
						position++
						goto l289
					l290:
						position, tokenIndex = position289, tokenIndex289
						if buffer[position] != rune('*') {
							goto l291
						}
						position++
						goto l289
					l291:
						position, tokenIndex = position289, tokenIndex289
						if buffer[position] != rune('+') {
							goto l292
						}
						position++
						goto l289
					l292:
						position, tokenIndex = position289, tokenIndex289
						if buffer[position] != rune('-') {
							goto l288
						}
						position++
					}
				l289:
					goto l287
				l288:
					position, tokenIndex = position288, tokenIndex288
				}
				add(ruleOffset, position282)
			}
			return true
		l281:
			position, tokenIndex = position281, tokenIndex281
			return false
		},
		/* 27 Absolute <- <(('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))* ':')? [0-9]+)> */
		func() bool {
			position293, tokenIndex293 := position, tokenIndex
			{
				position294 := position
				{
					position295, tokenIndex295 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l295
					}
					position++
					{
						position297, tokenIndex297 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l298
						}
						position++
						goto l297
					l298:
						position, tokenIndex = position297, tokenIndex297
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l295
						}
						position++
					}
				l297:
				l299:
					{
						position300, tokenIndex300 := position, tokenIndex
						{
							position301, tokenIndex301 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l302
							}
							position++
							goto l301
						l302:
							position, tokenIndex = position301, tokenIndex301
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l303
							}
							position++
							goto l301
						l303:
							position, tokenIndex = position301, tokenIndex301
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
									goto l300
								}
								position++
							}
						l304:
						}
					l301:
						goto l299
					l300:
						position, tokenIndex = position300, tokenIndex300
					}
					if buffer[position] != rune(':') {
						goto l295
					}
					position++
					goto l296
				l295:
					position, tokenIndex = position295, tokenIndex295
				}
			l296:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l293
				}
				position++
			l306:
				{
					position307, tokenIndex307 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l307
					}
					position++
					goto l306
				l307:
					position, tokenIndex = position307, tokenIndex307
				}
				add(ruleAbsolute, position294)
			}
			return true
		l293:
			position, tokenIndex = position293, tokenIndex293
			return false
		},
		/* 28 Section <- <[A-Z]+> */
		func() bool {
			position308, tokenIndex308 := position, tokenIndex
			{
				position309 := position
				if c := buffer[position]; c < rune('A') || c > rune('Z') {
					goto l308
				}
				position++
			l310:
				{
					position311, tokenIndex311 := position, tokenIndex
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l311
					}
					position++
					goto l310
				l311:
					position, tokenIndex = position311, tokenIndex311
				}
				add(ruleSection, position309)
			}
			return true
		l308:
			position, tokenIndex = position308, tokenIndex308
			return false
		},
	}
	p.rules = _rules
}
