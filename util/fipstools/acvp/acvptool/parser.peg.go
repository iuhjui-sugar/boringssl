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
	ruleStatement
	ruleAssignment
	ruleVariable
	ruleExpression
	ruleStringLiteral
	ruleQuotedText
	ruleEscapedChar
	ruleIndexing
	ruleIndex
	ruleSearch
	ruleAction
	ruleCommand
	ruleFunction
	ruleArgs
	ruleQuery
	ruleConjunctions
	ruleConjunction
	ruleField
	ruleRelation
	ruleWS
)

var rul3s = [...]string{
	"Unknown",
	"Statement",
	"Assignment",
	"Variable",
	"Expression",
	"StringLiteral",
	"QuotedText",
	"EscapedChar",
	"Indexing",
	"Index",
	"Search",
	"Action",
	"Command",
	"Function",
	"Args",
	"Query",
	"Conjunctions",
	"Conjunction",
	"Field",
	"Relation",
	"WS",
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

type Statement struct {
	Buffer string
	buffer []rune
	rules  [21]func() bool
	parse  func(rule ...int) error
	reset  func()
	Pretty bool
	tokens32
}

func (p *Statement) Parse(rule ...int) error {
	return p.parse(rule...)
}

func (p *Statement) Reset() {
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
	p   *Statement
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

func (p *Statement) PrintSyntaxTree() {
	if p.Pretty {
		p.tokens32.PrettyPrintSyntaxTree(p.Buffer)
	} else {
		p.tokens32.PrintSyntaxTree(p.Buffer)
	}
}

func (p *Statement) Init() {
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
		/* 0 Statement <- <(WS? (Assignment / Action / Expression) WS? !.)> */
		func() bool {
			position0, tokenIndex0 := position, tokenIndex
			{
				position1 := position
				{
					position2, tokenIndex2 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l2
					}
					goto l3
				l2:
					position, tokenIndex = position2, tokenIndex2
				}
			l3:
				{
					position4, tokenIndex4 := position, tokenIndex
					if !_rules[ruleAssignment]() {
						goto l5
					}
					goto l4
				l5:
					position, tokenIndex = position4, tokenIndex4
					if !_rules[ruleAction]() {
						goto l6
					}
					goto l4
				l6:
					position, tokenIndex = position4, tokenIndex4
					if !_rules[ruleExpression]() {
						goto l0
					}
				}
			l4:
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
					if !matchDot() {
						goto l9
					}
					goto l0
				l9:
					position, tokenIndex = position9, tokenIndex9
				}
				add(ruleStatement, position1)
			}
			return true
		l0:
			position, tokenIndex = position0, tokenIndex0
			return false
		},
		/* 1 Assignment <- <(Variable WS? '=' WS? Expression)> */
		func() bool {
			position10, tokenIndex10 := position, tokenIndex
			{
				position11 := position
				if !_rules[ruleVariable]() {
					goto l10
				}
				{
					position12, tokenIndex12 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l12
					}
					goto l13
				l12:
					position, tokenIndex = position12, tokenIndex12
				}
			l13:
				if buffer[position] != rune('=') {
					goto l10
				}
				position++
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
				if !_rules[ruleExpression]() {
					goto l10
				}
				add(ruleAssignment, position11)
			}
			return true
		l10:
			position, tokenIndex = position10, tokenIndex10
			return false
		},
		/* 2 Variable <- <(([a-z] / [A-Z] / '_') ([a-z] / [A-Z] / [0-9] / '_')*)> */
		func() bool {
			position16, tokenIndex16 := position, tokenIndex
			{
				position17 := position
				{
					position18, tokenIndex18 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l19
					}
					position++
					goto l18
				l19:
					position, tokenIndex = position18, tokenIndex18
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l20
					}
					position++
					goto l18
				l20:
					position, tokenIndex = position18, tokenIndex18
					if buffer[position] != rune('_') {
						goto l16
					}
					position++
				}
			l18:
			l21:
				{
					position22, tokenIndex22 := position, tokenIndex
					{
						position23, tokenIndex23 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l24
						}
						position++
						goto l23
					l24:
						position, tokenIndex = position23, tokenIndex23
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l25
						}
						position++
						goto l23
					l25:
						position, tokenIndex = position23, tokenIndex23
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l26
						}
						position++
						goto l23
					l26:
						position, tokenIndex = position23, tokenIndex23
						if buffer[position] != rune('_') {
							goto l22
						}
						position++
					}
				l23:
					goto l21
				l22:
					position, tokenIndex = position22, tokenIndex22
				}
				add(ruleVariable, position17)
			}
			return true
		l16:
			position, tokenIndex = position16, tokenIndex16
			return false
		},
		/* 3 Expression <- <(StringLiteral / Indexing / Search / Variable)> */
		func() bool {
			position27, tokenIndex27 := position, tokenIndex
			{
				position28 := position
				{
					position29, tokenIndex29 := position, tokenIndex
					if !_rules[ruleStringLiteral]() {
						goto l30
					}
					goto l29
				l30:
					position, tokenIndex = position29, tokenIndex29
					if !_rules[ruleIndexing]() {
						goto l31
					}
					goto l29
				l31:
					position, tokenIndex = position29, tokenIndex29
					if !_rules[ruleSearch]() {
						goto l32
					}
					goto l29
				l32:
					position, tokenIndex = position29, tokenIndex29
					if !_rules[ruleVariable]() {
						goto l27
					}
				}
			l29:
				add(ruleExpression, position28)
			}
			return true
		l27:
			position, tokenIndex = position27, tokenIndex27
			return false
		},
		/* 4 StringLiteral <- <('"' QuotedText '"')> */
		func() bool {
			position33, tokenIndex33 := position, tokenIndex
			{
				position34 := position
				if buffer[position] != rune('"') {
					goto l33
				}
				position++
				if !_rules[ruleQuotedText]() {
					goto l33
				}
				if buffer[position] != rune('"') {
					goto l33
				}
				position++
				add(ruleStringLiteral, position34)
			}
			return true
		l33:
			position, tokenIndex = position33, tokenIndex33
			return false
		},
		/* 5 QuotedText <- <(EscapedChar / (!'"' .))*> */
		func() bool {
			{
				position36 := position
			l37:
				{
					position38, tokenIndex38 := position, tokenIndex
					{
						position39, tokenIndex39 := position, tokenIndex
						if !_rules[ruleEscapedChar]() {
							goto l40
						}
						goto l39
					l40:
						position, tokenIndex = position39, tokenIndex39
						{
							position41, tokenIndex41 := position, tokenIndex
							if buffer[position] != rune('"') {
								goto l41
							}
							position++
							goto l38
						l41:
							position, tokenIndex = position41, tokenIndex41
						}
						if !matchDot() {
							goto l38
						}
					}
				l39:
					goto l37
				l38:
					position, tokenIndex = position38, tokenIndex38
				}
				add(ruleQuotedText, position36)
			}
			return true
		},
		/* 6 EscapedChar <- <('\\' ('\\' / 'n' / '"'))> */
		func() bool {
			position42, tokenIndex42 := position, tokenIndex
			{
				position43 := position
				if buffer[position] != rune('\\') {
					goto l42
				}
				position++
				{
					position44, tokenIndex44 := position, tokenIndex
					if buffer[position] != rune('\\') {
						goto l45
					}
					position++
					goto l44
				l45:
					position, tokenIndex = position44, tokenIndex44
					if buffer[position] != rune('n') {
						goto l46
					}
					position++
					goto l44
				l46:
					position, tokenIndex = position44, tokenIndex44
					if buffer[position] != rune('"') {
						goto l42
					}
					position++
				}
			l44:
				add(ruleEscapedChar, position43)
			}
			return true
		l42:
			position, tokenIndex = position42, tokenIndex42
			return false
		},
		/* 7 Indexing <- <(Variable ('[' Index ']')+)> */
		func() bool {
			position47, tokenIndex47 := position, tokenIndex
			{
				position48 := position
				if !_rules[ruleVariable]() {
					goto l47
				}
				if buffer[position] != rune('[') {
					goto l47
				}
				position++
				if !_rules[ruleIndex]() {
					goto l47
				}
				if buffer[position] != rune(']') {
					goto l47
				}
				position++
			l49:
				{
					position50, tokenIndex50 := position, tokenIndex
					if buffer[position] != rune('[') {
						goto l50
					}
					position++
					if !_rules[ruleIndex]() {
						goto l50
					}
					if buffer[position] != rune(']') {
						goto l50
					}
					position++
					goto l49
				l50:
					position, tokenIndex = position50, tokenIndex50
				}
				add(ruleIndexing, position48)
			}
			return true
		l47:
			position, tokenIndex = position47, tokenIndex47
			return false
		},
		/* 8 Index <- <([0-9] / [a-z])+> */
		func() bool {
			position51, tokenIndex51 := position, tokenIndex
			{
				position52 := position
				{
					position55, tokenIndex55 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l56
					}
					position++
					goto l55
				l56:
					position, tokenIndex = position55, tokenIndex55
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l51
					}
					position++
				}
			l55:
			l53:
				{
					position54, tokenIndex54 := position, tokenIndex
					{
						position57, tokenIndex57 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l58
						}
						position++
						goto l57
					l58:
						position, tokenIndex = position57, tokenIndex57
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l54
						}
						position++
					}
				l57:
					goto l53
				l54:
					position, tokenIndex = position54, tokenIndex54
				}
				add(ruleIndex, position52)
			}
			return true
		l51:
			position, tokenIndex = position51, tokenIndex51
			return false
		},
		/* 9 Search <- <(Variable '[' WS? ('w' 'h' 'e' 'r' 'e') WS Query ']')> */
		func() bool {
			position59, tokenIndex59 := position, tokenIndex
			{
				position60 := position
				if !_rules[ruleVariable]() {
					goto l59
				}
				if buffer[position] != rune('[') {
					goto l59
				}
				position++
				{
					position61, tokenIndex61 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l61
					}
					goto l62
				l61:
					position, tokenIndex = position61, tokenIndex61
				}
			l62:
				if buffer[position] != rune('w') {
					goto l59
				}
				position++
				if buffer[position] != rune('h') {
					goto l59
				}
				position++
				if buffer[position] != rune('e') {
					goto l59
				}
				position++
				if buffer[position] != rune('r') {
					goto l59
				}
				position++
				if buffer[position] != rune('e') {
					goto l59
				}
				position++
				if !_rules[ruleWS]() {
					goto l59
				}
				if !_rules[ruleQuery]() {
					goto l59
				}
				if buffer[position] != rune(']') {
					goto l59
				}
				position++
				add(ruleSearch, position60)
			}
			return true
		l59:
			position, tokenIndex = position59, tokenIndex59
			return false
		},
		/* 10 Action <- <(Expression '.' Command)> */
		func() bool {
			position63, tokenIndex63 := position, tokenIndex
			{
				position64 := position
				if !_rules[ruleExpression]() {
					goto l63
				}
				if buffer[position] != rune('.') {
					goto l63
				}
				position++
				if !_rules[ruleCommand]() {
					goto l63
				}
				add(ruleAction, position64)
			}
			return true
		l63:
			position, tokenIndex = position63, tokenIndex63
			return false
		},
		/* 11 Command <- <(Function '(' Args? ')')> */
		func() bool {
			position65, tokenIndex65 := position, tokenIndex
			{
				position66 := position
				if !_rules[ruleFunction]() {
					goto l65
				}
				if buffer[position] != rune('(') {
					goto l65
				}
				position++
				{
					position67, tokenIndex67 := position, tokenIndex
					if !_rules[ruleArgs]() {
						goto l67
					}
					goto l68
				l67:
					position, tokenIndex = position67, tokenIndex67
				}
			l68:
				if buffer[position] != rune(')') {
					goto l65
				}
				position++
				add(ruleCommand, position66)
			}
			return true
		l65:
			position, tokenIndex = position65, tokenIndex65
			return false
		},
		/* 12 Function <- <([a-z] / [A-Z])+> */
		func() bool {
			position69, tokenIndex69 := position, tokenIndex
			{
				position70 := position
				{
					position73, tokenIndex73 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l74
					}
					position++
					goto l73
				l74:
					position, tokenIndex = position73, tokenIndex73
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l69
					}
					position++
				}
			l73:
			l71:
				{
					position72, tokenIndex72 := position, tokenIndex
					{
						position75, tokenIndex75 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l76
						}
						position++
						goto l75
					l76:
						position, tokenIndex = position75, tokenIndex75
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l72
						}
						position++
					}
				l75:
					goto l71
				l72:
					position, tokenIndex = position72, tokenIndex72
				}
				add(ruleFunction, position70)
			}
			return true
		l69:
			position, tokenIndex = position69, tokenIndex69
			return false
		},
		/* 13 Args <- <(StringLiteral (WS? ',' WS? Args))> */
		func() bool {
			position77, tokenIndex77 := position, tokenIndex
			{
				position78 := position
				if !_rules[ruleStringLiteral]() {
					goto l77
				}
				{
					position79, tokenIndex79 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l79
					}
					goto l80
				l79:
					position, tokenIndex = position79, tokenIndex79
				}
			l80:
				if buffer[position] != rune(',') {
					goto l77
				}
				position++
				{
					position81, tokenIndex81 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l81
					}
					goto l82
				l81:
					position, tokenIndex = position81, tokenIndex81
				}
			l82:
				if !_rules[ruleArgs]() {
					goto l77
				}
				add(ruleArgs, position78)
			}
			return true
		l77:
			position, tokenIndex = position77, tokenIndex77
			return false
		},
		/* 14 Query <- <(Conjunctions (WS? ('|' '|') WS? Conjunctions)?)> */
		func() bool {
			position83, tokenIndex83 := position, tokenIndex
			{
				position84 := position
				if !_rules[ruleConjunctions]() {
					goto l83
				}
				{
					position85, tokenIndex85 := position, tokenIndex
					{
						position87, tokenIndex87 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l87
						}
						goto l88
					l87:
						position, tokenIndex = position87, tokenIndex87
					}
				l88:
					if buffer[position] != rune('|') {
						goto l85
					}
					position++
					if buffer[position] != rune('|') {
						goto l85
					}
					position++
					{
						position89, tokenIndex89 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l89
						}
						goto l90
					l89:
						position, tokenIndex = position89, tokenIndex89
					}
				l90:
					if !_rules[ruleConjunctions]() {
						goto l85
					}
					goto l86
				l85:
					position, tokenIndex = position85, tokenIndex85
				}
			l86:
				add(ruleQuery, position84)
			}
			return true
		l83:
			position, tokenIndex = position83, tokenIndex83
			return false
		},
		/* 15 Conjunctions <- <(Conjunction (WS? ('&' '&') WS? Conjunctions)?)> */
		func() bool {
			position91, tokenIndex91 := position, tokenIndex
			{
				position92 := position
				if !_rules[ruleConjunction]() {
					goto l91
				}
				{
					position93, tokenIndex93 := position, tokenIndex
					{
						position95, tokenIndex95 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l95
						}
						goto l96
					l95:
						position, tokenIndex = position95, tokenIndex95
					}
				l96:
					if buffer[position] != rune('&') {
						goto l93
					}
					position++
					if buffer[position] != rune('&') {
						goto l93
					}
					position++
					{
						position97, tokenIndex97 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l97
						}
						goto l98
					l97:
						position, tokenIndex = position97, tokenIndex97
					}
				l98:
					if !_rules[ruleConjunctions]() {
						goto l93
					}
					goto l94
				l93:
					position, tokenIndex = position93, tokenIndex93
				}
			l94:
				add(ruleConjunctions, position92)
			}
			return true
		l91:
			position, tokenIndex = position91, tokenIndex91
			return false
		},
		/* 16 Conjunction <- <(Field WS? Relation WS? StringLiteral)> */
		func() bool {
			position99, tokenIndex99 := position, tokenIndex
			{
				position100 := position
				if !_rules[ruleField]() {
					goto l99
				}
				{
					position101, tokenIndex101 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l101
					}
					goto l102
				l101:
					position, tokenIndex = position101, tokenIndex101
				}
			l102:
				if !_rules[ruleRelation]() {
					goto l99
				}
				{
					position103, tokenIndex103 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l103
					}
					goto l104
				l103:
					position, tokenIndex = position103, tokenIndex103
				}
			l104:
				if !_rules[ruleStringLiteral]() {
					goto l99
				}
				add(ruleConjunction, position100)
			}
			return true
		l99:
			position, tokenIndex = position99, tokenIndex99
			return false
		},
		/* 17 Field <- <([a-z] ([a-z] / [A-Z] / [0-9])*)> */
		func() bool {
			position105, tokenIndex105 := position, tokenIndex
			{
				position106 := position
				if c := buffer[position]; c < rune('a') || c > rune('z') {
					goto l105
				}
				position++
			l107:
				{
					position108, tokenIndex108 := position, tokenIndex
					{
						position109, tokenIndex109 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l110
						}
						position++
						goto l109
					l110:
						position, tokenIndex = position109, tokenIndex109
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l111
						}
						position++
						goto l109
					l111:
						position, tokenIndex = position109, tokenIndex109
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l108
						}
						position++
					}
				l109:
					goto l107
				l108:
					position, tokenIndex = position108, tokenIndex108
				}
				add(ruleField, position106)
			}
			return true
		l105:
			position, tokenIndex = position105, tokenIndex105
			return false
		},
		/* 18 Relation <- <(('=' '=') / ('!' '=') / ('c' 'o' 'n' 't' 'a' 'i' 'n' 's') / ('s' 't' 'a' 'r' 't' 's' 'W' 'i' 't' 'h') / ('e' 'n' 'd' 's' 'W' 'i' 't' 'h'))> */
		func() bool {
			position112, tokenIndex112 := position, tokenIndex
			{
				position113 := position
				{
					position114, tokenIndex114 := position, tokenIndex
					if buffer[position] != rune('=') {
						goto l115
					}
					position++
					if buffer[position] != rune('=') {
						goto l115
					}
					position++
					goto l114
				l115:
					position, tokenIndex = position114, tokenIndex114
					if buffer[position] != rune('!') {
						goto l116
					}
					position++
					if buffer[position] != rune('=') {
						goto l116
					}
					position++
					goto l114
				l116:
					position, tokenIndex = position114, tokenIndex114
					if buffer[position] != rune('c') {
						goto l117
					}
					position++
					if buffer[position] != rune('o') {
						goto l117
					}
					position++
					if buffer[position] != rune('n') {
						goto l117
					}
					position++
					if buffer[position] != rune('t') {
						goto l117
					}
					position++
					if buffer[position] != rune('a') {
						goto l117
					}
					position++
					if buffer[position] != rune('i') {
						goto l117
					}
					position++
					if buffer[position] != rune('n') {
						goto l117
					}
					position++
					if buffer[position] != rune('s') {
						goto l117
					}
					position++
					goto l114
				l117:
					position, tokenIndex = position114, tokenIndex114
					if buffer[position] != rune('s') {
						goto l118
					}
					position++
					if buffer[position] != rune('t') {
						goto l118
					}
					position++
					if buffer[position] != rune('a') {
						goto l118
					}
					position++
					if buffer[position] != rune('r') {
						goto l118
					}
					position++
					if buffer[position] != rune('t') {
						goto l118
					}
					position++
					if buffer[position] != rune('s') {
						goto l118
					}
					position++
					if buffer[position] != rune('W') {
						goto l118
					}
					position++
					if buffer[position] != rune('i') {
						goto l118
					}
					position++
					if buffer[position] != rune('t') {
						goto l118
					}
					position++
					if buffer[position] != rune('h') {
						goto l118
					}
					position++
					goto l114
				l118:
					position, tokenIndex = position114, tokenIndex114
					if buffer[position] != rune('e') {
						goto l112
					}
					position++
					if buffer[position] != rune('n') {
						goto l112
					}
					position++
					if buffer[position] != rune('d') {
						goto l112
					}
					position++
					if buffer[position] != rune('s') {
						goto l112
					}
					position++
					if buffer[position] != rune('W') {
						goto l112
					}
					position++
					if buffer[position] != rune('i') {
						goto l112
					}
					position++
					if buffer[position] != rune('t') {
						goto l112
					}
					position++
					if buffer[position] != rune('h') {
						goto l112
					}
					position++
				}
			l114:
				add(ruleRelation, position113)
			}
			return true
		l112:
			position, tokenIndex = position112, tokenIndex112
			return false
		},
		/* 19 WS <- <(' ' / '\t')+> */
		func() bool {
			position119, tokenIndex119 := position, tokenIndex
			{
				position120 := position
				{
					position123, tokenIndex123 := position, tokenIndex
					if buffer[position] != rune(' ') {
						goto l124
					}
					position++
					goto l123
				l124:
					position, tokenIndex = position123, tokenIndex123
					if buffer[position] != rune('\t') {
						goto l119
					}
					position++
				}
			l123:
			l121:
				{
					position122, tokenIndex122 := position, tokenIndex
					{
						position125, tokenIndex125 := position, tokenIndex
						if buffer[position] != rune(' ') {
							goto l126
						}
						position++
						goto l125
					l126:
						position, tokenIndex = position125, tokenIndex125
						if buffer[position] != rune('\t') {
							goto l122
						}
						position++
					}
				l125:
					goto l121
				l122:
					position, tokenIndex = position122, tokenIndex122
				}
				add(ruleWS, position120)
			}
			return true
		l119:
			position, tokenIndex = position119, tokenIndex119
			return false
		},
	}
	p.rules = _rules
}
