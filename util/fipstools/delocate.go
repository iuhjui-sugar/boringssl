// Copyright (c) 2017, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

//go:generate peg delocate.peg

// delocate performs several transformations of textual assembly code. See
// FIPS.md in this directory for an overview.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
)

// inputFile represents a textual assembly file.
type inputFile struct {
	path string
	// index is a unique identifer given to this file. It's used for mapping local symbols.
	index int
	// isArchive indicates the the input should be processed as an ar file.
	isArchive bool
	// contents contains the contents of the file.
	contents string
	// ast points to the head of the syntax tree.
	ast *node32
}

type stringWriter interface {
	WriteString(string) (int, error)
}

type processorType int

const (
	POWER processorType = iota
	X86_64
)

// delocation holds the state needed during a delocation operation.
type delocation struct {
	target    targetPlatform
	processor processorType

	output stringWriter
	// symbols maps from defined symbols to whether that symbol is global
	// or not.
	symbols map[string]bool
	// redirectors maps from out-call symbol name to the name of a
	// redirector function for that symbol.
	redirectors map[string]string
	// bssAccessorsNeeded maps from a BSS symbol name to the symbol that
	// should be used to reference it.
	bssAccessorsNeeded map[string]string
	// tocLoaders is a set of symbol names for which TOC helper functions
	// are required. (ppc64le only.)
	tocLoaders map[string]struct{}

	currentInput inputFile
}

// writeNode writes out an AST node.
func (d *delocation) writeNode(node *node32) {
	if _, err := d.output.WriteString(d.currentInput.contents[node.begin:node.end]); err != nil {
		panic(err)
	}
}

func (d *delocation) writeCommentedNode(node *node32) {
	line := d.currentInput.contents[node.begin:node.end]
	if _, err := d.output.WriteString("# WAS " + strings.TrimSpace(line) + "\n"); err != nil {
		panic(err)
	}
}

func (d *delocation) processInput(input inputFile) (err error) {
	statement := input.ast.up
	var origStatement *node32
	d.currentInput = input

	/*defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(os.Stdout, "Panic while processing:\n  %s%s\n", input.contents[origStatement.begin:origStatement.end], err)
			os.Exit(1)
		}
	}()*/

	for ; statement != nil; statement = statement.next {
		origStatement = statement

		node := skipNodes(statement.up, ruleWS)
		if node == nil {
			d.writeNode(statement)
			continue
		}

		switch node.pegRule {
		case ruleGlobalDirective, ruleComment, ruleLocationDirective:
			d.writeNode(statement)
		case ruleDirective:
			statement, err = d.processDirective(statement, node.up)
		case ruleLabelContainingDirective:
			statement, err = d.processLabelContainingDirective(statement, node.up)
		case ruleLabel:
			statement, err = d.processLabel(statement, node.up)
		case ruleInstruction:
			switch d.processor {
			case X86_64:
				statement, err = d.processIntelInstruction(statement, node.up)
			case POWER:
				statement, err = d.processPPCInstruction(statement, node.up)
			default:
				panic("unknown processor")
			}
		default:
			panic(fmt.Sprintf("unknown top-level statement type %q", rul3s[node.pegRule]))
		}

		if err != nil {
			posMap := translatePositions([]rune(input.contents), []int{int(origStatement.begin)})
			var line int
			for _, pos := range posMap {
				line = pos.line
			}

			return fmt.Errorf("error while processing %q on line %d: %q", input.contents[origStatement.begin:origStatement.end], line, err)
		}
	}

	return nil
}

func (d *delocation) processDirective(statement, directive *node32) (*node32, error) {
	assertNodeType(directive, ruleDirectiveName)
	directiveName := d.currentInput.contents[directive.begin:directive.end]

	var args []string
	forEachPath(directive, func(arg *node32) {
		if arg.up != nil {
			arg = arg.up
			assertNodeType(arg, ruleQuotedArg)
			if arg.up == nil {
				args = append(args, "")
				return
			}
			arg = arg.up
			assertNodeType(arg, ruleQuotedText)
		}
		args = append(args, d.currentInput.contents[arg.begin:arg.end])
	}, ruleArgs, ruleArg)

	switch directiveName {
	case "comm", "lcomm":
		if len(args) < 1 {
			return nil, errors.New("comm directive has no arguments")
		}
		d.bssAccessorsNeeded[args[0]] = args[0]
		d.writeNode(statement)

	case "section":
		section := args[0]

		if section == ".data.rel.ro" {
			// In a normal build, this is an indication of a
			// problem but any references from the module to this
			// section will result in a relocation and thus will
			// break the integrity check. However, ASAN can
			// generate these sections and so we cannot forbid
			// them.
			d.output.WriteString(".text\n")
			break
		}

		sectionType, ok := sectionType(section)
		if !ok {
			// Unknown sections are permitted in order to be robust
			// to different compiler modes.
		}

		switch sectionType {
		case ".rodata", ".text":
			// Move .rodata to .text so it may be accessed without
			// a relocation. GCC with -fmerge-constants will place
			// strings into separate sections, so we move all
			// sections named like .rodata. Also move .text.startup
			// so the self-test function is also in the module.
			d.writeCommentedNode(statement)
			d.output.WriteString(".text\n")

		case ".data":
			return nil, errors.New(".data section found in module")

		case ".init_array", ".fini_array", ".ctors", ".dtors":
			// init_array/ctors/dtors contains function
			// pointers to constructor/destructor
			// functions. These contain relocations, but
			// they're in a different section anyway.
			d.writeNode(statement)
			break

		case ".debug", ".note", ".toc":
			d.writeNode(statement)
			break

		case ".bss":
			d.writeNode(statement)
			return d.handleBSS(statement)
		}

	default:
		d.writeNode(statement)
	}

	return statement, nil
}

func (d *delocation) processLabelContainingDirective(statement, directive *node32) (*node32, error) {
	changed := false
	assertNodeType(directive, ruleLabelContainingDirectiveName)
	name := d.currentInput.contents[directive.begin:directive.end]

	node := directive.next
	assertNodeType(node, ruleWS)

	node = node.next
	assertNodeType(node, ruleSymbolArgs)

	var args []string
	for node = node.up; node != nil; node = node.next {
		if node.pegRule != ruleSymbolArg {
			continue
		}

		arg := node.up
		var mapped string

		for term := arg; term != nil; term = term.next {
			if term.pegRule == ruleLocalSymbol {
				changed = true
				mapped += d.mapLocalSymbol(d.currentInput.contents[term.begin:term.end])
			} else {
				mapped += d.currentInput.contents[term.begin:term.end]
			}
		}

		args = append(args, mapped)
	}

	if !changed {
		d.writeNode(statement)
	} else {
		d.writeCommentedNode(statement)
		d.output.WriteString("\t" + name + "\t" + strings.Join(args, ", ") + "\n")
	}

	return statement, nil
}

func (d *delocation) processLabel(statement, label *node32) (*node32, error) {
	symbol := d.currentInput.contents[label.begin:label.end]

	switch label.pegRule {
	case ruleLocalLabel:
		d.output.WriteString(symbol + ":\n")
	case ruleLocalSymbol:
		d.output.WriteString(d.mapLocalSymbol(symbol) + ":\n")
	case ruleSymbolName:
		d.output.WriteString(localTargetName(symbol) + ":\n")
		d.writeNode(statement)
	default:
		return nil, fmt.Errorf("unknown label type %q", rul3s[label.pegRule])
	}

	return statement, nil
}

func instructionArgs(node *node32) (argNodes []*node32) {
	for ; node != nil; node = node.next {
		if node.pegRule != ruleInstructionArg {
			continue
		}

		argNodes = append(argNodes, node.up)
	}

	return argNodes
}

func (d *delocation) isPPC64LEAPair(statement *node32) (target, source, relative string, ok bool) {
	instruction := skipNodes(statement.up, ruleWS).up
	assertNodeType(instruction, ruleInstructionName)
	name1 := d.currentInput.contents[instruction.begin:instruction.end]
	args1 := instructionArgs(instruction.next)

	statement = statement.next
	instruction = skipNodes(statement.up, ruleWS).up
	assertNodeType(instruction, ruleInstructionName)
	name2 := d.currentInput.contents[instruction.begin:instruction.end]
	args2 := instructionArgs(instruction.next)

	if name1 != "addis" ||
		len(args1) != 3 ||
		name2 != "addi" ||
		len(args2) != 3 {
		return "", "", "", false
	}

	target = d.currentInput.contents[args1[0].begin:args1[0].end]
	relative = d.currentInput.contents[args1[1].begin:args1[1].end]
	source1 := d.currentInput.contents[args1[2].begin:args1[2].end]
	source2 := d.currentInput.contents[args2[2].begin:args2[2].end]

	if !strings.HasSuffix(source1, "@ha") ||
		!strings.HasSuffix(source2, "@l") ||
		source1[:len(source1)-3] != source2[:len(source2)-2] ||
		d.currentInput.contents[args2[0].begin:args2[0].end] != target ||
		d.currentInput.contents[args2[1].begin:args2[1].end] != target {
		return "", "", "", false
	}

	source = source1[:len(source1)-3]
	ok = true
	return
}

func loadTOCFuncName(symbol, section, offset string) string {
	ret := "bcm_loadtoc_" + symbol + "_at_" + strings.Replace(section, "@", "_at_", -1)
	if len(offset) > 0 {
		ret += "_offset_"
		ret += strings.Replace(strings.Replace(offset, "+", "", 1), "-", "neg_", 1)
	}
	return strings.Replace(ret, ".", "_dot_", -1)
}

func (d *delocation) getTOC(w stringWriter, symbol, section, offset, instruction string, avoidRegisters []int) (dest string, wrapper wrapperFunc) {
	destRegisterNo := 3

FindDest:
	for ; ; destRegisterNo++ {
		for _, avoid := range avoidRegisters {
			if avoid == destRegisterNo {
				continue FindDest
			}
		}

		break
	}

	dest = strconv.Itoa(destRegisterNo)
	d.tocLoaders[symbol+"@"+section+"\x00"+offset] = struct{}{}

	return dest, func(k func()) {
		w.WriteString("\taddi 1, 1, -288\n")
		w.WriteString("\tstd " + dest + ", 0(1)\n")
		w.WriteString("\tmflr " + dest + "\n")
		w.WriteString("\tstd " + dest + ", 8(1)\n")
		if dest != "3" {
			w.WriteString("\tstd 3, 16(1)\n")
		}
		w.WriteString("\tbl " + loadTOCFuncName(symbol, section, offset) + "\n")
		// The POWER ABI requires a nop instruction after a function call so
		// that the linker has space to insert an unspecified instruction to
		// restore register two.
		w.WriteString("\tnop\n")

		if dest != "3" {
			w.WriteString("\tmr " + dest + ", 3\n")
			w.WriteString("\tld 3, 16(1)\n")
		}

		k()

		w.WriteString("\tld " + dest + ", 8(1)\n")
		w.WriteString("\tmtlr " + dest + "\n")
		w.WriteString("\tld " + dest + ", 0(1)\n")
		w.WriteString("\taddi 1, 1, 288\n")
	}
}

func (d *delocation) processPPCInstruction(statement, instruction *node32) (*node32, error) {
	assertNodeType(instruction, ruleInstructionName)
	instructionName := d.currentInput.contents[instruction.begin:instruction.end]

	argNodes := instructionArgs(instruction.next)

	var wrappers wrapperStack
	var args []string
	changed := false

Args:
	for _, arg := range argNodes {
		fullArg := arg
		isIndirect := false

		if arg.pegRule == ruleIndirectionIndicator {
			arg = arg.next
			isIndirect = true
		}

		switch arg.pegRule {
		case ruleRegisterOrConstant, ruleLocalLabelRef:
			args = append(args, d.currentInput.contents[fullArg.begin:fullArg.end])

		case ruleTOCRefLow:
			return nil, errors.New("Found low TOC reference outside preamble pattern")

		case ruleTOCRefHigh:
			target, _, relative, ok := d.isPPC64LEAPair(statement)
			if !ok {
				return nil, errors.New("Found high TOC reference outside preamble pattern")
			}

			if relative != "12" {
				return nil, fmt.Errorf("preamble is relative to %q, not r12", relative)
			}

			if target != "2" {
				return nil, fmt.Errorf("preamble is setting %q, not r2", target)
			}

			statement = statement.next
			d.target.loadTOC(d.output)
			instructionName = ""
			changed = true
			break Args

		case ruleMemoryRef:
			memRef := arg.up

			var symbol, section, offset string
			var symbolIsLocal bool

			if memRef.pegRule == ruleSymbolRef {
				symRef := memRef.up
				memRef = memRef.next

				symbol = d.currentInput.contents[symRef.begin:symRef.end]
				if symRef.pegRule == ruleLocalSymbol {
					symbolIsLocal = true
					mapped := d.mapLocalSymbol(symbol)
					if mapped != symbol {
						symbol = mapped
						changed = true
					}
				}

				symRef = symRef.next
				if symRef != nil && symRef.pegRule == ruleOffset {
					offset = d.currentInput.contents[symRef.begin:symRef.end]
					symRef = symRef.next
				}

				if symRef != nil {
					assertNodeType(symRef, ruleSection)
					section = d.currentInput.contents[symRef.begin:symRef.end]
				}
			}

			_, knownSymbol := d.symbols[symbol]
			if knownSymbol {
				symbol = localTargetName(symbol)
				changed = true
			} else if len(symbol) > 0 && !symbolIsLocal && !isSynthesized(symbol) {
				changed = true
				d.redirectors[symbol] = redirectorName(symbol)
				symbol = redirectorName(symbol)
			}

			switch section {
			case "":
				break

			case "toc@ha", "toc@l":
				changed = true

				var avoidRegisters []int
				for _, node := range argNodes {
					if node.pegRule != ruleRegisterOrConstant {
						continue
					}
					val, err := strconv.ParseInt(d.currentInput.contents[node.begin:node.end], 10, 32)
					if err != nil {
						continue
					}

					avoidRegisters = append(avoidRegisters, int(val))
				}

				valReg, wrapper := d.getTOC(d.output, symbol, section, offset, instructionName, avoidRegisters)
				wrappers = append(wrappers, wrapper)

				switch instructionName {
				case "addis":
					// addis shifts its argument 16 bits left before addition.
					wrappers = append(wrappers, func(k func()) {
						d.output.WriteString("\t sldi " + valReg + ", " + valReg + ", 16\n")
						k()
					})
					fallthrough
				case "addi":
					instructionName = "add"

				case "ld", "lhz", "lwz":
					// ld 6,foo@toc@l(26) needs to be turned into:
					// add 6, <TOC value>, 26
					// ld 6, 0(6)
					origInstructionName := instructionName
					instructionName = ""

					assertNodeType(memRef, ruleBaseIndexScale)
					assertNodeType(memRef.up, ruleRegisterOrConstant)
					if memRef.next != nil || memRef.up.next != nil {
						return nil, errors.New("expected single register in BaseIndexScale for ld argument.")
					}
					baseReg := d.currentInput.contents[memRef.up.begin:memRef.up.end]

					wrappers = append(wrappers, func(k func()) {
						d.output.WriteString("\tadd " + valReg + ", " + valReg + ", " + baseReg + "\n")
						d.output.WriteString("\t" + origInstructionName + " " + args[0] + ", 0(" + valReg + ")\n")
					})
					break Args
				default:
					return nil, fmt.Errorf("can't process TOC argument to %q", instructionName)
				}

				symbol = valReg

			default:
				return nil, fmt.Errorf("Unknown section type %q", section)
			}

			section = ""

			argStr := ""
			if isIndirect {
				argStr += "*"
			}
			argStr += symbol

			for ; memRef != nil; memRef = memRef.next {
				argStr += d.currentInput.contents[memRef.begin:memRef.end]
			}

			args = append(args, argStr)

		default:
			panic(fmt.Sprintf("unknown instruction argument type %q", rul3s[arg.pegRule]))
		}
	}

	if changed {
		d.writeCommentedNode(statement)

		var replacement string
		if len(instructionName) > 0 {
			replacement = "\t" + instructionName + "\t" + strings.Join(args, ", ") + "\n"
		}

		wrappers.do(func() {
			d.output.WriteString(replacement)
		})
	} else {
		d.writeNode(statement)
	}

	return statement, nil
}

func (d *delocation) processIntelInstruction(statement, instruction *node32) (*node32, error) {
	assertNodeType(instruction, ruleInstructionName)
	instructionName := d.currentInput.contents[instruction.begin:instruction.end]

	argNodes := instructionArgs(instruction.next)

	var wrappers wrapperStack
	var args []string
	changed := false

Args:
	for _, arg := range argNodes {
		fullArg := arg
		isIndirect := false

		if arg.pegRule == ruleIndirectionIndicator {
			arg = arg.next
			isIndirect = true
		}

		switch arg.pegRule {
		case ruleRegisterOrConstant, ruleLocalLabelRef:
			args = append(args, d.currentInput.contents[fullArg.begin:fullArg.end])

		case ruleMemoryRef:
			memRef := arg.up

			var symbol, section string
			if memRef.pegRule == ruleSymbolRef {
				symRef := memRef.up
				memRef = memRef.next

				symbol = d.currentInput.contents[symRef.begin:symRef.end]
				if symRef.pegRule == ruleLocalSymbol {
					mapped := d.mapLocalSymbol(symbol)
					if mapped != symbol {
						symbol = mapped
						changed = true
					}
				}

				symRef = symRef.next
				if symRef != nil {
					assertNodeType(symRef, ruleSection)
					section = d.currentInput.contents[symRef.begin:symRef.end]
				}
			}

			if symbol == "OPENSSL_ia32cap_P" {
				target := argNodes[1]
				assertNodeType(target, ruleRegisterOrConstant)
				reg := d.currentInput.contents[target.begin:target.end]
				instructionName = ""
				changed = true
				d.target.loadIA32Cap(d.output, reg)
				break Args
			}

			if section != "GOTTPOFF" {
				_, knownSymbol := d.symbols[symbol]
				if knownSymbol /*&& globalSymbol doesn't work for ppc64le */ {
					symbol = localTargetName(symbol)
					changed = true
				}
			}

			switch section {
			case "":
				break

			case "PLT":
				if d.target.classifyInstruction(instructionName, argNodes) != instrJump {
					return nil, fmt.Errorf("Cannot rewrite PLT reference for non-jump instruction %q", instructionName)
				}

				if !changed && !isSynthesized(symbol) {
					// Unknown symbol via PLT is an
					// out-call from the module, i.e.
					// memcpy.
					d.redirectors[symbol+"@"+section] = redirectorName(symbol)
					symbol = redirectorName(symbol)
				}

				changed = true

			case "GOTPCREL":
				instructionName = d.target.leaInstruction()
				changed = true

				switch d.target.classifyInstruction(instructionName, argNodes) {
				case instrPush:
					wrappers = append(wrappers, d.target.push(d.output))

				case instrConditionalMove:
					wrappers = append(wrappers, d.target.undoConditionalMove(d.output, instructionName))
					fallthrough

				case instrMove:
					break

				default:
					return nil, fmt.Errorf("Cannot rewrite GOTPCREL reference for instruction %q", instructionName)
				}

			case "GOTTPOFF":
				// GOTTPOFF are offsets into the thread-local
				// storage that are stored in the GOT. We make
				// a call to a synthesized function to get the
				// value.
				changed = true

				switch d.target.classifyInstruction(instructionName, argNodes) {
				case instrPush:
					wrappers = append(wrappers, d.target.push(d.output))
					wrappers = append(wrappers, d.target.call(d.output, tpOffFunction(symbol)))
					instructionName = ""

				case instrConditionalMove:
					wrappers = append(wrappers, d.target.undoConditionalMove(d.output, instructionName))
					fallthrough

				case instrMove:
					target := argNodes[1]
					assertNodeType(target, ruleRegisterOrConstant)
					reg := d.currentInput.contents[target.begin:target.end]
					if !strings.EqualFold(reg[1:], d.target.returnRegister()) {
						wrappers = append(wrappers, d.target.saveRegister(d.output))
						wrappers = append(wrappers, d.target.call(d.output, tpOffFunction(symbol)))
						instructionName = d.target.moveInstruction()
						args = []string{"%" + d.target.returnRegister(), reg}
					} else {
						wrappers = append(wrappers, d.target.call(d.output, tpOffFunction(symbol)))
						instructionName = ""
					}

					break Args

				default:
					panic(fmt.Sprintf("Cannot rewrite GOTTPOFF reference for instruction %q", instructionName))
				}

			default:
				return nil, fmt.Errorf("Unknown section type %q", section)
			}

			section = ""

			argStr := ""
			if isIndirect {
				argStr += "*"
			}
			argStr += symbol

			for ; memRef != nil; memRef = memRef.next {
				argStr += d.currentInput.contents[memRef.begin:memRef.end]
			}

			args = append(args, argStr)

		default:
			panic(fmt.Sprintf("unknown instruction argument type %q", rul3s[arg.pegRule]))
		}
	}

	if changed {
		d.writeCommentedNode(statement)

		if instructionName == d.target.leaInstruction() && len(args) == 2 && !d.target.isValidLEATarget(args[1]) {
			// Sometimes the compiler will load from the GOT to an
			// XMM register, which is not a valid target of an LEA
			// instruction.
			wrappers = append(wrappers, d.target.saveRegister(d.output))
			wrappers = append(wrappers, d.target.moveTo(d.output, args[1]))
			args[1] = d.target.returnRegister()
		}

		var replacement string
		if len(instructionName) > 0 {
			replacement = "\t" + instructionName + "\t" + strings.Join(args, ", ") + "\n"
		}

		wrappers.do(func() {
			d.output.WriteString(replacement)
		})
	} else {
		d.writeNode(statement)
	}

	return statement, nil
}

func (d *delocation) handleBSS(statement *node32) (*node32, error) {
	lastStatement := statement
	for statement = statement.next; statement != nil; lastStatement, statement = statement, statement.next {
		node := skipNodes(statement.up, ruleWS)
		if node == nil {
			d.writeNode(statement)
			continue
		}

		switch node.pegRule {
		case ruleGlobalDirective, ruleComment, ruleInstruction, ruleLocationDirective:
			d.writeNode(statement)

		case ruleDirective:
			directive := node.up
			assertNodeType(directive, ruleDirectiveName)
			directiveName := d.currentInput.contents[directive.begin:directive.end]
			if directiveName == ".text" || directiveName == ".section" {
				return lastStatement, nil
			}
			d.writeNode(statement)

		case ruleLabel:
			label := node.up
			d.writeNode(statement)

			if label.pegRule != ruleLocalSymbol {
				symbol := d.currentInput.contents[label.begin:label.end]
				localSymbol := localTargetName(symbol)
				d.output.WriteString(fmt.Sprintf("\n%s:\n", localSymbol))

				d.bssAccessorsNeeded[symbol] = localSymbol
			}

		case ruleLabelContainingDirective:
			var err error
			statement, err = d.processLabelContainingDirective(statement, node.up)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unknown BSS statement type %q in %q", rul3s[node.pegRule], d.currentInput.contents[statement.begin:statement.end])
		}
	}

	return lastStatement, nil
}

func transform(w stringWriter, target targetPlatform, inputs []inputFile) error {
	// symbols contains all defined symbols and maps to whether they're
	// global or not.
	symbols := make(map[string]bool)

	for _, input := range inputs {
		forEachPath(input.ast.up, func(node *node32) {
			symbol := input.contents[node.begin:node.end]
			if _, ok := symbols[symbol]; ok {
				panic(fmt.Sprintf("Duplicate symbol found: %q", symbol))
			}
			symbols[symbol] = false
		}, ruleStatement, ruleLabel, ruleSymbolName)

		forEachPath(input.ast.up, func(node *node32) {
			symbol := input.contents[node.begin:node.end]
			if _, ok := symbols[symbol]; !ok {
				// GCC will emit .globl directives for symbols
				// that it doesn't define.
				return
			}
			symbols[symbol] = true
		}, ruleStatement, ruleGlobalDirective, ruleSymbolName)
	}

	d := &delocation{
		symbols:            symbols,
		processor:          POWER,
		output:             w,
		target:             target,
		redirectors:        make(map[string]string),
		bssAccessorsNeeded: make(map[string]string),
		tocLoaders:         make(map[string]struct{}),
	}

	w.WriteString(".text\nBORINGSSL_bcm_text_start:\n")

	for _, input := range inputs {
		if err := d.processInput(input); err != nil {
			return err
		}
	}

	w.WriteString(".text\nBORINGSSL_bcm_text_end:\n")

	// Emit redirector functions. Each is a single jump instruction.
	var redirectorNames []string
	for name := range d.redirectors {
		redirectorNames = append(redirectorNames, name)
	}
	sort.Strings(redirectorNames)

	for _, name := range redirectorNames {
		redirector := d.redirectors[name]
		w.WriteString(".type " + redirector + ", @function\n")
		w.WriteString(redirector + ":\n")
		target.jumpTo(w, name)
	}

	var accessorNames []string
	for accessor := range d.bssAccessorsNeeded {
		accessorNames = append(accessorNames, accessor)
	}
	sort.Strings(accessorNames)

	// Emit BSS accessor functions. Each is a single LEA followed by RET.
	for _, name := range accessorNames {
		funcName := accessorName(name)
		w.WriteString(".type " + funcName + ", @function\n")
		w.WriteString(funcName + ":\n")
		target.returnRelativeAddr(w, d.bssAccessorsNeeded[name])
	}

	if d.processor == POWER {
		var loadTOCNames []string
		for name := range d.tocLoaders {
			loadTOCNames = append(loadTOCNames, name)
		}
		sort.Strings(loadTOCNames)

		for _, name := range loadTOCNames {
			parts := strings.SplitN(name, "\x00", 2)
			symAndSection, offset := parts[0], parts[1]
			parts = strings.SplitN(symAndSection, "@", 2)
			symbol, section := parts[0], parts[1]
			funcName := loadTOCFuncName(symbol, section, offset)
			w.WriteString(".type " + funcName + ", @function\n")
			w.WriteString(funcName + ":\n")
			w.WriteString("\taddi 3, 0, " + symAndSection + offset + "\n")
			w.WriteString("\tblr\n")
		}

		w.WriteString("BORINGSSL_bcm_set_toc:\n")
		w.WriteString(".LBORINGSSL_bcm_set_toc:\n")
		w.WriteString("0:\n")
		w.WriteString("\taddis 2,12,.TOC.-0b@ha\n")
		w.WriteString("\taddi 2,2,.TOC.-0b@l\n")
		w.WriteString("\tblr\n")
	}

	/*
		w.WriteString(".type OPENSSL_ia32cap_get, @function\n")
		w.WriteString("OPENSSL_ia32cap_get:\n")
		target.returnRelativeAddr(w, "OPENSSL_ia32cap_P")

		w.WriteString(".extern OPENSSL_ia32cap_P\n")
		w.WriteString(".type OPENSSL_ia32cap_get, @object\n")
		w.WriteString(".size OPENSSL_ia32cap_addr_delta, 8\n")
		w.WriteString("OPENSSL_ia32cap_addr_delta:\n")
		w.WriteString(".quad OPENSSL_ia32cap_P-OPENSSL_ia32cap_addr_delta\n")
	*/

	w.WriteString(".type BORINGSSL_bcm_text_hash, @object\n")
	w.WriteString(".size BORINGSSL_bcm_text_hash, 64\n")
	w.WriteString("BORINGSSL_bcm_text_hash:\n")
	for _, b := range uninitHashValue {
		w.WriteString(".byte 0x" + strconv.FormatUint(uint64(b), 16) + "\n")
	}

	return nil
}

func parseInputs(inputs []inputFile) error {
	for i, input := range inputs {
		var contents string

		if input.isArchive {
			arFile, err := os.Open(input.path)
			if err != nil {
				return err
			}
			defer arFile.Close()

			ar, err := ParseAR(arFile)
			if err != nil {
				return err
			}

			if len(ar) != 1 {
				return fmt.Errorf("expected one file in archive, but found %d", len(ar))
			}

			for _, c := range ar {
				contents = string(c)
			}
		} else {
			inBytes, err := ioutil.ReadFile(input.path)
			if err != nil {
				return err
			}

			contents = string(inBytes)
		}

		asm := Asm{Buffer: contents, Pretty: true}
		asm.Init()
		if err := asm.Parse(); err != nil {
			return fmt.Errorf("error while parsing %q: %s", input.path, err)
		}
		ast := asm.AST()

		inputs[i].contents = contents
		inputs[i].ast = ast
	}

	return nil
}

type instructionType int

const (
	instrPush instructionType = iota
	instrMove
	instrJump
	instrConditionalMove
	instrOther
)

type targetPlatform interface {
	classifyInstruction(instr string, args []*node32) instructionType
	isValidLEATarget(reg string) bool
	leaInstruction() string
	moveInstruction() string
	returnRegister() string

	push(stringWriter) wrapperFunc
	undoConditionalMove(w stringWriter, instr string) wrapperFunc
	call(w stringWriter, target string) wrapperFunc
	saveRegister(stringWriter) wrapperFunc
	moveTo(stringWriter, string) wrapperFunc

	jumpTo(w stringWriter, target string)
	returnRelativeAddr(w stringWriter, target string)
	loadIA32Cap(w stringWriter, target string)
	loadTOC(w stringWriter)
	leaSym(w stringWriter, target, source, offset string, deref bool)
}

type x86_64 struct{}

func (x86_64) classifyInstruction(instr string, args []*node32) instructionType {
	switch instr {
	case "push", "pushq":
		if len(args) == 1 {
			return instrPush
		}

	case "mov", "movq", "cmpq", "leaq":
		if len(args) == 2 {
			return instrMove
		}

	case "cmovneq", "cmoveq":
		if len(args) == 2 {
			return instrConditionalMove
		}

	case "call", "callq", "jmp", "jne", "jb", "jz", "jnz", "ja":
		if len(args) == 1 {
			return instrJump
		}
	}

	return instrOther
}

func (x86_64) isValidLEATarget(reg string) bool {
	return !strings.HasPrefix(reg, "%xmm") && !strings.HasPrefix(reg, "%ymm") && !strings.HasPrefix(reg, "%zmm")
}

func (x86_64) leaInstruction() string {
	return "leaq"
}

func (x86_64) moveInstruction() string {
	return "movq"
}

func (x86_64) returnRegister() string {
	return "rax"
}

func (x86_64) push(w stringWriter) wrapperFunc {
	return func(k func()) {
		w.WriteString("\tpushq %rax\n")
		k()
		w.WriteString("\txchg %rax, (%rsp)\n")
	}
}

func (x86_64) undoConditionalMove(w stringWriter, instr string) wrapperFunc {
	var invertedCondition string

	switch instr {
	case "cmoveq":
		invertedCondition = "ne"
	case "cmovneq":
		invertedCondition = "e"
	default:
		panic(fmt.Sprintf("don't know how to handle conditional move instruction %q", instr))
	}

	return func(k func()) {
		w.WriteString("\tj" + invertedCondition + " 999f\n")
		k()
		w.WriteString("999:\n")
	}
}

func (x86_64) call(w stringWriter, target string) wrapperFunc {
	return func(k func()) {
		w.WriteString("\tcall " + target + "\n")
		k()
	}
}

func (x86_64) saveRegister(w stringWriter) wrapperFunc {
	return func(k func()) {
		w.WriteString("\tleaq -128(%rsp), %rsp\n")
		w.WriteString("\tpushq %rax\n")
		k()
		w.WriteString("\tpopq %rax\n")
		w.WriteString("\tleaq 128(%rsp), %rsp\n")
	}
}

func (x86_64) moveTo(w stringWriter, target string) wrapperFunc {
	return func(k func()) {
		k()
		w.WriteString("\tmovq %rax, " + target + "\n")
	}
}

func (x86_64) jumpTo(w stringWriter, target string) {
	w.WriteString("\tjmp\t" + target + "\n")
}

func (x86_64) returnRelativeAddr(w stringWriter, target string) {
	w.WriteString("\tleaq\t" + target + "(%rip), %rax\n\tret\n")
}

func (x86_64) loadIA32Cap(w stringWriter, target string) {
	w.WriteString("\tleaq\t-128(%rsp), %rsp\n")
	w.WriteString("\tpushfq\n")
	w.WriteString("\tleaq\tOPENSSL_ia32cap_addr_delta(%rip), " + target + "\n")
	w.WriteString("\taddq\tOPENSSL_ia32cap_addr_delta(%rip), " + target + "\n")
	w.WriteString("\tpopfq\n")
	w.WriteString("\tleaq\t128(%rsp), %rsp\n")
}

func (x86_64) loadTOC(w stringWriter) {
	panic("x86-64 doesn't have a TOC")
}

func (x86_64) leaSym(w stringWriter, target, source, offset string, deref bool) {
	panic("x86-64 doesn't have a TOC")
}

type ppc64le struct{}

func (ppc64le) classifyInstruction(instr string, args []*node32) instructionType {
	return instrOther
}

func (ppc64le) isValidLEATarget(reg string) bool {
	panic("no LEA instruction")
}

func (ppc64le) leaInstruction() string {
	return "<fake-lea>"
}

func (ppc64le) moveInstruction() string {
	panic("unimplemented")
}

func (ppc64le) returnRegister() string {
	panic("unimplemented")
}

func (ppc64le) push(w stringWriter) wrapperFunc {
	panic("unimplemented")
}

func (ppc64le) undoConditionalMove(w stringWriter, instr string) wrapperFunc {
	panic("unimplemented")
}

func (ppc64le) call(w stringWriter, target string) wrapperFunc {
	panic("unimplemented")
}

func (ppc64le) saveRegister(w stringWriter) wrapperFunc {
	panic("unimplemented")
}

func (ppc64le) moveTo(w stringWriter, target string) wrapperFunc {
	panic("unimplemented")
}

func (ppc64le) jumpTo(w stringWriter, target string) {
	w.WriteString("\tmflr 0\n")
	w.WriteString("\tstd 0,16(1)\n")
	w.WriteString("\tstdu 1,-32(1)\n")
	w.WriteString("\tbl\t" + target + "\n")
	w.WriteString("\tnop\n")
	w.WriteString("\taddi 1,1,32\n")
	w.WriteString("\tld 0,16(1)\n")
	w.WriteString("\tmtlr 0\n")
	w.WriteString("\tblr\n")
}

func (p ppc64le) returnRelativeAddr(w stringWriter, target string) {
	w.WriteString("\taddis 3, 2, " + target + "@toc@ha\n")
	w.WriteString("\taddi 3, 3, " + target + "@toc@l\n")
	w.WriteString("\tblr\n")
}

func (ppc64le) loadIA32Cap(w stringWriter, target string) {
	panic("unimplemented")
}

func (ppc64le) loadTOC(w stringWriter) {
	w.WriteString("\tstd 3,16(1)\n")
	w.WriteString("\tmflr 3\n")
	w.WriteString("\tstd 3,8(1)\n")
	w.WriteString("\tbl .LBORINGSSL_bcm_set_toc\n")
	w.WriteString("\tld 3,8(1)\n")
	w.WriteString("\tmtlr 3\n")
	w.WriteString("\tld 3,16(1)\n")
	w.WriteString("\tnop\n")
}

func (ppc64le) leaSym(w stringWriter, target, source, offset string, deref bool) {
	temp := "3"
	if temp == target {
		temp = "4"
	}

	w.WriteString("\taddi 1, 1, -288\n")
	w.WriteString("\tstd " + temp + ", 0(1)\n")
	w.WriteString("\tmflr " + temp + "\n")
	w.WriteString("\tstd " + temp + ", 8(1)\n")
	w.WriteString("\tbl bcm_loadtoc_" + source + "\n")

	if len(offset) > 0 {
		offsetBytes, err := strconv.Atoi(offset)
		if err != nil {
			panic(err)
		}

		w.WriteString("\taddi 3, 3, " + strconv.Itoa(offsetBytes) + "\n")
	}

	if target != "3" {
		w.WriteString("\tmr " + target + ", 3\n")
	}
	if deref {
		w.WriteString("\tld " + target + ", 0(" + target + ")\n")
	}

	w.WriteString("\tld " + temp + ", 8(1)\n")
	w.WriteString("\tmtlr " + temp + "\n")
	w.WriteString("\tld " + temp + ", 0(1)\n")
	w.WriteString("\taddi 1, 1, 288\n")
}

func main() {
	// The .a file, if given, is expected to be an archive of textual
	// assembly sources. That's odd, but CMake really wants to create
	// archive files so it's the only way that we can make it work.
	arInput := flag.String("a", "", "Path to a .a file containing assembly sources")
	outFile := flag.String("o", "", "Path to output assembly")
	isPPC := flag.Bool("ppc64le", false, "Target ppc64le output")

	flag.Parse()

	if len(*outFile) == 0 {
		fmt.Fprintf(os.Stderr, "Must give argument to -o.\n")
		os.Exit(1)
	}

	var inputs []inputFile
	if len(*arInput) > 0 {
		inputs = append(inputs, inputFile{
			path:      *arInput,
			index:     0,
			isArchive: true,
		})
	}

	for i, path := range flag.Args() {
		if len(path) == 0 {
			continue
		}

		inputs = append(inputs, inputFile{
			path:  path,
			index: i + 1,
		})
	}

	if err := parseInputs(inputs); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	out, err := os.OpenFile(*outFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	var target targetPlatform
	target = x86_64{}
	if *isPPC {
		target = ppc64le{}
	}

	if err := transform(out, target, inputs); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func forEachPath(node *node32, cb func(*node32), rules ...pegRule) {
	if node == nil {
		return
	}

	if len(rules) == 0 {
		cb(node)
		return
	}

	rule := rules[0]
	childRules := rules[1:]

	for ; node != nil; node = node.next {
		if node.pegRule != rule {
			continue
		}

		if len(childRules) == 0 {
			cb(node)
		} else {
			forEachPath(node.up, cb, childRules...)
		}
	}
}

func skipNodes(node *node32, ruleToSkip pegRule) *node32 {
	for ; node != nil && node.pegRule == ruleToSkip; node = node.next {
	}
	return node
}

func assertNodeType(node *node32, expected pegRule) {
	if rule := node.pegRule; rule != expected {
		panic(fmt.Sprintf("node was %q, but wanted %q", rul3s[rule], rul3s[expected]))
	}
}

type wrapperFunc func(func())

type wrapperStack []wrapperFunc

func (w *wrapperStack) do(baseCase func()) {
	if len(*w) == 0 {
		baseCase()
		return
	}

	wrapper := (*w)[0]
	*w = (*w)[1:]
	wrapper(func() { w.do(baseCase) })
}

// localTargetName returns the name of the local target label for a global
// symbol named name.
func localTargetName(name string) string {
	return ".L" + name + "_local_target"
}

func isSynthesized(symbol string) bool {
	return strings.HasSuffix(symbol, "_bss_get") || symbol == "OPENSSL_ia32cap_get" || strings.HasPrefix(symbol, "BORINGSSL_bcm_text_")
}

func redirectorName(symbol string) string {
	return "bcm_redirector_" + symbol
}

func tpOffFunction(symbol string) string {
	return "BORINGSSL_bcm_tpoff_" + symbol
}

// sectionType returns the type of a section. I.e. a section called “.text.foo”
// is a “.text” section.
func sectionType(section string) (string, bool) {
	if len(section) == 0 || section[0] != '.' {
		return "", false
	}

	i := strings.Index(section[1:], ".")
	if i != -1 {
		section = section[:i+1]
	}

	if strings.HasPrefix(section, ".debug_") {
		return ".debug", true
	}

	return section, true
}

// accessorName returns the name of the accessor function for a BSS symbol
// named name.
func accessorName(name string) string {
	return name + "_bss_get"
}

func (d *delocation) mapLocalSymbol(symbol string) string {
	if d.currentInput.index == 0 {
		return symbol
	}
	return symbol + "_BCM_" + strconv.Itoa(d.currentInput.index)
}
