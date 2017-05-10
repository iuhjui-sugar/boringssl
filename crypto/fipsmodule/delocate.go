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

// delocate performs several transformations of textual assembly code. See
// FIPS.md in this directory for an overview.
package main

import (
	"io/ioutil"
	"sort"
	"fmt"
	"os"
	"strconv"
	"errors"
	"strings"
	"flag"
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
	WriteString (string) (int, error)
}

// delocation holds the state needed during a delocation operation.
type delocation struct {
	target targetPlatform

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

	currentInput inputFile
}

// writeNode writes out an AST node.
func (d *delocation) writeNode(node *node32) {
	if _, err := d.output.WriteString(d.currentInput.contents[node.begin:node.end]); err != nil {
		panic(err)
	}
}

func (d *delocation) writeCommentedNode(node *node32) {
	return
	line := d.currentInput.contents[node.begin:node.end]
	if _, err := d.output.WriteString("# WAS " + strings.TrimSpace(line) + "\n"); err != nil {
		panic(err)
	}
}

func (d *delocation) processInput(input inputFile) (err error) {
	statement := input.ast.up
	d.currentInput = input

	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(os.Stdout, "Error while processing:\n  %s%s\n", input.contents[statement.begin:statement.end], err)
			os.Exit(1)
		}
	}()

	for ; statement != nil; statement = statement.next {
		node := skipNodes(statement.up, ruleWS)
		if node == nil {
			d.writeNode(statement)
			continue
		}

		switch node.pegRule {
			case ruleGlobalDirective, ruleComment:
				d.writeNode(statement)
			case ruleDirective:
				if statement, err = d.processDirective(statement, node.up); err != nil {
					return err
				}
			case ruleLabel:
				if statement, err = d.processLabel(statement, node.up); err != nil {
					return err
				}
			case ruleInstruction:
				if statement, err = d.processInstruction(statement, node.up); err != nil {
					return err
				}
			default:
				panic(fmt.Sprintf("unknown top-level statement type %q", rul3s[node.pegRule]))
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
	case "comm":
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

		case ".debug", ".note":
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

func (d *delocation) processLabel(statement, label *node32) (*node32, error) {
	symbol := d.currentInput.contents[label.begin:label.end]

	if label.pegRule == ruleLocalSymbol {
		d.output.WriteString(d.mapLocalSymbol(symbol) + ":\n")
	} else {
		d.output.WriteString(localTargetName(symbol) + ":\n")
		d.writeNode(statement)
	}

	return statement, nil
}

func (d *delocation) processInstruction(statement, instruction *node32) (*node32, error) {
	assertNodeType(instruction, ruleInstructionName)
	instructionName := d.currentInput.contents[instruction.begin:instruction.end]

	var argNodes []*node32
	for node := instruction.next; node != nil; node = node.next {
		if node.pegRule != ruleInstructionArg {
			continue
		}

		argNodes = append(argNodes, node.up)
	}

	var wrappers wrapperStack
	var args []string
	changed := false

	Args:
	for argNum, arg := range argNodes {
		fullArg := arg
		isIndirect := false

		if arg.pegRule == ruleIndirectionIndicator {
			arg = arg.next
			isIndirect = true
		}

		switch arg.pegRule {
		case ruleRegister, ruleConstant, ruleLocalLabelRef:
			args = append(args, d.currentInput.contents[fullArg.begin:fullArg.end])

		case ruleMemoryRef:
			memRef := arg.up

			var symbol, section string
			if memRef.pegRule == ruleSymbolRef {
				if len(argNodes) > 1 && argNum == len(argNodes) - 1 {
					return nil, errors.New("cannot handle writing to a symbol")
				}

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
				assertNodeType(target, ruleRegister)
				reg := d.currentInput.contents[target.begin:target.end]
				instructionName = ""
				changed = true
				d.target.loadIA32Cap(d.output, reg)
				break Args
			}

			if section != "GOTTPOFF" {
				globalSymbol, knownSymbol := d.symbols[symbol]
				if knownSymbol && globalSymbol {
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
					d.redirectors[symbol + "@" + section] = redirectorName(symbol)
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
					assertNodeType(target, ruleRegister)
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
				panic(fmt.Sprintf("Unknown section type %q", section))
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

			/*
			node := statement.up
			for ; node != nil; node = node.next {
				if node.pegRule == ruleInstruction {
					node = node.next
					break
				}
			}
			for ; node != nil; node = node.next {
				d.output.WriteString(d.currentInput.contents[node.begin:node.end])
			}

			d.output.WriteString("\n")*/
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
			case ruleGlobalDirective, ruleComment, ruleInstruction:
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

			default:
				return nil, fmt.Errorf("unknown top-level statement type %q", rul3s[node.pegRule])
		}
	}

	return lastStatement, nil
}

func transform(w stringWriter, inputs []inputFile) error {
	// symbols contains all defined symbols and maps to whether they're
	// global or not.
	symbols := make(map[string]bool)

	for _, input := range inputs {
		forEachPath(input.ast.up, func (node *node32) {
			symbol := input.contents[node.begin:node.end]
			if _, ok := symbols[symbol]; ok {
				panic(fmt.Sprintf("Duplicate symbol found: %q", symbol))
			}
			symbols[symbol] = false
		}, ruleStatement, ruleLabel, ruleSymbolName)

		forEachPath(input.ast.up, func (node *node32) {
			symbol := input.contents[node.begin:node.end]
			if _, ok := symbols[symbol]; !ok {
				panic(fmt.Sprintf("Global directive for unknown symbol: %q", symbol))
			}
			symbols[symbol] = true
		}, ruleStatement, ruleGlobalDirective, ruleSymbolName)
	}

	var platform x86_64

	d := &delocation{
		symbols: symbols,
		output: w,
		target: platform,
		redirectors: make(map[string]string),
		bssAccessorsNeeded: make(map[string]string),
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
		platform.jumpTo(w, name)
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
		platform.returnRelativeAddr(w, d.bssAccessorsNeeded[name])
	}

	w.WriteString(".type OPENSSL_ia32cap_get, @function\n")
	w.WriteString("OPENSSL_ia32cap_get:\n")
	platform.returnRelativeAddr(w, "OPENSSL_ia32cap_P")

	w.WriteString(".extern OPENSSL_ia32cap_P\n")
	w.WriteString(".type OPENSSL_ia32cap_get, @object\n")
	w.WriteString(".size OPENSSL_ia32cap_addr_delta, 8\n")
	w.WriteString("OPENSSL_ia32cap_addr_delta:\n")
	w.WriteString(".quad OPENSSL_ia32cap_P-OPENSSL_ia32cap_addr_delta\n")

	w.WriteString(".type BORINGSSL_bcm_text_hash, @object\n")
	w.WriteString(".size BORINGSSL_bcm_text_hash, 64\n")
	w.WriteString("BORINGSSL_bcm_text_hash:\n")
	for _, b := range uninitHashValue {
		w.WriteString(".byte 0x"+strconv.FormatUint(uint64(b), 16) + "\n")
	}

	fmt.Printf("%d symbols\n", len(symbols))
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
		w.WriteString("\tj" + invertedCondition + " 1f\n")
		k()
		w.WriteString("1:\n")
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

func main() {
	// The .a file, if given, is expected to be an archive of textual
	// assembly sources. That's odd, but CMake really wants to create
	// archive files so it's the only way that we can make it work.
	arInput := flag.String("a", "", "Path to a .a file containing assembly sources")
	outFile := flag.String("o", "", "Path to output assembly")

	flag.Parse()

	var inputs []inputFile
	if len(*arInput) > 0 {
		inputs = append(inputs, inputFile{
			path: *arInput,
			index: 0,
			isArchive: true,
		})
	}

	for i, path := range flag.Args() {
		if len(path) == 0 {
			continue
		}

		inputs = append(inputs, inputFile{
			path: path,
			index: i+1,
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

	if err := transform(out, inputs); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func forEachPath(node *node32, cb func (*node32), rules ...pegRule) {
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
	for ; node != nil && node.pegRule == ruleToSkip; node = node.next {}
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
	wrapper(func() {w.do(baseCase)})
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
