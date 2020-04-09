# Ghidra Snippets
*Ghidra Snippets* is a collection of Python examples showing how to work with [Ghidra](https://ghidra-sre.org/) APIs. There are three primary APIs covered here, the [Flat Program API][1], the [Flat Decompiler API][2], and everything else ("Complex API"). The Flat APIs are 'simple' versions of the full fledged Complex Ghidra API. They are a great starting point for anyone looking to develop Ghidra modules and/or scripts.

At some point however, you need to reach outside of the Flat APIs to do really interesting things. Everything here is just a mashup to get the job done. There's more than one way to accomplish each task so make sure you ask yourself if these snippets are really what you need before copy/pasta.

# Latest Release & API Docs
* Loooking for the latest release of Ghidra? [Download it here][0]. 
* Loooking for the latest API Docs? In Ghidra's UI, select **Help** -> **Ghidra API Help** to unpack the docs and view them.
* Just want a quick online API reference? [Ghidra.re](https://ghidra.re/) hosts an online version of the [API docs](https://ghidra.re/ghidra_docs/api/index.html) (may not be up to date).

# Contributing

Feel free to submit pull requests to master on this repo with any modifications you see fit. Most of these snippets are meant to be verbose, but if you know of a better way to do something, please share it via pull request or submitting an issue. Thanks!

# Table of Contents

<details>
<summary>Working with Projects</summary>

* [`Get the name and location on disk of the current project`](#get-the-name-and-location-on-disk-of-the-current-project)
* [`List all programs in the current project`](#list-all-programs-in-the-current-project)

</details>

<details>
<summary>Working with Programs</summary>

* [`List the current program name and location on disk`](#list-the-current-program-name-and-location-on-disk)
* [`List the name and size of program sections`](#list-the-name-and-size-of-program-sections)

</details>


<details>
<summary>Working with Functions</summary>

* [`Enumerate all functions printing their name and address`](#enumerate-all-functions-printing-their-name-and-address)
* [`Get a function name by address`](#get-a-function-name-by-address)
* [`Get a function address by name`](#get-a-function-address-by-name)

</details>

<details>
<summary>Working with Instructions</summary>

* [`Print all instructions in a select function`](#print-all-instructions-in-a-select-function)
* [`Find all calls and jumps to a register`](#find-all-calls-and-jumps-to-a-register)

</details>

<details>
<summary>Working with Basic Blocks</summary>

* [`Print details about basic blocks in a select function`](#print-details-about-basic-blocks-in-a-select-function)

</details>

<details>
<summary>Working with the Decompiler</summary>

* [`Print decompiled code for a specific function`](#print-decompiled-code-for-a-specific-function)

</details>

<details>
<summary>Working with Comments</summary>

* [`Get all Automatic comments for a function`](#get-all-automatic-comments-for-a-function)

</details>

<details>
<summary>Working with PCode</summary>

* [`Emulating a function`](#emulating-a-function)
* [`Dumping Raw PCode`](#dumping-raw-pcode)
* [`Dumping Refined PCode`](#dumping-refined-pcode)
* [`Plotting a Function AST`](#plotting-a-function-ast)

</details>

<details>
<summary>Working with Graphs</summary>

* [`Creating a Call Graph`](#creating-a-call-graph)

</details>

<details>
<summary>Miscellaneous</summary>

* [`Program Slices`](#program-slices)

</details>


## Working with Projects
A Ghidra *Project* (class [GhidraProject][4]) contains a logical set of program binaries related to a reverse engineering effort. Projects can be shared (collaborative) or non-shared (private). The snippets in this section deal with bulk import and analysis, locating project files on disk, and more.

### Get the name and location on disk of the current project
If you're looking to automate analysis using headless scripts you'll likley have to deal with project management. This includes adding binaries to existing projects, cleaning up old projects, or perhaps syncing analysis to shared projects.

```python
state = getState()
project = state.getProject()
program = state.getCurrentProgram()
locator = project.getProjectData().getProjectLocator()
print("type(state):           {}".format(type(state)))
print("type(project):         {}".format(type(project)))
print("type(program):         {}".format(type(program)))
print("type(locator):         {}".format(type(locator)))
print("Project Name:          {}".format(locator.getName()))
print("Files in this project: {}".format(project.getProjectData().getFileCount()))
print("Is a remote project:   {}".format(locator.isTransient()))
print("Project location:      {}".format(locator.getLocation()))
print("Project directory:     {}".format(locator.getProjectDir()))
print("Lock file:             {}".format(locator.getProjectLockFile()))
print("Marker file:           {}".format(locator.getMarkerFile()))
print("Project URL:           {}".format(locator.getURL()))
```

<details>
<summary>Output example</summary>

```
type(state):           <type 'ghidra.app.script.GhidraState'>
type(project):         <type 'ghidra.framework.project.DefaultProject'>
type(program):         <type 'ghidra.program.database.ProgramDB'>
type(locator):         <type 'ghidra.framework.model.ProjectLocator'>
Project Name:          pcodeproject
Files in this project: 4
Is a remote project:   0
Project location:      C:\Users\username\Desktop\pcode
Project directory:     C:\Users\username\Desktop\pcode\pcodeproject.rep
Lock file:             C:\Users\username\Desktop\pcode\pcodeproject.lock
Marker file:           C:\Users\username\Desktop\pcode\pcodeproject.gpr
Project URL:           ghidra:/C:/Users/username/Desktop/pcode/pcodeproject
```
</details>

<br>[⬆ Back to top](#table-of-contents)

### List all programs in the current project
A Ghidra project is a logical collection binaries that relate to a specific RE effort. This might be a single executable with multiple shared objects, or multiple executables with numerous third-party libraries, kernel modules, and drivers.

```python
state = getState()
project = state.getProject()
locator = project.getProjectData().getProjectLocator()
projectMgr = project.getProjectManager()
activeProject = projectMgr.getActiveProject()
projectData = activeProject.getProjectData()
rootFolder = projectData.getRootFolder()

print("type(state):           {}".format(type(state)))
print("type(project):         {}".format(type(project)))
print("type(projectMgr):      {}".format(type(projectMgr)))
print("type(activeProject):   {}".format(type(activeProject)))
print("type(projectData):     {}".format(type(projectData)))
print("type(rootFolder):      {}".format(type(rootFolder)))

projectName = locator.getName()
fileCount = projectData.getFileCount()
files = rootFolder.getFiles()

print("The project '{}' has {} files in it:".format(projectName, fileCount))
for file in files:
	print("\t{}".format(file))
```

<details>
<summary>Output example</summary>

```
type(state):           <type 'ghidra.app.script.GhidraState'>
type(project):         <type 'ghidra.framework.project.DefaultProject'>
type(projectMgr):      <type 'ghidra.GhidraRun$GhidraProjectManager'>
type(activeProject):   <type 'ghidra.framework.project.DefaultProject'>
type(projectData):     <type 'ghidra.framework.data.ProjectFileManager'>
type(rootFolder):      <type 'ghidra.framework.data.RootGhidraFolder'>
The project 'pcodeproject' has 4 files in it:
	pcodeproject:/WinSCP.exe
	pcodeproject:/deobExampleX86
	pcodeproject:/deobHookExampleX86
	pcodeproject:/server
```
</details>

<br>[⬆ Back to top](#table-of-contents)


## Working with Programs
A *Program* is a binary component within a Ghidra Project. The snippets in this section deal with gathering information about the Programs within a Project.

### List the current program name and location on disk
```python
state = getState()
currentProgram = state.getCurrentProgram()
name = currentProgram.getName()
location = currentProgram.getExecutablePath()
print("The currently loaded program is: '{}'".format(name))
print("Its location on disk is: '{}'".format(location))
```

<details>
<summary>Output example</summary>

```
The currently loaded program is: 'deobExampleX86'
Its location on disk is: '/C:/Users/username/Desktop/pcode/emulation/deobExampleX86'
```
</details>

<br>[⬆ Back to top](#table-of-contents)


### List the name and size of program sections
```python
blocks = currentProgram.getMemory().getBlocks()
for block in blocks:
	print("Name: {}, Size: {}".format(block.getName(), block.getSize()))
```

<details>
<summary>Output example</summary>

```
Name: segment_2.1, Size: 568
Name: .interp, Size: 28
Name: .note.ABI-tag, Size: 32
Name: .note.gnu.build-id, Size: 36
Name: .gnu.hash, Size: 36
Name: .dynsym, Size: 360
Name: .dynstr, Size: 192
Name: .gnu.version, Size: 30
Name: .gnu.version_r, Size: 48
Name: .rela.dyn, Size: 216
Name: .rela.plt, Size: 192
Name: .init, Size: 23
Name: .plt, Size: 144
Name: .plt.got, Size: 8
Name: .text, Size: 706
Name: .fini, Size: 9
Name: .rodata, Size: 134
Name: .eh_frame_hdr, Size: 68
Name: .eh_frame, Size: 296
Name: .init_array, Size: 8
Name: .fini_array, Size: 8
Name: .dynamic, Size: 496
Name: .got, Size: 128
Name: .data, Size: 16
Name: .bss, Size: 16
Name: EXTERNAL, Size: 104
Name: .comment, Size: 43
Name: .shstrtab, Size: 254
Name: .strtab, Size: 672
Name: .symtab, Size: 1728
Name: _elfSectionHeaders, Size: 1856
```
</details>

<br>[⬆ Back to top](#table-of-contents)


## Working with Functions
A *Function* is a subroutine within an Program. The snippets in this section deal with gathering information about Functions and modifying them within an Program.

### Enumerate all functions printing their name and address
There are at least two ways to do this. The output is the same for each method.
```python
# Method 1:
func = getFirstFunction()
while func is not None:
    print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
    func = getFunctionAfter(func)

# Method 2:
fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True) # True means 'forward'
for func in funcs: 
    print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
```

<details>
<summary>Output example</summary>

```
Function: _alloca_probe @ 0x1400a8e00
Function: FUN_1400a8e70 @ 0x1400a8e70
... snip ...
```
</details>

<br>[⬆ Back to top](#table-of-contents)

### Get a function name by address
This snippet will help you correlate addresses with associated function names.

```python
# helper function to get a Ghidra Address type
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# get a FunctionManager reference for the current program
functionManager = currentProgram.getFunctionManager()

# getFunctionAt() only works with function entryPoint addresses!
# returns `None` if address is not the address of the first
# instruction in a defined function. Consider using
# getFunctionContaining() method instead.
addr = getAddress(0x00100690)
funcName = functionManager.getFunctionAt(addr).getName()
print(funcName)

# check if a specific address resides in a function
addr = getAddress(0x00100691)
print(functionManager.isInFunction(addr))

# get the function an address belongs to, returns `None` if the address
# is not part of a defined function.
addr = getAddress(0x00100691)
print(functionManager.getFunctionContaining(addr))
```

<details>
<summary>Output example</summary>

```
main
True
main
```
</details>

<br>[⬆ Back to top](#table-of-contents)

### Get a function address by name
Have a name for a function but want the entry point address for it? This will help you do that. Just remember that two or more functions can share the same name (due to function overloading), so Ghidra will return an array (Python list) you have to consider iterating over.

```python
# Note that multiple functions can share the same name, so Ghidra's API
# returns a list of `Function` types. Just keep this in mind.
name = "main"
funcs = getGlobalFunctions(name)
print("Found {} function(s) with the name '{}'".format(len(funcs), name))
for func in funcs:
	print("{} is located at 0x{}".format(func.getName(), func.getEntryPoint()))
```

<details>
<summary>Output example</summary>

```
Found 1 function(s) with the name 'main'
main is located at 0x00100690
```
</details>

<br>[⬆ Back to top](#table-of-contents)

## Working with Instructions

### Print all instructions in a select function
Just like `objdump` or a `disas` command in GDB, Ghidra provides a way to dump instructions if you need.  You might do this to generate input for another application, or for documenting issues found during analysis. Whatever you use case might be, you can easily acquire the address, opcodes, and instruction text for a target function, or specific addresses.

```python
from binascii import hexlify

listing = currentProgram.getListing()
main_func = getGlobalFunctions("main")[0] # assume there's only 1 function named 'main'
addrSet = main_func.getBody()
codeUnits = listing.getCodeUnits(addrSet, True) # true means 'forward'

for codeUnit in codeUnits:
	print("0x{} : {:16} {}".format(codeUnit.getAddress(), hexlify(codeUnit.getBytes()), codeUnit.toString()))
```

<details>
<summary>Output example</summary>

```
0x00100690 : 55               PUSH RBP
0x00100691 : 4889e5           MOV RBP,RSP
0x00100694 : 4883ec30         SUB RSP,0x30
0x00100698 : 897ddc           MOV dword ptr [RBP + -0x24],EDI
0x0010069b : 488975d0         MOV qword ptr [RBP + -0x30],RSI
0x0010069f : 488d051a010000   LEA RAX,[0x1007c0]
0x001006a6 : 488945f0         MOV qword ptr [RBP + -0x10],RAX
0x001006aa : c745e800000000   MOV dword ptr [RBP + -0x18],0x0
0x001006b1 : eb4d             JMP 0x00100700
0x001006b3 : 488b45f0         MOV RAX,qword ptr [RBP + -0x10]
0x001006b7 : 4889c7           MOV RDI,RAX
0x001006ba : e83bffffff       CALL 0x001005fa
0x001006bf : 8945ec           MOV dword ptr [RBP + -0x14],EAX
0x001006c2 : 8b55ec           MOV EDX,dword ptr [RBP + -0x14]
0x001006c5 : 488b45f0         MOV RAX,qword ptr [RBP + -0x10]
0x001006c9 : 488d3570092000   LEA RSI,[0x301040]
0x001006d0 : 4889c7           MOV RDI,RAX
0x001006d3 : e84fffffff       CALL 0x00100627
0x001006d8 : 488945f8         MOV qword ptr [RBP + -0x8],RAX
0x001006dc : 8b45e8           MOV EAX,dword ptr [RBP + -0x18]
0x001006df : 8d5001           LEA EDX,[RAX + 0x1]
0x001006e2 : 8955e8           MOV dword ptr [RBP + -0x18],EDX
0x001006e5 : 488b55f8         MOV RDX,qword ptr [RBP + -0x8]
0x001006e9 : 89c6             MOV ESI,EAX
0x001006eb : 4889d7           MOV RDI,RDX
0x001006ee : e88fffffff       CALL 0x00100682
0x001006f3 : 8b45ec           MOV EAX,dword ptr [RBP + -0x14]
0x001006f6 : 4898             CDQE
0x001006f8 : 4883c001         ADD RAX,0x1
0x001006fc : 480145f0         ADD qword ptr [RBP + -0x10],RAX
0x00100700 : 488b45f0         MOV RAX,qword ptr [RBP + -0x10]
0x00100704 : 0fb600           MOVZX EAX,byte ptr [RAX]
0x00100707 : 84c0             TEST AL,AL
0x00100709 : 75a8             JNZ 0x001006b3
0x0010070b : b800000000       MOV EAX,0x0
0x00100710 : c9               LEAVE
0x00100711 : c3               RET
```
</details>

<br>[⬆ Back to top](#table-of-contents)


### Find all calls and jumps to a register
This snippet shows how to find all instructions in an x86 program that are calls or jumps to a regitser. This information can be useful when attempting to track down a crash by researching code flow in hard-to-debug targets. `getRegister` returns `None` when the specified index is not a regitser. We use `startswith('J')` to account for all jump variants. This is not architecture agnostic and a little goofy but it gets the job done.

```python
listing = currentProgram.getListing()
func = getFirstFunction()
entryPoint = func.getEntryPoint()
instructions = listing.getInstructions(entryPoint, True)

for instruction in instructions:
    addr = instruction.getAddress()
    oper = instruction.getMnemonicString()
    if (oper.startswith('CALL') or oper.startswith('J') and instruction.getRegister(0)):
        print("0x{} : {}".format(addr, instruction))
```

<details>
<summary>Output example</summary>

```
0x001004c8 : CALL RAX
0x00100544 : JMP RAX
0x00100595 : JMP RDX
0x00100771 : CALL R15
```
</details>

<br>[⬆ Back to top](#table-of-contents)


## Working with Basic Blocks
Basic Blocks are collections of continuous non-branching instructions within Functions. They are joined by conditional and non-conditional branches, revealing valuable information about a program and function's code flow. This section deals with examples working with Basic Block models.

### Print details about basic blocks in a select function
```python
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

funcName = 'main'
blockModel = BasicBlockModel(currentProgram)
monitor = ConsoleTaskMonitor()
func = getGlobalFunctions(funcName)[0]

print("Basic block details for function '{}':".format(funcName))
blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)

# print first block
print("\t[*] {} ".format(func.getEntryPoint()))

# print any remaining blocks
while(blocks.hasNext()):
    bb = blocks.next()
    dest = bb.getDestinations(monitor)
    while(dest.hasNext()):
        dbb = dest.next()
        # For some odd reason `getCodeBlocksContaining()` and `.next()`
        # return the root basic block after CALL instructions (x86). To filter
        # these out, we use `getFunctionAt()` which returns `None` if the address
        # is not the entry point of a function. See:
        # https://github.com/NationalSecurityAgency/ghidra/issues/855
        if not getFunctionAt(dbb.getDestinationAddress()):
            print("\t[*] {} ".format(dbb))
```

<details>
<summary>Output example</summary>

```
Basic block details for function 'main':
	[*] 00100690 
	[*] 001006b1 -> 00100700 
	[*] 001006fc -> 00100700 
	[*] 00100709 -> 001006b3 
	[*] 00100709 -> 0010070b 
```
</details>

<br>[⬆ Back to top](#table-of-contents)


## Working with the Decompiler

### Print decompiled code for a specific function
Ghidra's decompiler is an exceptional resource. In certain cases you might want to extract the decompiler output for a list of functions. Here's an easy way to gather that information.  Just add your own file I/O code to dump everything to individual files for analysis.

```python
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

program = getCurrentProgram()
ifc = DecompInterface()
ifc.openProgram(program)

# here we assume there is only one function named `main`
function = getGlobalFunctions('main')[0]

# decompile the function and print the pseudo C
results = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())
print(results.getDecompiledFunction().getC())
```

<details>
<summary>Output example</summary>

```
undefined8 main(void)

{
  uint uVar1;
  undefined8 uVar2;
  uint local_20;
  undefined1 *local_18;
  
  local_18 = data;
  local_20 = 0;
  while (*local_18 != '\0') {
    uVar1 = length(local_18);
    uVar2 = deobfuscate(local_18,buffer,(ulong)uVar1);
    use_string(uVar2,(ulong)local_20,uVar2);
    local_18 = local_18 + (long)(int)uVar1 + 1;
    local_20 = local_20 + 1;
  }
  return 0;
}

```
</details>

<br>[⬆ Back to top](#table-of-contents)

## Working with Comments

### Get all Automatic comments for a function

Ghidra adds "automatic comments" (light gray in color) in the EOL field. Here's how you can access those comments.

```python
from ghidra.app.util import DisplayableEol

listing = currentProgram.getListing()
func = getGlobalFunctions("frame_dummy")[0]
addrSet = func.getBody()
codeUnits = listing.getCodeUnits(addrSet, True)

for codeUnit in codeUnits:
	deol = DisplayableEol(codeUnit, True, True, True, True, 5, True)
	if deol.hasAutomatic():
		ac = deol.getAutomaticComment()
		print(type(ac))
		print(ac)
		print(ac[0])
```

<details>
<summary>Output example</summary>

```
<type 'array.array'>
array(java.lang.String, [u'undefined register_tm_clones()'])
undefined register_tm_clones()
... snip ...
```
</details>

<br>[⬆ Back to top](#table-of-contents)


## Working with PCode

### Emulating a function
Instruction emulation is an extremely powerful technique to asist in static code analysis.  Rarely however, do we have the full memory context in which dynamic code executes. So while emulation can bring an element of 'dynamic' analysis to static RE, it's typically plagued with problems of unknown memory state. For simple code this might be no problem. For object oriented code this can be a major difficulty.  Either way, some element of emulation can help tremendously in speeding up analysis.  Ghidra uses its internal intermediate representation (PCode) to define what instructions do. Emulation is the process of tracking these changes in a cumulative state. Unfortunely Ghidra doesn't provide fancy GUI controls around the emulator (yet), but it's fully scriptable. Ghidra v9.1 added emprovements to the `EmulatorHelper` class, which is really quite amazing. Here's a simple example of what you can do with it.

```python
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.symbol import SymbolUtilities

# == Helper functions ======================================================
def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def getSymbolAddress(symbolName):
    symbol = SymbolUtilities.getLabelOrFunctionSymbol(currentProgram, symbolName, None)
    if (symbol != None):
        return symbol.getAddress()
    else:
        raise("Failed to locate label: {}".format(symbolName))

def getProgramRegisterList(currentProgram):
    pc = currentProgram.getProgramContext()
    return pc.registers

# == Main function =========================================================
def main():
    CONTROLLED_RETURN_OFFSET = 0

    # Identify function to be emulated
    mainFunctionEntry = getSymbolAddress("main")

    # Establish emulation helper, please check out the API docs
    # for `EmulatorHelper` - there's a lot of helpful things
    # to help make architecture agnostic emulator tools.
    emuHelper = EmulatorHelper(currentProgram)

    # Set controlled return location so we can identify return from emulated function
    controlledReturnAddr = getAddress(CONTROLLED_RETURN_OFFSET)

    # Set initial RIP
    mainFunctionEntryLong = int("0x{}".format(mainFunctionEntry), 16)
    emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntryLong)

    # For x86_64 `registers` contains 872 registers! You probably don't
    # want to print all of these. Just be aware, and print what you need.
    # To see all supported registers. just print `registers`.
    # We won't use this, it's just here to show you how to query
    # valid registers for your target architecture.
    registers = getProgramRegisterList(currentProgram)

    # Here's a list of all the registers we want printed after each
    # instruction. Modify this as you see fit, based on your architecture.
    reg_filter = [
        "RIP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", 
        "RSP", "RBP", "rflags"
    ]

    # Setup your desired starting state. By default, all registers
    # and memory will be 0. This may or may not be acceptable for
    # you. So please be aware.
    emuHelper.writeRegister("RAX", 0x20)
    emuHelper.writeRegister("RSP", 0x000000002FFF0000)
    emuHelper.writeRegister("RBP", 0x000000002FFF0000)
    
    # There are a couple of ways to write memory, use `writeMemoryValue` if you want
    # to set a small typed value (e.g. uint64). Use `writeMemory` if you're mapping in
    # a lot of memory (e.g. from a debugger memory dump). Note that each of these
    # methods write with different endianess, see the example output.
    emuHelper.writeMemoryValue(getAddress(0x000000000008C000), 4, 0x99AABBCC)  # writes big endian
    emuHelper.writeMemory(getAddress(0x00000000000CF000), b'\x99\xAA\xBB\xCC') # writes little endian

    # You can verify writes worked, or just read memory at select points
    # during emulation. Here's a couple of examples:
    mem1 = emuHelper.readMemory(getAddress(0x000000000008C000), 4)
    mem2 = emuHelper.readMemory(getAddress(0x00000000000CF000), 4)
    print("Memory at 0x000000000008C000: {}".format(mem1))
    print("Memory at 0x00000000000CF000: {}".format(mem2))

    print("Emulation starting at 0x{}".format(mainFunctionEntry))
    while monitor.isCancelled() is False:
        
        # Check the current address in the program counter, if it's
        # zero (our `CONTROLLED_RETURN_OFFSET` value) stop emulation.
        # Set this to whatever end target you want.
        executionAddress = emuHelper.getExecutionAddress()  
        if (executionAddress == controlledReturnAddr):
            print("Emulation complete.")
            return

        # Print current instruction and the registers we care about
        print("Address: 0x{} ({})".format(executionAddress, getInstructionAt(executionAddress)))
        for reg in reg_filter:
            reg_value = emuHelper.readRegister(reg)
            print("  {} = {:#018x}".format(reg, reg_value))

        # single step emulation
        success = emuHelper.step(monitor)
        if (success == False):
            lastError = emuHelper.getLastError()
            printerr("Emulation Error: '{}'".format(lastError))
            return

    # Cleanup resources and release hold on currentProgram
    emuHelper.dispose()

# == Invoke main ===========================================================
main()
```

<details>
<summary>Output example</summary>

```
Memory at 0x000000000008C000: array('b', [-52, -69, -86, -103])
Memory at 0x00000000000CF000: array('b', [-103, -86, -69, -52])
Emulation starting at 0x00100690
Address: 0x00100690 (PUSH RBP)
  RIP = 0x0000000000100690
  RAX = 0x0000000000000020
  RBX = 0x0000000000000000
  RCX = 0x0000000000000000
  RDX = 0x0000000000000000
  RSI = 0x0000000000000000
  RDI = 0x0000000000000000
  RSP = 0x000000002fff0000
  RBP = 0x000000002fff0000
  rflags = 0x0000000000000000
Address: 0x00100691 (MOV RBP,RSP)
  RIP = 0x0000000000100691
  RAX = 0x0000000000000020
  RBX = 0x0000000000000000
  RCX = 0x0000000000000000
  RDX = 0x0000000000000000
  RSI = 0x0000000000000000
  RDI = 0x0000000000000000
  RSP = 0x000000002ffefff8
  RBP = 0x000000002fff0000
  rflags = 0x0000000000000000
Address: 0x00100694 (SUB RSP,0x30)
  RIP = 0x0000000000100694
  RAX = 0x0000000000000020
  RBX = 0x0000000000000000
  RCX = 0x0000000000000000
  RDX = 0x0000000000000000
  RSI = 0x0000000000000000
  RDI = 0x0000000000000000
  RSP = 0x000000002ffefff8
  RBP = 0x000000002ffefff8
  rflags = 0x0000000000000000
Address: 0x00100698 (MOV dword ptr [RBP + -0x24],EDI)
  RIP = 0x0000000000100698
  RAX = 0x0000000000000020
  RBX = 0x0000000000000000
  RCX = 0x0000000000000000
  RDX = 0x0000000000000000
  RSI = 0x0000000000000000
  RDI = 0x0000000000000000
  RSP = 0x000000002ffeffc8
  RBP = 0x000000002ffefff8
  rflags = 0x0000000000000000
... snip ...
```
</details>

<br>[⬆ Back to top](#table-of-contents)


### Dumping Raw PCode
PCode exists in two primary forms you as a user should consider, "raw" and "refined".  In documentation both forms are simply referred to as "PCode" making it confusing to talk about - so I distinguish between the forms using raw and refined. Just know theses are not universally accepted terms. 

So raw PCode is the first pass, and the form that's displayed in the "Listing" pane inside the Ghidra UI.  It's extremely verbose and explicit. This is the form you want to use when emulating, if you're writing a symbolic executor, or anything of the sort.  If you want details from the decompiler passes, you want to analyze refined PCode, not this stuff!  So what does it look like and how do you access it? Let's take a look.

```python
def dump_raw_pcode(func):
    func_body = func.getBody()
    listing = currentProgram.getListing()
    opiter = listing.getInstructions(func_body, True)
    while opiter.hasNext():
        op = opiter.next()
        raw_pcode = op.getPcode()
        print("{}".format(op))
        for entry in raw_pcode:
            print("  {}".format(entry))

func = getGlobalFunctions("main")[0]    # assumes only one function named `main`
dump_raw_pcode(func)            	    # dump raw pcode as strings
```

<details>
<summary>Output example</summary>

```
PUSH RBP
  (unique, 0x2510, 8) COPY (register, 0x28, 8)
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8)
   ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (unique, 0x2510, 8)
MOV RBP,RSP
  (register, 0x28, 8) COPY (register, 0x20, 8)
SUB RSP,0x50
  (register, 0x200, 1) INT_LESS (register, 0x20, 8) , (const, 0x50, 8)
  (register, 0x20b, 1) INT_SBORROW (register, 0x20, 8) , (const, 0x50, 8)
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x50, 8)
  (register, 0x207, 1) INT_SLESS (register, 0x20, 8) , (const, 0x0, 8)
  (register, 0x206, 1) INT_EQUAL (register, 0x20, 8) , (const, 0x0, 8)
MOV dword ptr [RBP + -0x44],EDI
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffbc, 8)
  (unique, 0x1fd0, 4) COPY (register, 0x38, 4)
   ---  STORE (const, 0x1b1, 4) , (unique, 0x620, 8) , (unique, 0x1fd0, 4)
MOV qword ptr [RBP + -0x50],RSI
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffb0, 8)
  (unique, 0x1ff0, 8) COPY (register, 0x30, 8)
   ---  STORE (const, 0x1b1, 4) , (unique, 0x620, 8) , (unique, 0x1ff0, 8)
MOV RAX,qword ptr FS:[0x28]
  (unique, 0x9e0, 8) INT_ADD (register, 0x110, 8) , (const, 0x28, 8)
  (unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x9e0, 8)
  (register, 0x0, 8) COPY (unique, 0x1ff0, 8)
MOV qword ptr [RBP + -0x8],RAX
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xfffffffffffffff8, 8)
  (unique, 0x1ff0, 8) COPY (register, 0x0, 8)
   ---  STORE (const, 0x1b1, 4) , (unique, 0x620, 8) , (unique, 0x1ff0, 8)
XOR EAX,EAX
  (register, 0x200, 1) COPY (const, 0x0, 1)
  (register, 0x20b, 1) COPY (const, 0x0, 1)
  (register, 0x0, 4) INT_XOR (register, 0x0, 4) , (register, 0x0, 4)
  (register, 0x0, 8) INT_ZEXT (register, 0x0, 4)
  (register, 0x207, 1) INT_SLESS (register, 0x0, 4) , (const, 0x0, 4)
  (register, 0x206, 1) INT_EQUAL (register, 0x0, 4) , (const, 0x0, 4)
CMP dword ptr [RBP + -0x44],0x1
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffbc, 8)
  (unique, 0x1fe0, 4) LOAD (const, 0x1b1, 4) , (unique, 0x620, 8)
  (register, 0x200, 1) INT_LESS (unique, 0x1fe0, 4) , (const, 0x1, 4)
  (unique, 0x1fe0, 4) LOAD (const, 0x1b1, 4) , (unique, 0x620, 8)
  (register, 0x20b, 1) INT_SBORROW (unique, 0x1fe0, 4) , (const, 0x1, 4)
  (unique, 0x1fe0, 4) LOAD (const, 0x1b1, 4) , (unique, 0x620, 8)
  (unique, 0x5950, 4) INT_SUB (unique, 0x1fe0, 4) , (const, 0x1, 4)
  (register, 0x207, 1) INT_SLESS (unique, 0x5950, 4) , (const, 0x0, 4)
  (register, 0x206, 1) INT_EQUAL (unique, 0x5950, 4) , (const, 0x0, 4)
JG 0x00100743
  (unique, 0x2220, 1) BOOL_NEGATE (register, 0x206, 1)
  (unique, 0x2230, 1) INT_EQUAL (register, 0x20b, 1) , (register, 0x207, 1)
  (unique, 0x2250, 1) BOOL_AND (unique, 0x2220, 1) , (unique, 0x2230, 1)
   ---  CBRANCH (ram, 0x100743, 8) , (unique, 0x2250, 1)
MOV RAX,qword ptr [RBP + -0x50]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffb0, 8)
  (unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x620, 8)
  (register, 0x0, 8) COPY (unique, 0x1ff0, 8)
MOV RAX,qword ptr [RAX]
  (unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (register, 0x0, 8)
  (register, 0x0, 8) COPY (unique, 0x1ff0, 8)
MOV RSI,RAX
  (register, 0x30, 8) COPY (register, 0x0, 8)
LEA RDI,[0x1008a4]
  (register, 0x38, 8) COPY (const, 0x1008a4, 8)
MOV EAX,0x0
  (register, 0x0, 8) COPY (const, 0x0, 8)
CALL 0x001005d0
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8)
   ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (const, 0x100739, 8)
   ---  CALL (ram, 0x1005d0, 8)
MOV EAX,0x1
  (register, 0x0, 8) COPY (const, 0x1, 8)
JMP 0x001007ff
   ---  BRANCH (ram, 0x1007ff, 8)
MOV RAX,0x4242424241414141
  (register, 0x0, 8) COPY (const, 0x4242424241414141, 8)
MOV qword ptr [RBP + -0x1c],RAX
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffe4, 8)
  (unique, 0x1ff0, 8) COPY (register, 0x0, 8)
   ---  STORE (const, 0x1b1, 4) , (unique, 0x620, 8) , (unique, 0x1ff0, 8)
MOV word ptr [RBP + -0x14],0x43
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffec, 8)
  (unique, 0x1fc0, 2) COPY (const, 0x43, 2)
   ---  STORE (const, 0x1b1, 4) , (unique, 0x620, 8) , (unique, 0x1fc0, 2)
MOV qword ptr [RBP + -0x2c],0x0
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffd4, 8)
  (unique, 0x2000, 8) COPY (const, 0x0, 8)
   ---  STORE (const, 0x1b1, 4) , (unique, 0x620, 8) , (unique, 0x2000, 8)
LEA RDX,[RBP + -0x1c]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffe4, 8)
  (register, 0x10, 8) COPY (unique, 0x620, 8)
LEA RAX,[RBP + -0x2c]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffd4, 8)
  (register, 0x0, 8) COPY (unique, 0x620, 8)
MOV RSI,RDX
  (register, 0x30, 8) COPY (register, 0x10, 8)
MOV RDI,RAX
  (register, 0x38, 8) COPY (register, 0x0, 8)
CALL 0x001005b0
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8)
   ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (const, 0x100772, 8)
   ---  CALL (ram, 0x1005b0, 8)
LEA RAX,[RBP + -0x2c]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffd4, 8)
  (register, 0x0, 8) COPY (unique, 0x620, 8)
MOV RSI,RAX
  (register, 0x30, 8) COPY (register, 0x0, 8)
LEA RDI,[0x1008b6]
  (register, 0x38, 8) COPY (const, 0x1008b6, 8)
MOV EAX,0x0
  (register, 0x0, 8) COPY (const, 0x0, 8)
CALL 0x001005d0
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8)
   ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (const, 0x10078a, 8)
   ---  CALL (ram, 0x1005d0, 8)
MOV qword ptr [RBP + -0x24],0x0
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffdc, 8)
  (unique, 0x2000, 8) COPY (const, 0x0, 8)
   ---  STORE (const, 0x1b1, 4) , (unique, 0x620, 8) , (unique, 0x2000, 8)
MOV RAX,qword ptr [RBP + -0x50]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffb0, 8)
  (unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x620, 8)
  (register, 0x0, 8) COPY (unique, 0x1ff0, 8)
ADD RAX,0x8
  (register, 0x200, 1) INT_CARRY (register, 0x0, 8) , (const, 0x8, 8)
  (register, 0x20b, 1) INT_SCARRY (register, 0x0, 8) , (const, 0x8, 8)
  (register, 0x0, 8) INT_ADD (register, 0x0, 8) , (const, 0x8, 8)
  (register, 0x207, 1) INT_SLESS (register, 0x0, 8) , (const, 0x0, 8)
  (register, 0x206, 1) INT_EQUAL (register, 0x0, 8) , (const, 0x0, 8)
MOV RDX,qword ptr [RAX]
  (unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (register, 0x0, 8)
  (register, 0x10, 8) COPY (unique, 0x1ff0, 8)
LEA RAX,[RBP + -0x24]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffdc, 8)
  (register, 0x0, 8) COPY (unique, 0x620, 8)
MOV RSI,RDX
  (register, 0x30, 8) COPY (register, 0x10, 8)
MOV RDI,RAX
  (register, 0x38, 8) COPY (register, 0x0, 8)
CALL 0x001005b0
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8)
   ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (const, 0x1007ac, 8)
   ---  CALL (ram, 0x1005b0, 8)
LEA RAX,[RBP + -0x24]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffdc, 8)
  (register, 0x0, 8) COPY (unique, 0x620, 8)
MOV RSI,RAX
  (register, 0x30, 8) COPY (register, 0x0, 8)
LEA RDI,[0x1008c2]
  (register, 0x38, 8) COPY (const, 0x1008c2, 8)
MOV EAX,0x0
  (register, 0x0, 8) COPY (const, 0x0, 8)
CALL 0x001005d0
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8)
   ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (const, 0x1007c4, 8)
   ---  CALL (ram, 0x1005d0, 8)
MOV dword ptr [RBP + -0x31],0x39393939
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffcf, 8)
  (unique, 0x1fe0, 4) COPY (const, 0x39393939, 4)
   ---  STORE (const, 0x1b1, 4) , (unique, 0x620, 8) , (unique, 0x1fe0, 4)
MOV byte ptr [RBP + -0x2d],0x0
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffd3, 8)
  (unique, 0x1fa0, 1) COPY (const, 0x0, 1)
   ---  STORE (const, 0x1b1, 4) , (unique, 0x620, 8) , (unique, 0x1fa0, 1)
LEA RDX,[RBP + -0x31]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffcf, 8)
  (register, 0x10, 8) COPY (unique, 0x620, 8)
LEA RAX,[RBP + -0x12]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffee, 8)
  (register, 0x0, 8) COPY (unique, 0x620, 8)
MOV RSI,RDX
  (register, 0x30, 8) COPY (register, 0x10, 8)
MOV RDI,RAX
  (register, 0x38, 8) COPY (register, 0x0, 8)
CALL 0x001005b0
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8)
   ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (const, 0x1007e2, 8)
   ---  CALL (ram, 0x1005b0, 8)
LEA RAX,[RBP + -0x12]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xffffffffffffffee, 8)
  (register, 0x0, 8) COPY (unique, 0x620, 8)
MOV RSI,RAX
  (register, 0x30, 8) COPY (register, 0x0, 8)
LEA RDI,[0x1008cf]
  (register, 0x38, 8) COPY (const, 0x1008cf, 8)
MOV EAX,0x0
  (register, 0x0, 8) COPY (const, 0x0, 8)
CALL 0x001005d0
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8)
   ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (const, 0x1007fa, 8)
   ---  CALL (ram, 0x1005d0, 8)
MOV EAX,0x0
  (register, 0x0, 8) COPY (const, 0x0, 8)
MOV RCX,qword ptr [RBP + -0x8]
  (unique, 0x620, 8) INT_ADD (register, 0x28, 8) , (const, 0xfffffffffffffff8, 8)
  (unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x620, 8)
  (register, 0x8, 8) COPY (unique, 0x1ff0, 8)
XOR RCX,qword ptr FS:[0x28]
  (unique, 0x9e0, 8) INT_ADD (register, 0x110, 8) , (const, 0x28, 8)
  (register, 0x200, 1) COPY (const, 0x0, 1)
  (register, 0x20b, 1) COPY (const, 0x0, 1)
  (unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x9e0, 8)
  (register, 0x8, 8) INT_XOR (register, 0x8, 8) , (unique, 0x1ff0, 8)
  (register, 0x207, 1) INT_SLESS (register, 0x8, 8) , (const, 0x0, 8)
  (register, 0x206, 1) INT_EQUAL (register, 0x8, 8) , (const, 0x0, 8)
JZ 0x00100813
   ---  CBRANCH (ram, 0x100813, 8) , (register, 0x206, 1)
CALL 0x001005c0
  (register, 0x20, 8) INT_SUB (register, 0x20, 8) , (const, 0x8, 8)
   ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (const, 0x100813, 8)
   ---  CALL (ram, 0x1005c0, 8)
LEAVE
  (register, 0x20, 8) COPY (register, 0x28, 8)
  (register, 0x28, 8) LOAD (const, 0x1b1, 8) , (register, 0x20, 8)
  (register, 0x20, 8) INT_ADD (register, 0x20, 8) , (const, 0x8, 8)
RET
  (register, 0x288, 8) LOAD (const, 0x1b1, 8) , (register, 0x20, 8)
  (register, 0x20, 8) INT_ADD (register, 0x20, 8) , (const, 0x8, 8)
   ---  RETURN (register, 0x288, 8)
```
</details>

<br>[⬆ Back to top](#table-of-contents)


### Dumping Refined PCode
PCode exists in two primary forms you as a user should consider, "raw" and "refined".  In documentation both forms are simply referred to as "PCode" making it confusing to talk about - so I distinguish between the forms using raw and refined. Just know theses are not universally accepted terms. 

So refined PCode is heavily processed. It highly relates to the output you see in the decompiler, and if you're interested in making use of the Ghidra decompiler passes, this is the form of PCode you'll want to analyze. There are many interesting aspects of refined PCode we do not cover here, including `unique` values and name spaces. Just know that what might appear to be simple has a lot of analysis backing it and digging into these refined PCode elements are worth your time.

```python
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface

# == helper functions =============================================================================
def get_high_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    # Setting a simplification style will strip useful `indirect` information.
    # Please don't use this unless you know why you're using it.
    #ifc.setSimplificationStyle("normalize") 
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high

def dump_refined_pcode(func, high_func):
    opiter = high_func.getPcodeOps()
    while opiter.hasNext():
        op = opiter.next()
        print("{}".format(op.toString()))
        
# == run examples =================================================================================
func = getGlobalFunctions("main")[0]    # assumes only one function named `main`
hf = get_high_function(func)            # we need a high function from the decompiler
dump_refined_pcode(func, hf)            # dump straight refined pcode as strings
```

<details>
<summary>Output example</summary>

Notice how this looks quite different than the raw PCode.

```
(unique, 0x10000110, 8) INT_ADD (register, 0x110, 8) , (const, 0x28, 8)
(unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x9e0, 8)
(unique, 0x9e0, 8) CAST (unique, 0x10000110, 8)
(unique, 0x2250, 1) INT_SLESS (register, 0x38, 4) , (const, 0x2, 4)
 ---  CBRANCH (ram, 0x100743, 1) , (unique, 0x2250, 1)
(unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (register, 0x30, 8)
 ---  CALL (ram, 0x1005d0, 8) , (unique, 0x100000a8, 8) , (unique, 0x1ff0, 8)
(register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x32, 4)
(stack, 0xffffffffffffffc7, 4) INDIRECT (stack, 0xffffffffffffffc7, 4) , (const, 0x32, 4)
(stack, 0xffffffffffffffcb, 1) INDIRECT (stack, 0xffffffffffffffcb, 1) , (const, 0x32, 4)
(stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x32, 4)
(stack, 0xffffffffffffffd4, 8) INDIRECT (stack, 0xffffffffffffffd4, 8) , (const, 0x32, 4)
(stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x32, 4)
(stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x32, 4)
(stack, 0xfffffffffffffff0, 8) INDIRECT (unique, 0x1ff0, 8) , (const, 0x32, 4)
(unique, 0x100000a8, 8) COPY (const, 0x1008a4, 8)
 ---  BRANCH (ram, 0x1007ff, 1)
(stack, 0xffffffffffffffdc, 8) COPY (const, 0x4242424241414141, 8)
(stack, 0xffffffffffffffe4, 2) COPY (const, 0x43, 2)
(stack, 0xffffffffffffffcc, 8) COPY (const, 0x0, 8)
(unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffdc, 8)
(unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffcc, 8)
 ---  CALL (ram, 0x1005b0, 8) , (unique, 0x10000118, 8) , (unique, 0x10000120, 8)
(register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x5d, 4)
(stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x5d, 4)
(stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x5d, 4)
(stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x5d, 4)
(stack, 0xfffffffffffffff0, 8) INDIRECT (unique, 0x1ff0, 8) , (const, 0x5d, 4)
(unique, 0x10000118, 8) CAST (unique, 0x620, 8)
(unique, 0x10000120, 8) CAST (unique, 0x620, 8)
(unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffcc, 8)
 ---  CALL (ram, 0x1005d0, 8) , (unique, 0x100000b0, 8) , (unique, 0x620, 8)
(register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x65, 4)
(stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x65, 4)
(stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x65, 4)
(stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x65, 4)
(stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x65, 4)
(unique, 0x100000b0, 8) COPY (const, 0x1008b6, 8)
(stack, 0xffffffffffffffd4, 8) COPY (const, 0x0, 8)
(register, 0x0, 8) PTRADD (register, 0x30, 8) , (const, 0x1, 8) , (const, 0x8, 8)
(unique, 0x10000128, 8) LOAD (const, 0x1b1, 4) , (register, 0x0, 8)
(unique, 0x1ff0, 8) CAST (unique, 0x10000128, 8)
(unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffd4, 8)
 ---  CALL (ram, 0x1005b0, 8) , (unique, 0x10000130, 8) , (unique, 0x1ff0, 8)
(register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x79, 4)
(stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x79, 4)
(stack, 0xffffffffffffffd4, 8) INDIRECT (stack, 0xffffffffffffffd4, 8) , (const, 0x79, 4)
(stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x79, 4)
(stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x79, 4)
(stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x79, 4)
(unique, 0x10000130, 8) CAST (unique, 0x620, 8)
(unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffd4, 8)
 ---  CALL (ram, 0x1005d0, 8) , (unique, 0x100000b8, 8) , (unique, 0x620, 8)
(register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x81, 4)
(stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x81, 4)
(stack, 0xffffffffffffffd4, 8) INDIRECT (stack, 0xffffffffffffffd4, 8) , (const, 0x81, 4)
(stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x81, 4)
(stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x81, 4)
(stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x81, 4)
(unique, 0x100000b8, 8) COPY (const, 0x1008c2, 8)
(stack, 0xffffffffffffffc7, 4) COPY (const, 0x39393939, 4)
(stack, 0xffffffffffffffcb, 1) COPY (const, 0x0, 1)
(unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffc7, 8)
(unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffe6, 8)
 ---  CALL (ram, 0x1005b0, 8) , (unique, 0x620, 8) , (unique, 0x10000138, 8)
(register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x90, 4)
(stack, 0xffffffffffffffc7, 4) INDIRECT (stack, 0xffffffffffffffc7, 4) , (const, 0x90, 4)
(stack, 0xffffffffffffffcb, 1) INDIRECT (stack, 0xffffffffffffffcb, 1) , (const, 0x90, 4)
(stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x90, 4)
(stack, 0xffffffffffffffd4, 8) INDIRECT (stack, 0xffffffffffffffd4, 8) , (const, 0x90, 4)
(stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x90, 4)
(stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x90, 4)
(stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x90, 4)
(unique, 0x10000138, 8) CAST (unique, 0x620, 8)
(unique, 0x620, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffffe6, 8)
 ---  CALL (ram, 0x1005d0, 8) , (unique, 0x100000c0, 8) , (unique, 0x620, 8)
(register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x98, 4)
(stack, 0xffffffffffffffc7, 4) INDIRECT (stack, 0xffffffffffffffc7, 4) , (const, 0x98, 4)
(stack, 0xffffffffffffffcb, 1) INDIRECT (stack, 0xffffffffffffffcb, 1) , (const, 0x98, 4)
(stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x98, 4)
(stack, 0xffffffffffffffd4, 8) INDIRECT (stack, 0xffffffffffffffd4, 8) , (const, 0x98, 4)
(stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x98, 4)
(stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x98, 4)
(stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x98, 4)
(unique, 0x100000c0, 8) COPY (const, 0x1008cf, 8)
(register, 0x0, 8) INT_ZEXT (unique, 0x1000009c, 1)
(register, 0x110, 8) MULTIEQUAL (register, 0x110, 8) , (register, 0x110, 8)
(unique, 0x1000009c, 1) INT_SLESS (register, 0x38, 4) , (const, 0x2, 4)
(stack, 0xffffffffffffffc7, 4) MULTIEQUAL (stack, 0xffffffffffffffc7, 4) , (stack, 0xffffffffffffffc7, 4)
(stack, 0xffffffffffffffcb, 1) MULTIEQUAL (stack, 0xffffffffffffffcb, 1) , (stack, 0xffffffffffffffcb, 1)
(stack, 0xffffffffffffffcc, 8) MULTIEQUAL (stack, 0xffffffffffffffcc, 8) , (stack, 0xffffffffffffffcc, 8)
(stack, 0xffffffffffffffd4, 8) MULTIEQUAL (stack, 0xffffffffffffffd4, 8) , (stack, 0xffffffffffffffd4, 8)
(stack, 0xffffffffffffffdc, 8) MULTIEQUAL (stack, 0xffffffffffffffdc, 8) , (stack, 0xffffffffffffffdc, 8)
(stack, 0xffffffffffffffe4, 2) MULTIEQUAL (stack, 0xffffffffffffffe4, 2) , (stack, 0xffffffffffffffe4, 2)
(stack, 0xfffffffffffffff0, 8) MULTIEQUAL (stack, 0xfffffffffffffff0, 8) , (stack, 0xfffffffffffffff0, 8)
(unique, 0x10000140, 8) INT_ADD (register, 0x110, 8) , (const, 0x28, 8)
(unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x9e0, 8)
(register, 0x206, 1) INT_NOTEQUAL (stack, 0xfffffffffffffff0, 8) , (unique, 0x1ff0, 8)
(unique, 0x9e0, 8) CAST (unique, 0x10000140, 8)
 ---  CBRANCH (ram, 0x100813, 1) , (register, 0x206, 1)
 ---  CALL (ram, 0x1005c0, 8)
 ---  RETURN (const, 0x1, 4)
(stack, 0xffffffffffffffc7, 4) INDIRECT (stack, 0xffffffffffffffc7, 4) , (const, 0x42, 4)
(stack, 0xffffffffffffffcb, 1) INDIRECT (stack, 0xffffffffffffffcb, 1) , (const, 0x42, 4)
(stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x42, 4)
(stack, 0xffffffffffffffd4, 8) INDIRECT (stack, 0xffffffffffffffd4, 8) , (const, 0x42, 4)
(stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x42, 4)
(stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x42, 4)
(stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x42, 4)
 ---  RETURN (const, 0x0, 8) , (register, 0x0, 8)
```
</details>

<br>[⬆ Back to top](#table-of-contents)


### Plotting a Function AST
Ghidra does not define a default graph provider, so you cannot graph abstract synatax trees out of the box.  Here's a snippet that takes elements from Ghidra's Graph Java snippets and hacks them together to get an SVG version of a function's AST.  This requires you to have `GraphViz` installed with the `dot` binary in your `PATH`, and `networkx` and `pydot` accessible from the Ghidra Jython console.  Basically, I just copy my Python2 site-packages over to my ghidra_scripts directory and everything works.  Keep in mind that if your Python module uses a natively compiled element (like Matplot lib does), you won't be able to use it in Jython. If you know of a way, please let me know.

```python
import networkx as nx
import pydot

from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.pcode import PcodeOp

def buildAST(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    ifc.setSimplificationStyle("normalize")
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high

def buildGraph(graph, func, high):
    vertices = {}
    opiter = getPcodeOpIterator(high)
    while opiter.hasNext():
        op = opiter.next()
        vert = createOpVertex(func, op)
        graph.add_node(vert)
        for i in range(0, op.getNumInputs()):
            opcode = op.getOpcode()
            if (i == 0 and (opcode == PcodeOp.LOAD or opcode == PcodeOp.STORE)):
                continue
            if (i == 1 and opcode == PcodeOp.INDIRECT):
                continue
            vn = op.getInput(i)
            if (vn != None):
                v = getVarnodeVertex(graph, vertices, vn)
                graph.add_edge(v, vert)

        outvn = op.getOutput()
        if (outvn != None):
            outv = getVarnodeVertex(graph, vertices, outvn)
            if (outv != None):
                graph.add_edge(vert, outv)

def createOpVertex(func, op):
    name = op.getMnemonic()
    id = getOpKey(op)
    opcode = op.getOpcode()
    if ((opcode == PcodeOp.LOAD) or (opcode == PcodeOp.STORE)):
        vn = op.getInput(0)
        addrspace = currentProgram.getAddressFactory().getAddressSpace(vn.getOffset())
        name += ' ' + addrspace.getName()
    elif (opcode == PcodeOp.INDIRECT):
        vn = op.getInput(1)
        if (vn != None):
            indOp = high.getOpRef(vn.getOffset())
            if (indOp != None):
                name += " (" + indOp.getMnemonic() + ")"
    return "{}_{}".format(name, id)

def createVarnodeVertex(graph, vn):
    name = str(vn.getAddress())
    id = getVarnodeKey(vn)
    if (vn.isRegister()):
        reg = currentProgram.getRegister(vn.getAddress(), vn.getSize())
        if (reg != None):
            name = reg.getName()
    return "{}_{}".format(name, id)

def getVarnodeVertex(graph, vertices, vn):
    res = None
    try:
        res = vertices[str(vn.getUniqueId())]
    except KeyError:
        res = None
    if (res == None):
        res = createVarnodeVertex(graph, vn)
        vertices[str(vn.getUniqueId())] = res
    return res

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def getOpKey(op):
    sq = op.getSeqnum()
    id = str(sq.getTarget()) + " o " + str(op.getSeqnum().getTime())
    return id

def getPcodeOpIterator(high):
    return high.getPcodeOps()

def getVarnodeKey(vn):
    op = vn.getDef()
    id = ""
    if (op != None):
        id = str(op.getSeqnum().getTarget()) + " v " + str(vn.getUniqueId())
    else:
        id = "i v " + str(vn.getUniqueId())
    return id

def main():
    graph = nx.DiGraph()
    listing = currentProgram.getListing()
    func = getFunctionContaining(getAddress(0x00100690))
    high = buildAST(func)
    buildGraph(graph, func, high)

    dot_data = nx.nx_pydot.to_pydot(graph)
    svg = pydot.graph_from_dot_data(dot_data.to_string())[0].create_svg()
    svg_path = "C:\\Users\\username\\Desktop\\test.svg"
    f = open(svg_path, 'w')
    f.write(svg)
    f.close()

    print("Wrote pydot SVG of graph to: {}\nNodes: {}, Edges: {}".format(svg_path, len(graph.nodes), len(graph.edges)))

main()
```

<details>
<summary>Output example</summary>

```
# also writes a file called 'test.svg' to the Windows Desktop for user 'username'.
Wrote pydot SVG of graph to: C:\Users\username\Desktop\test.svg
Nodes: 47, Edges: 48
```
</details>


## Working with Graphs

### Creating a Call Graph
Ghidra's complex API allows for the creation of various graph structures including directional graphs (digraphs). This example shows how to create a DiGraph of vertices (functions) and edges (calls from/to). 

Note that adding a vertex or an edge between two vertex entries does not reuse or override them! This is because, while many nodes share the same name, they contain unique hash codes (keys). If you were looking to trim this graph to include only unqiue nodes, you would need to consider both the name of the symbol and its address to account for overridden functions. 

In its current form, this DiGraph is unlikely to be of any use to you. But the building blocks of creating interesting control flow graphs (CFG), program dependence graphs (PDG), data dependency graphs (DDG), and other graphs are all here.

```python
from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

digraph = DirectedGraph()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

funcs = fm.getFunctions(True) # True mean iterate forward
for func in funcs: 
	# Add function vertices
	print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint())) # FunctionDB
	digraph.add(Vertex(func))
	
	# Add edges for static calls
	entryPoint = func.getEntryPoint()
	instructions = listing.getInstructions(entryPoint, True)
	for instruction in instructions:
		addr = instruction.getAddress()
		oper = instruction.getMnemonicString()
		if oper == "CALL":
			print("    0x{} : {}".format(addr, instruction))
			flows = instruction.getFlows()
			if len(flows) == 1:
				target_addr = "0x{}".format(flows[0])
				digraph.add(Edge(Vertex(func), Vertex(fm.getFunctionAt(getAddress(target_addr)))))

print("DiGraph info:")
edges = digraph.edgeIterator()
while edges.hasNext():
	edge = edges.next()
	from_vertex = edge.from()
	to_vertex = edge.to()
	print("  Edge from {} to {}".format(from_vertex, to_vertex))

vertices = digraph.vertexIterator()
while vertices.hasNext():
	vertex = vertices.next()
	print("  Vertex: {} (key: {})".format(vertex, vertex.key()))
    # some extra stuff you might want to see
	#print("    type(vertex):      {}".format(type(vertex)))
	#print("    vertex.hashCode(): {}".format(vertex.hashCode()))
	#print("    vertex.referent(): {}".format(vertex.referent()))
	#print("    type(referent):    {}".format(type(vertex.referent())))
```

<details>
<summary>Output example</summary>

```
Function: main @ 0x0010064a
    0x00100691 : CALL 0x00100520
    0x001006cc : CALL 0x001004f0
    0x001006e9 : CALL qword ptr [R12 + RBX*0x8]
<...snip...>

DiGraph info:
  Edge from _init to __gmon_start__
  Edge from _init to __libc_start_main
  Edge from _init to __cxa_finalize
  Edge from _init to deregister_tm_clones
  Edge from _init to printf
  Edge from _init to _init
  Edge from printf to __libc_start_main
  Edge from printf to __cxa_finalize
  <...snip...>
  Vertex: _init (key: 3690)
  Vertex: main (key: 3803)
  Vertex: main (key: 3804)
  Vertex: printf (key: 3805)
  Vertex: main (key: 3807)
  Vertex: _init (key: 3808)
  Vertex: __libc_csu_init (key: 3810)
  Vertex: _init (key: 3812)
  Vertex: __libc_csu_fini (key: 3814)
  <...snip...>
```
</details>

<br>[⬆ Back to top](#table-of-contents)


## Miscellaneous

### Program Slices
Given a specific varnode, Ghidra is able to generate backward and forward program slices. This functionality is contained in the `DecompilerUtils` class as four functions; `getBackwardSlice`, `getForwardSlice`, `getForwardSliceToPCodeOps`, and `getBackwardSliceToPCodeOps`.

You can read more about program slicing online, but the idea is to focus on a specific varnode (say a variable) and slice away anything unrelated to it so you're left with a slice of program related to the element you're interested in. In the Ghidra UI you can right-click a variable and select a program slice option and Ghidra will highlight the slice.  If you right-click and don't see an option, you're not clicking on a compatable varnode / element, try something else.

```python
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.app.decompiler.component import DecompilerUtils

# == helper functions =============================================================================
def get_high_function(func):
    options = DecompileOptions()
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(getCurrentProgram())
    res = ifc.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high

# == run examples =================================================================================
func = getGlobalFunctions("main")[0]
hf = get_high_function(func)
lsm = hf.getLocalSymbolMap()
symbols = lsm.getSymbols()

for symbol in symbols:
    print("\nSymbol name: {}".format(symbol.getName()))
    hv = symbol.getHighVariable()
    # Try this snippet with `hv.getInstances()` to enumerate slices for all instances!
    varnode = hv.getRepresentative()
    print("Varnode: {}".format(varnode))
    fs = DecompilerUtils.getForwardSlice(varnode)
    print("Forward Slice: {}".format(fs))
    bs = DecompilerUtils.getBackwardSlice(varnode)
    print("Backward Slice: {}".format(bs))
    bswo = DecompilerUtils.getBackwardSliceToPCodeOps(varnode)
    print("Backward Slice w/ PCode Ops: {}".format(bswo))
    fswo = DecompilerUtils.getForwardSliceToPCodeOps(varnode)
    print("Forward Slice w/ PCode Ops: {}".format(fswo))
```

<details>
<summary>Output examples</summary>

You might think these slices are returning arrays (Python lists) with the name varnodes duplacted over and over - but that's not the case. Each use has a unique ID that ties it to other operations and uses. The printed varnodes may look the same, but these are all unique instances with more data under the hood. Experiment a bit and you'll see what I mean.

```
Symbol name: local_1c
Varnode: (stack, 0xffffffffffffffe4, 2)
Forward Slice: [(stack, 0xffffffffffffffe4, 2), (stack, 0xffffffffffffffe4, 2), (stack, 0xffffffffffffffe4, 2), (stack, 0xffffffffffffffe4, 2)]
Backward Slice: [(stack, 0xffffffffffffffe4, 2)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: [(stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x32, 4), (stack, 0xffffffffffffffe4, 2) MULTIEQUAL (stack, 0xffffffffffffffe4, 2) , (stack, 0xffffffffffffffe4, 2), (stack, 0xffffffffffffffe4, 2) INDIRECT (stack, 0xffffffffffffffe4, 2) , (const, 0x42, 4)]

Symbol name: local_24
Varnode: (stack, 0xffffffffffffffdc, 8)
Forward Slice: [(stack, 0xffffffffffffffdc, 8), (stack, 0xffffffffffffffdc, 8), (stack, 0xffffffffffffffdc, 8), (stack, 0xffffffffffffffdc, 8)]
Backward Slice: [(stack, 0xffffffffffffffdc, 8)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: [(stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x32, 4), (stack, 0xffffffffffffffdc, 8) MULTIEQUAL (stack, 0xffffffffffffffdc, 8) , (stack, 0xffffffffffffffdc, 8), (stack, 0xffffffffffffffdc, 8) INDIRECT (stack, 0xffffffffffffffdc, 8) , (const, 0x42, 4)]

Symbol name: local_35
Varnode: (stack, 0xffffffffffffffcb, 1)
Forward Slice: [(stack, 0xffffffffffffffcb, 1), (stack, 0xffffffffffffffcb, 1), (stack, 0xffffffffffffffcb, 1), (stack, 0xffffffffffffffcb, 1)]
Backward Slice: [(stack, 0xffffffffffffffcb, 1)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: [(stack, 0xffffffffffffffcb, 1) INDIRECT (stack, 0xffffffffffffffcb, 1) , (const, 0x42, 4), (stack, 0xffffffffffffffcb, 1) INDIRECT (stack, 0xffffffffffffffcb, 1) , (const, 0x32, 4), (stack, 0xffffffffffffffcb, 1) MULTIEQUAL (stack, 0xffffffffffffffcb, 1) , (stack, 0xffffffffffffffcb, 1)]

Symbol name: param_1
Varnode: (register, 0x38, 4)
Forward Slice: [(register, 0x38, 4), (unique, 0x2250, 1), (register, 0x0, 8), (unique, 0x1000009c, 1)]
Backward Slice: [(register, 0x38, 4)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: [(unique, 0x2250, 1) INT_SLESS (register, 0x38, 4) , (const, 0x2, 4), (register, 0x0, 8) INT_ZEXT (unique, 0x1000009c, 1), (unique, 0x1000009c, 1) INT_SLESS (register, 0x38, 4) , (const, 0x2, 4),  ---  CBRANCH (ram, 0x100743, 1) , (unique, 0x2250, 1),  ---  RETURN (const, 0x0, 8) , (register, 0x0, 8)]

Symbol name: param_2
Varnode: (register, 0x30, 8)
Forward Slice: [(register, 0x30, 8), (unique, 0x1ff0, 8), (unique, 0x1ff0, 8), (unique, 0x10000128, 8), (register, 0x0, 8)]
Backward Slice: [(register, 0x30, 8)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: [(unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (register, 0x30, 8), (unique, 0x10000128, 8) LOAD (const, 0x1b1, 4) , (register, 0x0, 8),  ---  CALL (ram, 0x1005d0, 8) , (unique, 0x100000a8, 8) , (unique, 0x1ff0, 8), (register, 0x0, 8) PTRADD (register, 0x30, 8) , (const, 0x1, 8) , (const, 0x8, 8), (unique, 0x1ff0, 8) CAST (unique, 0x10000128, 8),  ---  CALL (ram, 0x1005b0, 8) , (unique, 0x10000130, 8) , (unique, 0x1ff0, 8)]

Symbol name: in_FS_OFFSET
Varnode: (register, 0x110, 8)
Forward Slice: [(stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (unique, 0x9e0, 8), (stack, 0xfffffffffffffff0, 8), (unique, 0x1ff0, 8), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (register, 0x110, 8), (register, 0x110, 8), (register, 0x206, 1), (register, 0x110, 8), (register, 0x110, 8), (unique, 0x9e0, 8), (register, 0x110, 8), (unique, 0x1ff0, 8), (register, 0x110, 8), (register, 0x110, 8), (register, 0x110, 8), (unique, 0x10000110, 8), (register, 0x110, 8), (unique, 0x10000140, 8)]
Backward Slice: [(register, 0x110, 8)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: [(unique, 0x10000140, 8) INT_ADD (register, 0x110, 8) , (const, 0x28, 8), (register, 0x206, 1) INT_NOTEQUAL (stack, 0xfffffffffffffff0, 8) , (unique, 0x1ff0, 8), (stack, 0xfffffffffffffff0, 8) INDIRECT (unique, 0x1ff0, 8) , (const, 0x5d, 4), (unique, 0x9e0, 8) CAST (unique, 0x10000110, 8), (unique, 0x9e0, 8) CAST (unique, 0x10000140, 8), (unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x9e0, 8), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x79, 4), (register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x5d, 4), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x65, 4), (stack, 0xfffffffffffffff0, 8) MULTIEQUAL (stack, 0xfffffffffffffff0, 8) , (stack, 0xfffffffffffffff0, 8), (unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x9e0, 8), (register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x79, 4), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x81, 4), (register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x90, 4), (stack, 0xfffffffffffffff0, 8) INDIRECT (unique, 0x1ff0, 8) , (const, 0x32, 4), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x98, 4),  ---  CBRANCH (ram, 0x100813, 1) , (register, 0x206, 1), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x42, 4), (unique, 0x10000110, 8) INT_ADD (register, 0x110, 8) , (const, 0x28, 8), (register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x32, 4), (register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x98, 4), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x90, 4), (register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x65, 4), (register, 0x110, 8) MULTIEQUAL (register, 0x110, 8) , (register, 0x110, 8), (register, 0x110, 8) INDIRECT (register, 0x110, 8) , (const, 0x81, 4)]

Symbol name: local_10
Varnode: (stack, 0xfffffffffffffff0, 8)
Forward Slice: [(stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (register, 0x206, 1), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8), (stack, 0xfffffffffffffff0, 8)]
Backward Slice: [(stack, 0xfffffffffffffff0, 8), (const, 0x5d, 4), (register, 0x110, 8), (unique, 0x10000110, 8), (unique, 0x9e0, 8), (const, 0x1b1, 4), (const, 0x28, 8), (unique, 0x1ff0, 8)]
Backward Slice w/ PCode Ops: [(unique, 0x1ff0, 8) LOAD (const, 0x1b1, 4) , (unique, 0x9e0, 8), (unique, 0x10000110, 8) INT_ADD (register, 0x110, 8) , (const, 0x28, 8), (stack, 0xfffffffffffffff0, 8) INDIRECT (unique, 0x1ff0, 8) , (const, 0x5d, 4), (unique, 0x9e0, 8) CAST (unique, 0x10000110, 8)]
Forward Slice w/ PCode Ops: [(stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x65, 4), (stack, 0xfffffffffffffff0, 8) MULTIEQUAL (stack, 0xfffffffffffffff0, 8) , (stack, 0xfffffffffffffff0, 8), (register, 0x206, 1) INT_NOTEQUAL (stack, 0xfffffffffffffff0, 8) , (unique, 0x1ff0, 8), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x42, 4), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x81, 4), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x90, 4), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x98, 4), (stack, 0xfffffffffffffff0, 8) INDIRECT (stack, 0xfffffffffffffff0, 8) , (const, 0x79, 4),  ---  CBRANCH (ram, 0x100813, 1) , (register, 0x206, 1)]

Symbol name: local_1a
Varnode: (stack, 0xffffffffffffffe6, 10)
Forward Slice: [(stack, 0xffffffffffffffe6, 10)]
Backward Slice: [(stack, 0xffffffffffffffe6, 10)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: []

Symbol name: local_34
Varnode: (stack, 0xffffffffffffffcc, 8)
Forward Slice: [(stack, 0xffffffffffffffcc, 8), (stack, 0xffffffffffffffcc, 8), (stack, 0xffffffffffffffcc, 8), (stack, 0xffffffffffffffcc, 8)]
Backward Slice: [(stack, 0xffffffffffffffcc, 8)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: [(stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x32, 4), (stack, 0xffffffffffffffcc, 8) MULTIEQUAL (stack, 0xffffffffffffffcc, 8) , (stack, 0xffffffffffffffcc, 8), (stack, 0xffffffffffffffcc, 8) INDIRECT (stack, 0xffffffffffffffcc, 8) , (const, 0x42, 4)]

Symbol name: local_2c
Varnode: (stack, 0xffffffffffffffd4, 8)
Forward Slice: [(stack, 0xffffffffffffffd4, 8), (stack, 0xffffffffffffffd4, 8), (stack, 0xffffffffffffffd4, 8), (stack, 0xffffffffffffffd4, 8)]
Backward Slice: [(stack, 0xffffffffffffffd4, 8)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: [(stack, 0xffffffffffffffd4, 8) INDIRECT (stack, 0xffffffffffffffd4, 8) , (const, 0x32, 4), (stack, 0xffffffffffffffd4, 8) MULTIEQUAL (stack, 0xffffffffffffffd4, 8) , (stack, 0xffffffffffffffd4, 8), (stack, 0xffffffffffffffd4, 8) INDIRECT (stack, 0xffffffffffffffd4, 8) , (const, 0x42, 4)]

Symbol name: local_39
Varnode: (stack, 0xffffffffffffffc7, 4)
Forward Slice: [(stack, 0xffffffffffffffc7, 4), (stack, 0xffffffffffffffc7, 4), (stack, 0xffffffffffffffc7, 4), (stack, 0xffffffffffffffc7, 4)]
Backward Slice: [(stack, 0xffffffffffffffc7, 4)]
Backward Slice w/ PCode Ops: []
Forward Slice w/ PCode Ops: [(stack, 0xffffffffffffffc7, 4) INDIRECT (stack, 0xffffffffffffffc7, 4) , (const, 0x32, 4), (stack, 0xffffffffffffffc7, 4) MULTIEQUAL (stack, 0xffffffffffffffc7, 4) , (stack, 0xffffffffffffffc7, 4), (stack, 0xffffffffffffffc7, 4) INDIRECT (stack, 0xffffffffffffffc7, 4) , (const, 0x42, 4)]
```
</details>

<br>[⬆ Back to top](#table-of-contents)


[0]: https://ghidra-sre.org/
[1]: https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
[2]: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
[3]: https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html
[4]: https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html
[5]: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html
[6]: https://ghidra.re/ghidra_docs/api/ghidra/program/database/ProgramDB.html

