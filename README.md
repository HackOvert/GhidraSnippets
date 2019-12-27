# Ghidra Snippets
*Ghidra Snippets* is a collection of Python examples showing how to work with [Ghidra](https://ghidra-sre.org/) APIs. There are two primary APIs coverted here, the [Flat Program API][1] and the [Flat Decompiler API][2]. The Flat APIs are 'simple' versions of the full fledged Ghidra API. They are a great starting point for anyone looking to develop Ghidra modules and/or scripts.

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

* [`List the current program's name and location on disk`](#list-the-current-program's-name-and-location-on-disk)

</details>

<details>
<summary>Working with Functions</summary>

* [`Enumerate all functions printing their name and address`](#enumerate-all-functions-printing-their-name-and-address)
* [`Get a function's name by address`](#get-a-function's-name-by-address)
* [`Get a function's address by name`](#get-a-function's-address-by-name)

</details>

<details>
<summary>Working with Instructions</summary>

* [`Print all instructions in a select function`](#print-all-instructions-in-a-select-function)

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
<summary>Emulating PCode</summary>

* [`Emulating a function`](#emulating-a-function)

</details>

## Working with Projects
A Ghidra *Project* (class [GhidraProject][4]) contains a logical set of program binaries related to a reverse engineering effort. Projects can be shared (collaborative) or non-shared (private). The snippets in this section deal with bulk import and analysis, locating project files on disk, and more.

### Get the name and location on disk of the current project
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

### List the current program's name and location on disk
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


## Working with Functions
A *Function* is a subroutine within an Program. The snippets in this section deal with gathering information about Functions and modifying them within an Program.

### Enumerate all functions printing their name and address
```python
func = getFirstFunction()
while func is not None:
    print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
    func = getFunctionAfter(func)
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

### Get a function's name by address
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

### Get a function's address by name
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

## Emulating PCode

### Emulating a function
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


[0]: https://ghidra-sre.org/
[1]: https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
[2]: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
[3]: https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html
[4]: https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html
[5]: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html
[6]: https://ghidra.re/ghidra_docs/api/ghidra/program/database/ProgramDB.html

