# Ghidra Snippets
*Ghidra Snippets* is a collection of Python examples showing how to work with [Ghidra](https://ghidra-sre.org/) APIs. There are two primary APIs coverted here, the [Flat Program API][1] and the [Flat Decompiler API][2]. The Flat APIs are 'simple' versions of the full fledged Ghidra API. They are a great starting point for anyone looking to develop Ghidra modules and/or scripts.

# Latest Release
**Ghidra v9.1** released 23 October 2019. [Download here][0].

# Classes References
* [GhidraProject][4]
* [Project][3]
* [Program][5]
* [ProgramDB][6]

## Table of Contents

<details>
<summary>Working with Projects</summary>

* [`Get the name and location on disk of the current project`](#get-the-name-and-location-on-disk-of-the-current-project)
* [`List all programs in the current project`](#list-all-programs-in-the-current-project)

</details>

<details>
<summary>Working with Programs</summary>

* ...

</details>

<details>
<summary>Working with Functions</summary>

* ...

</details>

<details>
<summary>Working with Instructions</summary>

* ...

</details>

<details>
<summary>Working with Basic Blocks</summary>

* ...

</details>

<details>
<summary>Working with User Input</summary>

* ...

</details>

<details>
<summary>Working with the Decompiler</summary>

* ...

</details>

<details>
<summary>Emulating PCode</summary>

* ...

</details>

# Working with Projects
A Ghidra *Project* (class [GhidraProject][4]) contains a logical set of program binaries related to a reverse engineering effort. Projects can be shared (collaborative) or non-shared (private). The snippets in this section deal with bulk import and analysis, locating project files on disk, and more.

### Get the name and location on disk of the current project
```python
# getState() is available without imports
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
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

### Load a new program in the current project
```python
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

### Remove an program from the current project
```python
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

### Selecting a program to work with
```python
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

# Working with Programs
A *Program* is a binary component within a Ghidra Project. The snippets in this section deal with gathering information about the Programs within a Project.

<br>[⬆ Back to top](#table-of-contents)

### List the current program's name and location on disk
```python
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

### Reanalyze the current program
```python
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

# Working with Functions
A *Function* is a subroutine within an Program. The snippets in this section deal with gathering information about Functions and modifying them within an Program.

### Enumerate all functions printing their name and address
```python
# Print name and address of all functions in the loaded binary
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
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

### Get a function's address by name
```python
func_name = "main"
listing = currentProgram.getListing()
func = listing.getGlobalFunctions(func_name)
if len(func) > 0:
	func = func[0]
else:
	print("No function named '{}' found.".format(func_name))
	exit()
print("{} is located at 0x{}".format(func_name, func.getEntryPoint()))
```

<details>
<summary>Output example</summary>

```
main is located at 0x00100690
```
</details>

<br>[⬆ Back to top](#table-of-contents)

# Working with Instructions
A blurb here about this section and working with Instructions...

### Get a function's address by name
```python
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

# Working with Basic Blocks
Basic Blocks are collections of continuous non-branching instructions within Functions. They are joined by conditional and non-conditional branches, revealing valuable information about a program and function's code flow. This section deals with examples working with Basic Block models.

### Get a basic block model for a program
```python
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

# Working with User Input
A blurb here about this section and working with user input...

### Ask the user to select a function and jump to it
```python
# code here...
```

<br>[⬆ Back to top](#table-of-contents)

# Working with the Decompiler
A blurb here about this section and working with the decompiler and P-Code...

### Print decompiled code for each function in the current program
```python
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

program = getCurrentProgram()
ifc = DecompInterface()
ifc.openProgram(program)
functions = program.getFunctionManager().getFunctions(True)

ifc.toggleSyntaxTree(True) 			# Produce syntax trees 
ifc.toggleCCode(True)				# Produce C code

for function in list(functions):
    print("Function name: {}".format(function.getName()))
    res = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())
    print(res.getDecompiledFunction().getC())
    break

hf = res.getHighFunction()
print(hf)
```

<br>[⬆ Back to top](#table-of-contents)

# Emulating PCode

### Emulating PCode without hooking functions
```python
#Simple PCode emulator
#@author 
#@category Examples.Emulation
#@keybinding
#@menupath
#@toolbar

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

    # Obtain entry instruction in order to establish initial processor context
    entryInstr = getInstructionAt(mainFunctionEntry)

    # Establish emulation helper
    emuHelper = EmulatorHelper(currentProgram)

    # Set controlled return location so we can identify return from emulated function
    controlledReturnAddr = getAddress(CONTROLLED_RETURN_OFFSET)

    # Set initial RIP
    mainFunctionEntryLong = int("0x{}".format(mainFunctionEntry), 16)
    emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntryLong)

    registers = getProgramRegisterList(currentProgram)

    print("Emulation starting at 0x{}".format(mainFunctionEntry))
    while monitor.isCancelled() is False:
        
        executionAddress = emuHelper.getExecutionAddress()  
        if (executionAddress == controlledReturnAddr):
            print("Emulation complete.")
            return

        print("Address: 0x{}".format(executionAddress))
        for reg in registers:
            if str(reg).startswith('R') and len(str(reg)) == 3 and str(reg) != 'RIP':
                reg_value = emuHelper.readRegister(reg)
                if reg_value != 0:
                    print("  {} = {:#018x}".format(reg, reg_value))

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

<br>[⬆ Back to top](#table-of-contents)

### Emulating PCode with functions hooks
```python
# code here...
```

<br>[⬆ Back to top](#table-of-contents)


[0]: https://ghidra-sre.org/
[1]: https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html
[2]: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/flatapi/FlatDecompilerAPI.html
[3]: https://ghidra.re/ghidra_docs/api/ghidra/framework/model/Project.html
[4]: https://ghidra.re/ghidra_docs/api/ghidra/base/project/GhidraProject.html
[5]: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html
[6]: https://ghidra.re/ghidra_docs/api/ghidra/program/database/ProgramDB.html
