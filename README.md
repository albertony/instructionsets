# InstructionSets

Command line utility to list instruction sets (semantic groups of instructions),
or instructions, used by an executable file. Can optionally mark if the current
CPU supports the corresponding feature.

**Note that this project is created for Windows operating system and x86 architecture CPUs (Intel or AMD)!**

The utility includes the following components:
* Disassembler
* CPU feature detection
* PE file parser

## Usage

Usage:

```
InstructionSets[32|64][d].exe -help|-h|-?
    Show this help text.
InstructionSets[32|64][d].exe [-supported|-s]|[-unsupported|-u]
    Check features, instruction sets, supported by the current CPU.
    supported:    Only list instruction sets.
    unsupported:  Only list unsupported sets.
InstructionSets[32|64][d].exe filename [-cpu|-c] [-supported|-s]|[-unsupported|-u]
    Disassemble executable file and list names of unique instruction sets.
    filename:     Name of executable file, optionally with absolute or
                  relative path.
    cpu:          Verify if the identified instruction sets are supported
                  by the CPU on the current machine.
    supported:    List supported instruction sets only (implied -cpu).
    unsupported:  List only instruction sets not supported (implied -cpu).
InstructionSets[32|64][d].exe filename -instructions|-i [-groups|-g] [-verbose|-v]
    Disassemble executable file and list all instructions.
    instructions: List name of all instructions.
    groups:       Show instruction sets each instruction is member of.
    verbose:      Show address and operands, in addition to the
                  instruction name.
```

Sample usage:

```
InstructionSets[32|64][d].exe
    List all instruction sets and if the current CPU supports them.
InstructionSets[32|64][d].exe -supported
    Plain list with names of the instruction sets supported by the CPU.
InstructionSets[32|64][d].exe somefile.dll
    Report all instruction sets for specified file.
InstructionSets[32|64][d].exe somefile.dll -c
    Report all instruction sets for specified file, and warn about any
    unsupported.
InstructionSets[32|64][d].exe somefile.dll -c -u
    List any unsupported instruction sets for the specified file on the
    current machine.
InstructionSets[32|64][d].exe somefile.dll -i -g
    List all instructions and their instruction groups from the
    specified file.
InstructionSets[32|64][d].exe somefile.dll -i -g -v
    List all instructions, with address and operands, and their
    instruction sets (groups), from the specified file.
```

## Alternatives

The Microsoft COFF Binary File Dumper (DUMPBIN.EXE) utility, included with Visual Studio,
can also be used to list instructions in an executable, as well as other information.

What it does not do, is to classify the instructions into instruction sets, which is
a key for matching it against supported CPU features.

Example of a powershell expression that uses dumpbin to list name of all instructions
(`-Pattern '.{39}...` assumes 64-bit executable, for 32-bit executable change to
`-Pattern '.{29}`):

```
&"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.38.33130\bin\Hostx64\x64\dumpbin.exe" /NOLOGO /DISASM mylibrary.dll | Select-Object -Skip 5 | Select-String -Pattern '.{39}(?<instruction>\b.+?\b)' | % { $_.Matches[0].Groups["instruction"].Value.Trim() } | ? { ![string]::IsNullOrEmpty($_) }
```

See:
* https://docs.microsoft.com/en-us/cpp/build/reference/dumpbin-reference

## Disassembler component

The most important part of this utility is the disassembler. It is not written by me,
but taken from the [Capstone disassembly/disassembler framework](https://github.com/aquynh/capstone)
created by by [Nguyen Anh Quynh](https://github.com/aquynh), developed and maintained by a small community.
It is a disassembly framework with the target of becoming the ultimate disasm engine for
binary analysis and reversing in the security community.

I'm including only parts of the source code necessary for my use case. Here is what I do:
* Download latest version of source code from https://github.com/aquynh/capstone.
* Extract source files (\*.h;\*.c) and LICENSE.TXT from root folder.
* Extract folders "arch/X86" and "include/capstone".
* Extract project file msvc\capstone_static\capstone_static.vcxproj into root folder.
* Edit file cs.c: Comment out includes of all "arch/" except "arch/X86/X86Module.h".
* Edit project file capstone_static.vcxproj:
    * Remove all file references to files in subfolders of "arch", except "arch\X86".
    * Fix relative paths (remove "..\\..").
    * Remove all preprocessor definitions with prefix "CAPSTONE_HAS_", except CAPSTONE_HAS_X86.
    * Remove "..\headers" from additional include directory (leaving only "include").
    * Specify output and intermediate directory "$(SolutionDir)\obj\$(ProjectName)\$(Platform)\$(Configuration)\".

## CPU feature detection component

In addition to the disassembler, there is also functionality for detecting which of the
x86 architecture-specific CPU features (extended instruction sets) the executing processor
supports, from the ones reported by the Capstone disassembler - which calls it "instruction groups".

Note that this code is designed only for the Microsoft Visual C++ compiler and x86 architecture CPUs (Intel or AMD),
as it is based on the `__cpuid` intrinsic supported by Microsoft Visual C++ compiler
(which can detect most features from Intel and AMD processors).

Implementation is based on sample source code in the Microsoft Docs article about the __cpuid/__cpuidex
intrinsic, with information about newer AVX features from Wikipedia article about CPUID, and
some more details from an Intel article, see:
* https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex
* https://en.wikipedia.org/wiki/CPUID
* https://software.intel.com/sites/default/files/managed/c5/15/architecture-instruction-set-extensions-programming-reference.pdf

See also my project [CPUFeatures](https://github.com/albertony/cpufeatures), where I originally
explored this functionality.

## PE file parser component

There is also an implementation of a simple parser of Windows executable (image) files,
also known as Portable Executable (PE) files. It is by no means a complete parser,
for example it does not consider object files or other Common Object File Format (COFF) files,
but it has worked for my usage so far. It is used by the command line utility
when user specifies path to an executable file as argument, then it parses the PE
file to fetch the binary data where the executable code is contained, which is then
supplied to the disassembler.

Based on the following sources:
* https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547
* https://msdn.microsoft.com/en-us/library/ms809762.aspx
* https://msdn.microsoft.com/en-us/magazine/bb985992.aspx

## License

This is free software under the terms of the MIT license (check the [LICENSE](LICENSE) file for details).

Note that the included [Capstone](https://github.com/aquynh/capstone) source has its own license (check the [Capstone/LICENSE.TXT](Capstone/LICENSE.TXT) file for details).
