//
// Starting by reading and parsing the specified file as an Windows executable (image) file,
// also known as Portable Executable (PE) - to verify that it is really an executable file, to
// find its target machine (platform) that we use to set the mode of the disassembler, and to read
// the executable code data from it to be disassembled (and nothing else).
//
// Using Capstone disassembler library to process the executable code and collect the
// instruction sets (semantic groups) that it contains instructions for.
//
// Using cpuid intrinsic to optionally verify if the identified instructions are supported
// on the current CPU.
//
#include "Version.h"
#include <cstdint>
#include <cstdio>
#include "PEFile.hpp"
#include "Disassembler.hpp"

void show_usage(wchar_t* argv[])
{
	wchar_t* exe_name = wcsrchr(argv[0], '\\');
	if (exe_name)
		++exe_name;
	else
		exe_name = argv[0];
	wprintf(L"\nInstructionSets version %hs\n"
		"\n"
		"List instruction sets (semantic groups of instructions) (or instructions)\n"
		"used by an executable file, and optionally if the current CPU supports the\n"
		"corresponding feature.\n"
		"\n"
		"Usage:\n"
		"%s -help|-h|-?\n"
			"\tShow this help text.\n"
		"%s [-supported|-s]|[-unsupported|-u]\n"
			"\tCheck features, instruction sets, supported by the current CPU.\n"
			"\tsupported:\tOnly list instruction sets.\n"
			"\tunsupported:\tOnly list unsupported sets.\n"
		"%s filename [-cpu|-c] [-supported|-s] [-unsupported|-u]\n"
			"\tDisassemble executable file and list names of unique instruction sets.\n"
			"\tfilename:\tName of executable file, optionally with absolute or\n\t\t\trelative path.\n"
			"\tcpu:\t\tVerify if the identified instruction sets are supported\n\t\t\tby the CPU on the current machine.\n"
			"\tsupported:\tList supported instruction sets only (implied -cpu).\n"
			"\tunsupported:\tList only instruction sets not supported (implied -cpu).\n"
		"%s filename -instructions|-i [-verbose|-v]\n"
			"\tDisassemble executable file and list all instructions.\n"
			"\tinstructions:\tList name of all instructions.\n"
			"\tverbose:\tShow address and operands, in addition to the\n\t\t\tinstruction name.\n"
		"\n"
		"Samples:\n"
		"%s\n"
			"\tList all instruction sets and if the current CPU supports them.\n"
		"%s -supported\n"
			"\tPlain list with names of the instruction sets supported by the CPU.\n"
		"%s somefile.dll\n"
			"\tReport all instruction sets for specified file.\n"
		"%s somefile.dll -c\n"
			"\tReport all instruction sets for specified file, and warn about any\n\tunsupported.\n"
		"%s somefile.dll -c -u\n"
			"\tList any unsupported instruction sets for the specified file on the\n\tcurrent machine.\n"
		"%s somefile.dll -i -v\n"
			"\tList verbosely all instructions from the specified file.\n"
		, VERSION_STRING, exe_name, exe_name, exe_name, exe_name, exe_name, exe_name, exe_name, exe_name, exe_name, exe_name);
}
bool is_option(const wchar_t* arg)
{
	return (arg[0] == L'-' || arg[0] == L'/') && arg[1] != L'\0';
}
bool match_option_name(const wchar_t* arg, const wchar_t* option_name)
{
	return option_name && _wcsicmp(&arg[1], option_name) == 0;
}
bool match_option(const wchar_t* arg, const wchar_t* option_full = nullptr, const wchar_t* option_short = nullptr, const wchar_t* option_alternative = nullptr)
{
	return is_option(arg) && (match_option_name(arg, option_full) || match_option_name(arg, option_short) || match_option_name(arg, option_alternative));
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 2) {
		disasm_check_cpu_features(stdout, false, false);
		return 0;
	}
	if (match_option(argv[1], L"supported", L"s")) {
		disasm_check_cpu_features(stdout, true, false);
		return 0;
	}
	if (match_option(argv[1], L"unsupported", L"u")) {
		disasm_check_cpu_features(stdout, false, true);
		return 0;
	}
	if (match_option(argv[1], L"help", L"h", L"?")) {
		show_usage(argv);
		return 0;
	}
	try
	{
		// Parse the specified file as a Windows executable (image) file, also known as Portable Executable (PE).
		const wchar_t* filename = argv[1];
		pe_file pe(filename);
		cs_mode mode = pe.is_x86() ? CS_MODE_32 : CS_MODE_64;
		std::uint8_t* code = pe.get_code();
		std::uint32_t code_size = pe.get_code_size();

		// Run Capstone dissassebler on executable code and report results on stdout (errors on stderr).
		if (argc > 2 && match_option(argv[2], L"instructions", L"i")) {
			// Report all individual instructions
			bool verbose = argc > 3 && match_option(argv[3], L"verbose", L"v");
			disasm_instructions_to_stream(stdout, code, code_size, mode, verbose);
		} else {
			// Report unique instruction sets, what Capstone calls semantic groups
			bool check_cpu = false;
			bool filter_cpu_supported = false;
			bool filter_cpu_unsupported = false;
			if (argc > 2) {
				filter_cpu_supported = match_option(argv[2], L"supported", L"s");
				filter_cpu_unsupported = match_option(argv[2], L"unsupported", L"u");
				if (filter_cpu_supported || filter_cpu_unsupported) {
					check_cpu = true;
				} else if (match_option(argv[2], L"cpu", L"c")) {
					check_cpu = true;
					if (argc > 3) {
						filter_cpu_supported = match_option(argv[3], L"supported", L"s");
						filter_cpu_unsupported = match_option(argv[3], L"unsupported", L"u");
					}
				}
			}
			disasm_instruction_sets_to_stream(stdout, code, code_size, mode, check_cpu, filter_cpu_supported, filter_cpu_unsupported);
		}
		return 0;
	}
	catch (std::runtime_error& er)
	{
		wprintf(L"ERROR: %hs", er.what());
		return -1;
	}
}
