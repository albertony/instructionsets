//
// Wrapper for Capstone dissassembler, combined with our own CPUFeatures functionality.
//
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <bitset>
#include <exception>
#include <Capstone\include\capstone\capstone.h>
#include "CPUFeatures.hpp"

//
// Helper function to report information about a single instruction set.
//
static void disasm_report_instruction_set(std::uint8_t id, const char* name, bool report_cpu_support, bool cpu_supported, bool filter_cpu_supported, bool filter_cpu_unsupported)
{
	if (report_cpu_support) {
		if ((!filter_cpu_supported && !filter_cpu_unsupported) || (filter_cpu_supported && filter_cpu_unsupported)) {
			// Reporting all, and then we must indicate on each of them if supported or not
			if (name) {
				wprintf_s(L"%hs %s\n", name, cpu_supported ? L"supported" : L"unsupported");
			}
			else {
				wprintf_s(L"unknown_group_id_%d %s\n", id, cpu_supported ? L"supported" : L"unsupported");
			}
		} else if ((cpu_supported && filter_cpu_supported) || (!cpu_supported && filter_cpu_unsupported)) {
			// Reporting only supported or only unsupported as a plain list
			if (name) {
				wprintf_s(L"%hs\n", name);
			}
			else {
				wprintf_s(L"unknown_group_id_%d\n", id);
			}
		}
	} else {
		// Reporting all as a plain list, without indicating support
		if (name) {
			wprintf_s(L"%hs\n", name);
		}
		else {
			wprintf_s(L"unknown_group_id_%d\n", id);
		}
	}
}

//
// List the instruction sets (semantic groups) handled by the disassembler,
// and check if the CPU on the current machine supports the corresponding
// feature. This function is streaming the results to a supplied stream handle,
// any errors are thrown as exceptions.
//
static void disasm_check_cpu_features(std::FILE* out, bool filter_supported, bool filter_unsupported)
{
	csh handle;
#ifdef _WIN64
	cs_mode mode = CS_MODE_64;
#else
	cs_mode mode = CS_MODE_32;
#endif
	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
		throw std::runtime_error("Initializing Capstone disassembler library failed");
	}
	const std::uint64_t cpu_features = get_current_cpu_features();
	const cpu_feature_id num_features = number_of_cpu_features();
	for (cpu_feature_id i = 1; i <= num_features; ++i) {
		std::uint8_t group_id = cpu_feature_id_to_cs_group_id(i);
		const char* group_name = cs_group_name(handle, group_id);
		bool supported = check_cpu_feature_support(i, cpu_features);
		disasm_report_instruction_set(group_id, group_name, true, supported, filter_supported, filter_unsupported);
	}
	cs_close(&handle);
}

//
// Disassembling a byte buffer with code, write name of all instructions to the supplied
// stream handle, throw exception if error.
//
static void disasm_instructions_to_stream(std::FILE* out, std::uint8_t* code, std::size_t code_size, cs_mode mode, bool show_instruction_sets, bool show_address_and_operands)
{
	csh handle;
	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
		throw std::runtime_error("Initializing Capstone disassembler library failed");
	}
	if (show_instruction_sets) {
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // We need the detailed output from Capstone to get instruction groups, but not to just to list the instructions
	}
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON); // Don't stop disassembling when encountering something that is not an instruction, because when disassembling the code section of a PE file it normally contains data mixed with instructions. Capstone recommends that the caller finds where the next instruction is and restarts the disassembler from that place, but for simplicity we just enable the SKIPDATA mode where Capstone tries its best to determine where the next instruction is and continue automatically.
	cs_insn *insn;
	std::size_t n_insn = cs_disasm(handle, code, code_size, 0, 0, &insn);
	if (n_insn == 0) {
		cs_close(&handle);
		throw std::runtime_error("Disassembler found no instructions");
	}
	for (std::size_t i = 0; i < n_insn; ++i) {
		if (show_address_and_operands) {
			wprintf_s(L"0x%" PRIx64 L":\t%hs (%hs)", insn[i].address, insn[i].mnemonic, insn[i].op_str);
			if (show_instruction_sets && insn[i].detail->groups_count > 0) {
				int counter = 0;
				for (std::size_t j = 0; j < insn[i].detail->groups_count; ++j) {
					const char* group_name = cs_group_name(handle, insn[i].detail->groups[j]);
					if (group_name) {
						if (counter == 0) {
							wprintf_s(L": ");
						} else {
							wprintf_s(L", ");
						}
						wprintf_s(L"%hs", group_name);
						++counter;
					}
				}
			}
			wprintf_s(L"\n");
		}
		else if (show_instruction_sets) {
			wprintf_s(L"%hs", insn[i].mnemonic);
			if (insn[i].detail->groups_count > 0) {
				int counter = 0;
				for (std::size_t j = 0; j < insn[i].detail->groups_count; ++j) {
					const char* group_name = cs_group_name(handle, insn[i].detail->groups[j]);
					if (group_name) {
						if (counter == 0) {
							wprintf_s(L": ");
						}
						else {
							wprintf_s(L", ");
						}
						wprintf_s(L"%hs", group_name);
						++counter;
					}
				}
			}
			wprintf_s(L"\n");
		}
		else {
			wprintf_s(L"%hs\n", insn[i].mnemonic);
		}
	}
	cs_free(insn, n_insn);
	cs_close(&handle);
}

//
// Disassembling a byte buffer with code, collecting name of instruction sets (semantic groups)
// used and report list of unique names. This function is streaming the results to
// a supplied stream handle, any errors are thrown as exceptions.
//
static void disasm_instruction_sets_to_stream(std::FILE* out, std::uint8_t* code, std::size_t code_size, cs_mode mode, bool check_cpu, bool filter_cpu_supported, bool filter_cpu_unsupported)
{
	csh handle;
	if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK) {
		throw std::runtime_error("Initializing Capstone disassembler library failed");
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // We need detailed output from Capstone to get the semantic groups the instruction belongs
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON); // Don't stop disassembling when encountering something that is not an instruction, because when disassembling the code section of a PE file it normally contains data mixed with instructions. Capstone recommends that the caller finds where the next instruction is and restarts the disassembler from that place, but for simplicity we just enable the SKIPDATA mode where Capstone tries its best to determine where the next instruction is and continue automatically.
	cs_insn *insn;
	std::size_t n_insn = cs_disasm(handle, code, code_size, 0, 0, &insn);
	if (n_insn == 0) {
		cs_close(&handle);
		throw std::runtime_error("Disassembler found no instructions");
	}
	std::bitset<X86_GRP_ENDING> groups;
	std::uint64_t current_cpu_features = check_cpu ? get_current_cpu_features() : 0;
	for (std::size_t i = 0; i < n_insn; ++i) {
		if (insn[i].detail) {
			for (std::size_t j = 0; j < insn[i].detail->groups_count; ++j) {
				std::uint8_t group_id = insn[i].detail->groups[j];
				if (!groups[group_id]) {
					const char* group_name = cs_group_name(handle, group_id);
					bool supported = check_cpu ? check_cs_group_cpu_support(group_id, current_cpu_features) : true;
					disasm_report_instruction_set(group_id, group_name, check_cpu, supported, filter_cpu_supported, filter_cpu_unsupported);
					// DEBUG: Print name of the instruction that introduced this group:
					//wprintf_s(L"   %hs\n", insn[i].mnemonic);
					groups[group_id] = true;
				}
			}
		}
	}
	cs_free(insn, n_insn);
	cs_close(&handle);
}
