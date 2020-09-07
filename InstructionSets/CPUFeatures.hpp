//
// Code for detecting which of the x86 architecture-specific CPU features (extended instruction sets)
// the executing processor supports, from the ones reported by the Capstone disassembler - which calls
// it "instruction groups".
//
// There is not a function for returning the actual name of CPU features here, so the caller must use
// Capstone dissassembler function cs_group_name to do that, converting CPU feature id into corresponding
// Capstone group id.
//
// The code is designed only for the Microsoft Visual C++ compiler and x86 architecture CPUs (Intel or AMD).
//
#pragma once
#include <cstddef>
#include <cstdint>
#include <intrin.h>
#include <Capstone\include\capstone\x86.h> // Using Capstone's enum for grouping of X86 instructions

//
// Defining an identifier for CPU features as an unsigned integer, where the value
// is based on Capstone's enum for grouping x86 instructions, but ignoring the generic
// groups and only considering the x86 architecture-specific groups. Since these
// starts at an offset we squash the values so that the first x86 artchitecture-specific
// group (X86_GRP_VM, at value 128) corresponds to bit position 1 etc.
//
typedef std::uint8_t cpu_feature_id;
static const std::uint8_t cs_group_id_cpu_feature_id_offset = X86_GRP_VM-1;

//
// Simple utility functions for handling the difference between Capstone's group id
// and our squashed value as identifier for CPU feature.
//
static cpu_feature_id cs_group_id_to_cpu_feature_id(std::uint8_t group_id)
{
	// NB: Quick and dirty - caller must ensure only valid group id corresponding to a CPU feature
	//     is specified, because here it is assumed to be within the x86 architecture-specific range:
	//     Higher than the cs_group_id_cpu_feature_id_offset and not higher than number_of_cpu_features.
	//     It is called internally from check_cs_group_cpu_support which do complete validation of group id first,
	//     and from get_current_cpu_features which calls it with known group id constants.
	return group_id - cs_group_id_cpu_feature_id_offset;
}
static std::uint8_t cpu_feature_id_to_cs_group_id(cpu_feature_id cpu_feature)
{
	return cpu_feature + cs_group_id_cpu_feature_id_offset;
}
static cpu_feature_id number_of_cpu_features()
{
	return cs_group_id_to_cpu_feature_id(X86_GRP_ENDING-1);
}

//
// Check if a specified CPU feature is present in a bit encoded list of supported CPU features,
// as returned by get_current_cpu_features.
//
static bool check_cpu_feature_support(cpu_feature_id cpu_feature, std::uint64_t cpu_features)
{
	return (cpu_features & ((std::uint64_t)1 << cpu_feature)) != 0; // Check if bit for specified CPU feature is set
}

//
// Check if a specified Capstone instruction group is present in a bit encoded list of supported CPU features,
// as returned by get_current_cpu_features.
//
static bool check_cs_group_cpu_support(uint8_t group_id, std::uint64_t cpu_features)
{
	// Making assumptions on the enumeration like Capstone code does skip invalid groups the same way as X86_group_name function does.
	if (group_id <= X86_GRP_INVALID || group_id >= X86_GRP_ENDING || (group_id > X86_GRP_BRANCH_RELATIVE && group_id < X86_GRP_VM)) // Invalid groups (before first generic, after last architecture-specific or between last generic and first architecture-specific)
		return false; // Report invalid groups as unsupported?
	if (group_id < X86_GRP_VM) // Generic groups
		return true; // Report generic groups as supported
	cpu_feature_id cpu_feature = cs_group_id_to_cpu_feature_id(group_id);
	return check_cpu_feature_support(cpu_feature, cpu_features);
}

//
// For all x86 architecture-specific groups detected by Capstone (enumeration x86_insn_group in x86.h),
// check if the executing CPU supports it (by use of the __cpuid intrinsic supported by Microsoft
// Visual C++ compiler, which can detect most features from Intel and AMD processors).
// Returns bit encoded integer value, with Capstone x86 architecture-specific group identifiers squashed
// so first group corresponds to bit position 1 etc.
//
static std::uint64_t get_current_cpu_features()
{
	std::uint64_t cpu_features = 0; // Returning a bitcoded value
	int cpu_info[4]; // Value of the four registers EAX, EBX, ECX, and EDX, each 32-bit integers
	const std::size_t EAX=0,EBX=1,ECX=2,EDX=3; // Registry indexes in cpu_info

	// First we request the highest valid function ID for this CPU by sending value 0 in register EAX register (where we later request function ids).
	int max_function_id = 0;
	__cpuid(cpu_info, 0);
	max_function_id = cpu_info[0];

	// Function id 1 contains bitset with flags for main features
	int function_id = 1;
	if (function_id > max_function_id)
		return cpu_features;
	__cpuid(cpu_info, function_id);
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 <<  5) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_VM);		// ECX bit 5 indicates Virtual Machine eXtensions (Intel VT-x and AMD-V)
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 << 25) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_AES);		// ECX bit 25 indicates Advanced Encryption Standard
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 << 28) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_AVX);		// ECX bit 28 indicates Advanced Vector Extensions
	cpu_features |= (std::uint64_t)((cpu_info[EDX] & 1 << 15) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_CMOV);		// EDX bit 15 indicates Conditional move and FCMOV instructions
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 << 29) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_F16C);		// ECX bit 15 indicates F16C (half-precision) FP support
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 << 12) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_FMA);		// ECX bit 12 indicates Fused multiply-add (FMA3)
	cpu_features |= (std::uint64_t)((cpu_info[EDX] & 1 << 23) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_MMX);		// EDX bit 23 indicates MMX
	cpu_features |= (std::uint64_t)((cpu_info[EDX] & 1 << 25) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SSE1);		// EDX bit 25 indicates Streaming SIMD Extensions (a.k.a. Katmai New Instructions, KNI)
	cpu_features |= (std::uint64_t)((cpu_info[EDX] & 1 << 26) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SSE2);		// EDX bit 26 indicates Streaming SIMD Extensions 2
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 <<  0) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SSE3);		// ECX bit 0 indicates  Streaming SIMD Extensions 3 (a.k.a. Prescott New Instructions, PNI)
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 <<  9) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SSSE3);	// ECX bit 9 indicates Supplemental Streaming SIMD Extensions 3 (a.k.a. Tejas New Instructions, TNI, Merom New Instructions, MNI)
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 << 19) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SSE41);	// ECX bit 19 indicates Streaming SIMD Extensions 4 subset 1
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 << 20) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SSE42);	// ECX bit 20 indicates Streaming SIMD Extensions 4 subset 2
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 <<  1) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_PCLMUL);	// ECX bit 1 indicates Carry-less Multiplication (CLMUL) support
	cpu_features |= (std::uint64_t)((cpu_info[EDX] & 1 <<  0) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_FPU);		// EDX bit 0 indicates Floating-point Unit On-Chip

	// Function id 7 contains bitset with flags for extended features
	function_id = 7;
	if (function_id > max_function_id)
		return cpu_features;
	__cpuid(cpu_info, function_id);
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 19) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_ADX);		// EBX bit 25 indicates Multi-Precision Add-Carry Instruction Extensions (a.k.a. Intel ADX)
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 <<  5) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_AVX2);		// EBX bit 5 indicates Advanced Vector Extensions 2
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 16) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_AVX512);	// EBX bit 16 indicates Advanced Vector Extensions 512-bit Extensions Foundation (AVX-512F, the core extension required by all imiplementations of AVX-512).
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 <<  3) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_BMI);		// EBX bit 3 indicates Bit Manipulation Instruction Set 1
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 <<  8) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_BMI2);		// EBX bit 8 indicates Bit Manipulation Instruction Set 2
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 <<  0) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_FSGSBASE);	// EBX bit 0 indicates Access to base of %fs and %gs
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 <<  4) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_HLE);		// EBX bit 4 indicates Hardware Lock Elision from Transactional Synchronization Extensions
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 11) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_RTM);		// EBX bit 11 indicates Restricted Transactional Memory from Transactional Synchronization Extensions
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 29) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SHA);		// EBX bit 29 indicates Secure Hash Algorithm (a.ka. Intel SHA Extensions)
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 <<  2) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SGX);		// EBX bit 2 indicates Software Guard Extensions
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 20) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SMAP);		// EBX bit 2 indicates Supervisor Mode Access Prevention
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 26) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_PFI);		// EBX bit 26 indicates AVX-512-PF (AVX-512 Prefetch)
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 27) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_ERI);		// EBX bit 27 indicates AVX-512-ER (AVX-512 Exponential and Reciprocal)
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 28) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_CDI);		// EBX bit 28 indicates AVX-512-CD (AVX-512 Conflict Detection)
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 30) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_BWI);		// EBX bit 30 indicates AVX-512-BW (AVX-512 Byte and Word)
	cpu_features |= (std::uint64_t)((cpu_info[EBX] & 1 << 17) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_DQI);		// EBX bit 17 indicates AVX-512-DQ (AVX-512 Doubleword and Quadword)

	// Special handling for EBX bit 31 indicating AVX-512-VL (AVX-512 Vector Length).
	// AVX-512-VL (AVX-512 Vector Length) adds new versions of existing AVX-512 instructions.
	// AVX-512 includes instructions that can operate on 512-bit registers, but the
	// Vector Length Extensions (VLE) is a feature, categorized as an orthogonal feature,
	// that lets applications use most of the same instructions on shorter vector lengths.
	// Capstone adds additional group ids X86_GRP_VLX or X86_GRP_NOVLX to indicate this, and
	// seems to use them as following: Instructions in group X86_GRP_VLX are also in either group
	// X86_GRP_BWI (AVX-512-BW) or X86_GRP_AVX512 (AVX-512F), while instructions in group
	// X86_GRP_NOVLX are also in group X86_GRP_AVX.
	// Here we simply check the AVX-512-VL feature of the CPU, and if set then flag the
	// X86_GRP_VLX instruction group as supported, else flag the X86_GRP_NOVLX instruction group
	// as supported (which should work out fine due to the logic described above, without
	// checking if AVX or AVX-512 features are supported).
	// Updated for Capstone version 4.0.2, where running the application checking its own binary
	// reports instruction group novlx being used, together with avx and avx2 (but not avx512),
	// while previous version did not report novlx in this case!
	bool vlxMode = (std::uint64_t)((cpu_info[EBX] & 1 << 31) != 0);
	cpu_features |= (std::uint64_t)(1) << cs_group_id_to_cpu_feature_id(vlxMode ? X86_GRP_VLX : X86_GRP_NOVLX);

	// Extended functions
	// These are in a separate id sequence above above INT32_MAX (2147483647), so represented in a singed 
	// 32-bit integer they are negative values starting at INT32_MIN (-2147483648) and moving towards zero.
	// Max extended function id can be requested with value 0x80000000 in EAX (same register as we request
	// function id with positive values).
	int max_extended_function_id = 0x80000000;
	__cpuid(cpu_info, 0x80000000);
	max_extended_function_id = cpu_info[0];

	// Extended function id 0x80000001 contains bitset with flags for extended processor info and features
	function_id = 0x80000001;
	if (function_id > max_extended_function_id)
		return cpu_features;
	__cpuid(cpu_info, function_id);
	cpu_features |= (std::uint64_t)((cpu_info[EDX] & 1 << 31) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_3DNOW);	// EDX bit 31 indicates 3D Now!
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 << 16) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_FMA4);		// ECX bit 12 indicates 4 operands fused multiply-add
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 <<  6) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_SSE4A);	// ECX bit 6 indicates Streaming SIMD Extensions 4 subset a
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 << 11) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_XOP);		// ECX bit 11 indicates eXtended Operations
	cpu_features |= (std::uint64_t)((cpu_info[ECX] & 1 << 21) != 0) << cs_group_id_to_cpu_feature_id(X86_GRP_TBM);		// ECX bit 21 indicates Trailing Bit Manipulation

	// Special handling for EDX bit 29: It indicates Long mode, which means a 64-bit
	// operating system can access 64-bit instructions and registers.
	// This tells us we have an x86-64/AMD64 processor, which can run in either
	// real 64-bit mode (the long mode) or in 32-bit compatibility mode.
	bool longMode = (std::uint64_t)((cpu_info[EDX] & 1 << 29) != 0);
	if (longMode) { // 64-bit x86-64 processors can run applications in 32-bit mode or 64-bit mode
		cpu_features |= (std::uint64_t)(1) << cs_group_id_to_cpu_feature_id(X86_GRP_MODE32);
		cpu_features |= (std::uint64_t)(1) << cs_group_id_to_cpu_feature_id(X86_GRP_MODE64);
	} else { // 32-bit x86 processors can only run applications in 32-bit mode
		cpu_features |= (std::uint64_t)(1) << cs_group_id_to_cpu_feature_id(X86_GRP_MODE32); // TODO: Regular 32-bit instructions that can run on any x86?
		cpu_features |= (std::uint64_t)(1) << cs_group_id_to_cpu_feature_id(X86_GRP_NOT64BITMODE); // TODO: Some instructions that can only run on pure 32-bit x86?
	}

	return cpu_features;
}
