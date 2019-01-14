//
// Parsing of Windows executable (image) file, also known as Portable Executable (PE),
// but does not consider object files or other Common Object File Format (COFF) files.
// Based on: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547
// And: https://msdn.microsoft.com/en-us/library/ms809762.aspx
// And: https://msdn.microsoft.com/en-us/magazine/bb985992.aspx
//
#pragma once
#include <cstdint>
#include <fstream>
#include <exception>

class pe_file
{
private:
	bool _x64;
	bool _dll;
	std::uint8_t* _code;
	std::uint32_t _code_size;
public:
	bool is_x86() { return !is_x64(); }
	bool is_x64() { return _x64; }
	bool is_dll() { return _dll; }
	bool is_exe() { return !is_dll(); }
	std::uint8_t* get_code() { return _code; }
	std::uint32_t get_code_size() { return _code_size; }
	pe_file(const wchar_t* filename)
	{
		_x64 = false;
		_dll = false;
		_code = nullptr;
		_code_size = 0u;

		std::ifstream fstream(filename, std::ios_base::in | std::ios_base::binary);
		if (!fstream) {
			throw std::runtime_error("Unable to open file");
		}
		// DOS header
		// The first 2 bytes should be the "magic" value 0x5A4D, which corresponds to the string "MZ" 
		std::uint16_t dos_magic;
		if (!fstream.read((char*)&dos_magic, 2)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete DOS header)");
		}
		if (dos_magic != 0x5A4D) {
			throw std::runtime_error("File is not a valid Portable Executable (invalid DOS header)");
		}
		// The final field of the dos header, 58 bytes from current position - 60 bytes into the file which
		// is the known position 0x3c, gives the file offset to the PE header (which is following right after the MS-DOS stub)
		if (!fstream.seekg(58, std::ios_base::cur)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete DOS header)");
		}
		std::uint32_t pe_offset;
		if (!fstream.read((char*)&pe_offset, 4)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete DOS header)");
		}

		// PE Signature
		// Verify the 4-byte signature that identifies the file as a PE format image file
		if (!fstream.seekg(pe_offset, std::ios_base::beg)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete PE signature)");
		}
		std::uint32_t pe_head;
		if (!fstream.read((char*)&pe_head, 4)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete PE signature)");
		}
		if (pe_head != 0x00004550) { // The 4 bytes "PE\0\0", 0x50 0x45 0x00 0x00, little-endian
			throw std::runtime_error("File is not a valid Portable Executable (invalid PE signature)");
		}

		// COFF File Header
		// The first two bytes is a number that identifies the type of target machine
		std::uint16_t machine_type;
		if (!fstream.read((char*)&machine_type, 2)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete COFF file header)");
		}
		if (machine_type == 0x14c) {// Intel 386 or later processors and compatible processors (IMAGE_FILE_MACHINE_I386)
			_x64 = false;
		} else if (machine_type == 0x8664) { // x64 (IMAGE_FILE_MACHINE_AMD64)
			_x64 = true;
		} else {
			throw std::runtime_error("Unsupported target machine in COFF header");
		}
		// Get number of sections, which we need later.
		std::uint16_t num_sections;
		if (!fstream.read((char*)&num_sections, 2)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete COFF file header)");
		}
		// Skip next 12 bytes and read the value giving the size of the "optional" header, which is required for PE files (but not COFF).
		if (!fstream.seekg(12, std::ios_base::cur)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete COFF file header)");
		}
		std::uint16_t size_optional_header;
		if (!fstream.read((char*)&size_optional_header, 2)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete COFF file header)");
		}
		// The 2 final bytes of the COFF file header indicates characteristics such as if it is an .exe or .dll,
		// For PE it must be marked as executable image, or else the image is not valid and it indicates a linker error.
		int type = 0;
		std::uint16_t characteristics;
		if (!fstream.read((char*)&characteristics, 2)) { // Can be used to identify if .exe, .dll or .sys, large address aware, etc.
			throw std::runtime_error("File is not a valid Portable Executable (incomplete COFF file header)");
		}
		if ((characteristics & 0x0002) != 0x0002) { // IMAGE_FILE_EXECUTABLE_IMAGE
			throw std::runtime_error("File is not a valid Portable Executable (is not marked as an executable image file in the COFF file header)");
		}
		_dll = ((characteristics & 0x2000) == 0x2000); // IMAGE_FILE_DLL, in addition to IMAGE_FILE_EXECUTABLE_IMAGE, indicates executable .dll

		// Optional header (required for PE files)
		// 16 bytes into the optional header is the address of the entry point (relative to the image base
		// when the executable file is loaded into memory). This is optional for DLL, and will then be zero.
		if (!fstream.seekg(16, std::ios_base::cur)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete optional header)");
		}
		std::uint32_t address_entry_point;
		if (!fstream.read((char*)&address_entry_point, 4)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete optional header)");
		}
		if (!address_entry_point) {
			if (_dll) {
				throw std::runtime_error("File is a resource-only DLL without executable code");
			} else {
				throw std::runtime_error("File is not a valid Portable Executable (missing entry point address)");
			}
		}
		// By using the known size we can move past the optional header and get to the section table.
		if (!fstream.seekg(size_optional_header - 20, std::ios_base::cur)) {
			throw std::runtime_error("File is not a valid Portable Executable (incomplete optional header)");
		}

		// Section table
		// We need the code sections, which are sections with flag IMAGE_SCN_CNT_CODE, or possibly IMAGE_SCN_MEM_EXECUTE,
		// indicating that it contains executable code. The image files can in principle contain several such sections,
		// and in any position and order, but in reality the linkers targeting images for Microsoft Win32
		// have more or less standardized on concatenating all code sections from the various .obj files into a single
		// code section in the resulting PE file, naming this ".text" and is placing it as the first section (after the
		// optional header but before any other sections). The optional header have generic field BaseOfCode that describes
		// the position of the first code section, so this will have the value 0x1000 following these guidelines.
		// But this is not a strict requirement, so valid executables might be created using a different layout.
		// A much used technique is therefore to use the AddressOfEntryPoint from the optional header, and search for
		// the section containing that address (a section where SectionStart ≤ AddressOfEntryPoint < SectionEnd).
		// This should ensure you get the code section, regardless of its name and flags, but still we are assuming
		// it is the only one. DLLs can be built without an entry point, and then the AddressOfEntryPoint are zero,
		// but this is resource-only DLLs that contains no executable code.
		std::uint32_t pointer_to_code = 0;
		std::uint32_t pointer_to_entry_point = 0;
		std::uint32_t size_of_code = 0;
		while (num_sections && !pointer_to_code) {
			// Skip first 8 bytes of the section, which is the name, and then read the VirtualSize and VirtualAddress following
			if (!fstream.seekg(8, std::ios_base::cur)) {
				throw std::runtime_error("File is not a valid Portable Executable (invalid section)");
			}
			std::uint32_t section_virtual_size;
			if (!fstream.read((char*)&section_virtual_size, 4)) {
				throw std::runtime_error("File is not a valid Portable Executable (invalid section)");
			}
			std::uint32_t section_virtual_address;
			if (!fstream.read((char*)&section_virtual_address, 4)) {
				throw std::runtime_error("File is not a valid Portable Executable (invalid section)");
			}
			// Check if the addressOfEntryPoint is within this section
			if (section_virtual_address <= address_entry_point && address_entry_point < section_virtual_address + section_virtual_size) {
				// The data for each section is located at the file offset that was given by the PointerToRawData
				// field in the section header. The size of this data in the file is indicated by the SizeOfRawData
				// field, but for executables the value is rounded up according to file aligment while the value
				// in VirtualSize is the actual size of the section. Since SizeOfRawData is rounded up it might
				// actually become greater than VirtualSize. But VirtualSize can be also be greater than
				// SizeOfRawData, in case the end of the section has been padded with zeros.
				std::uint32_t size_of_raw_data;
				if (!fstream.read((char*)&size_of_raw_data, 4)) { // Read SizeOfRawData
					throw std::runtime_error("File is not a valid Portable Executable (invalid section)");
				}
				std::uint32_t pointer_to_raw_data;
				if (!fstream.read((char*)&pointer_to_raw_data, 4)) { // Read PointerToRawData
					throw std::runtime_error("File is not a valid Portable Executable (invalid section)");
				}
				pointer_to_code = pointer_to_raw_data; // This is a file pointer to the beginning of the executable code
				pointer_to_entry_point = address_entry_point - section_virtual_address + pointer_to_raw_data; // This is file pointer to the entry point, which may be at the beginning of the executable code or later
				if (size_of_raw_data < section_virtual_size) {
					size_of_code = size_of_raw_data; // Section is zero padded, so limit the size according to the raw data size - even though it is rounded up.
				} else {
					size_of_code = section_virtual_size; // Section virtual size gives the most accurate size since the raw data size is rounded up.
				}
			}
			else {
				// Skip remaining 24 bytes to get to start of next section
				if (!fstream.seekg(24, std::ios_base::cur)) {
					throw std::runtime_error("File is not a valid Portable Executable (invalid section)");
				}
				--num_sections;
			}
		}
		if (!pointer_to_code) {
			throw std::runtime_error("File is not a valid Portable Executable (could not find code section)");
		}
		if (!size_of_code) {
			throw std::runtime_error("File is not a valid Portable Executable (code section is empty)");
		}
		// Now move to the location where executable code begins
		if (!fstream.seekg(pointer_to_code, std::ios_base::beg)) {
			throw std::runtime_error("File is not a valid Portable Executable (invalid code section)");
		}

		// Must all code into one memory block for the disassembler to work correctly
		_code = new std::uint8_t[size_of_code];
		if (!fstream.read((char*)_code, size_of_code)) { // Note that we do not expect end-of-file to be reached before reading the requested size and will report this as error (because both eofbit and failbit are set in this case and the operator! returns false when failbit or badbit is set)
			delete[] _code;
			_code = nullptr;
			if (!fstream.bad() && fstream.eof()) {
				throw std::runtime_error("File is not a valid Portable Executable (premature end of file while reading executable code)");
			} else {
				throw std::runtime_error("Reading executable code from file failed");
			}
		}
		std::streamsize num_bytes_read = fstream.gcount();
		if (num_bytes_read <= 0) {
			delete[] _code;
			_code = nullptr;
			throw std::runtime_error("No executable code was read from the file");
		}
		_code_size = static_cast<std::uint32_t>(num_bytes_read);
	}
	~pe_file()
	{
		delete[] _code;
	};
};