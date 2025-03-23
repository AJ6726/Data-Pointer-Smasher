#pragma once
#include "types.h"
#include "nt.h"
#include "pe.h"

struct linked_runtime_function
{
	linked_runtime_function* next;
	PRUNTIME_FUNCTION runtime_function;
};

//All the data needed for a scan of the module
struct module_metadata
{
	const wchar_t* name;
	uint64_t base;
	PIMAGE_NT_HEADERS nt_header;
	uint64_t guard_dispatch_icall;
	PIMAGE_SECTION_HEADER data_section;
	PIMAGE_SECTION_HEADER rdata_section;
	linked_runtime_function* cfg_functions; //functions protected by cfg

	const char* guard_dispatch_icall_sig;
	const char* guard_dispatch_icall_mask;
	uint32_t rva_offset; //Offset to the rip relative address
	uint32_t instruction_length;
	uint32_t instruction_offset; //Offset to the instruction
};

constexpr int32_t system_module_count = 5;
module_metadata system_module_metadata[] =
{
	{
		.name = L"ntoskrnl.exe",
		.guard_dispatch_icall_sig = "\xE8\x00\x00\x00\x00\x24\x05",
		.guard_dispatch_icall_mask = "x????xx",
		.rva_offset = 1,
		.instruction_length = 5,
	},

	//Windows does runtime patches of guard_dispatch_icall_fptr (FF 15 -> E8), so no direct sig
	{
		.name = L"win32kbase.sys",
		.guard_dispatch_icall_sig = "\x48\x8B\xC4\x48\x89\x58\x10\x48\x89\x68\x18\x48\x89\x70\x20\x57\x48\x83\xEC\x30\x48\x83\x60\x00\x00\x48\x8B\xF9",
		.guard_dispatch_icall_mask = "xxxxxxxxxxxxxxxxxxxxxxx??xxx",
		.rva_offset = 1,
		.instruction_length = 5,
		.instruction_offset = 0x2C,

	},

	{
		.name = L"win32k.sys",
		.guard_dispatch_icall_sig = "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x30",
		.guard_dispatch_icall_mask = "xxxx?xxxx?xxxx?xxxxx",
		.rva_offset = 1,
		.instruction_length = 5,
		.instruction_offset = 0x2B,
	},

	{
		.name = L"win32kfull.sys",
		.guard_dispatch_icall_sig = "\x4C\x8D\x4C\x24\x00\x4C\x8B\xC3\x8B\xD7",
		.guard_dispatch_icall_mask = "xxxx?xxxxx",
		.rva_offset = 1,
		.instruction_length = 5,
		.instruction_offset = 0xD,
	},

	{
		.name = L"dxgkrnl.sys",
		.guard_dispatch_icall_sig = "\x84\xC0\x0F\x84\x00\x00\x00\x00\x48\x8D\x7B\x28",
		.guard_dispatch_icall_mask = "xxxx????xxxx",
		.rva_offset = 1,
		.instruction_length = 5,
		.instruction_offset = 0x15,
	}
};