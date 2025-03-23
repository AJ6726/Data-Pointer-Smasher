#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "Zydis/Zydis.h"
#include "pattern_scan.h"
#include "utility.h"
#include "wrappers.h"
#include "paging.h"
#include "control_register.h"

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

//Checks on the memory region any potential function pointers reside in
uint32_t get_self_ref_index(); 
page_table* get_pte(uint64_t address); 
page_directory* get_pde(uint64_t address); 

//Checks for a mov rax, [rip + offset] and *(rip + offset) == function pointer
bool is_data_pointer_present(uint64_t function_start, uint64_t function_end, module_metadata& system_module); 

//Checks for the presence of a guard_dispatch_icall (should be a direct call E8 00 00 00 00, other call types and cfg functions are not implemented) 
bool is_cfg_present(uint64_t function_start, uint64_t function_end, uint64_t guard_dispatch_icall); 

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object = nullptr, PUNICODE_STRING registry_path = nullptr)
{
	UNREFERENCED_PARAMETER(registry_path);

	if (driver_object)
		driver_object->DriverUnload = [](PDRIVER_OBJECT) {};

	PEPROCESS explorer_eprocess = get_eprocess(L"\\Windows\\explorer.exe");

	if (!explorer_eprocess)
	{
		print("Failed to get explorer.exe EPROCESS\n");
		return STATUS_UNSUCCESSFUL;
	}

	//Attach to a process that has session drivers (win32k, win32kfull, win32kbase...) mapped in
	PKAPC_STATE apc_state = allocate_pool<PKAPC_STATE>(NonPagedPool, sizeof(KAPC_STATE)); 

	KeStackAttachProcess(explorer_eprocess, apc_state);

	for (int i = 0; i < system_module_count; i++)
	{
		module_metadata& system_module = system_module_metadata[i];

		system_module.base = get_kernel_module(system_module.name); 
		system_module.nt_header = PIMAGE_NT_HEADERS(system_module.base + PIMAGE_DOS_HEADER(system_module.base)->e_lfanew); // I got lazy
		system_module.data_section = get_image_section(system_module.base, ".data");
		system_module.rdata_section = get_image_section(system_module.base, ".rdata");

		uint64_t guard_dispatch_icall = pattern_scan<uint64_t>(system_module.base, ".text", system_module.guard_dispatch_icall_sig, system_module.guard_dispatch_icall_mask); 
		if (!guard_dispatch_icall)
		{
			print("Failed to pattern scan for guard_dispatch_icall for module %ws \n", system_module.name); 
			continue; 
		}

		system_module.guard_dispatch_icall = resolve_rva<uint64_t>(guard_dispatch_icall + system_module.instruction_offset, system_module.rva_offset, system_module.instruction_length);

		print("System Module %ws | Base %p | guard_dispatch_icall %p \n", system_module.name, system_module.base, system_module.guard_dispatch_icall); 

		PIMAGE_DATA_DIRECTORY exception_directory = get_data_directory(system_module.base, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		PRUNTIME_FUNCTION runtime_function = reinterpret_cast<PRUNTIME_FUNCTION>(system_module.base + exception_directory->VirtualAddress); 
		int32_t total_function_count = exception_directory->Size / sizeof(RUNTIME_FUNCTION); 

		for (int j = 0; j < total_function_count; j++, runtime_function++)
		{
			uint64_t function_start = system_module.base + runtime_function->BeginAddress; 
			uint64_t function_end = system_module.base + runtime_function->EndAddress; 

			page_table* function_pte = get_pte(function_start);

			//Dxgkrnl crashes without this, skip ntoskrnl
			if ((i > 0) && (!function_pte->present))
				continue; 

			if (!is_cfg_present(function_start, function_end, system_module.guard_dispatch_icall))
				continue;

			//The function is protected by cfg, so let us store it and later look through it
			linked_runtime_function* cfg_function = allocate_pool<linked_runtime_function*>(NonPagedPool, sizeof(linked_runtime_function)); 
			cfg_function->runtime_function = runtime_function; 
			
			//Populate the link list
			if (!system_module.cfg_functions)
			{
				system_module.cfg_functions = cfg_function;
				continue; 
			}

			auto node = system_module.cfg_functions;
			while (true)
			{
				if (!node->next)
				{
					node->next = cfg_function; 
					break; 
				}

				node = node->next; 
			}
		}
	}

	for (int i = 0; i < system_module_count; i++)
	{
		module_metadata& system_module = system_module_metadata[i];

		linked_runtime_function* cfg_function = system_module.cfg_functions;

		while (true)
		{
			PRUNTIME_FUNCTION runtime_function = cfg_function->runtime_function; 

			uint64_t function_start = system_module.base + runtime_function->BeginAddress; 
			uint64_t function_end = system_module.base + runtime_function->EndAddress;
			
			if (is_data_pointer_present(function_start, function_end, system_module))
			{
				print("[DATA POINTER] Module %ws | Function %p - %p \n",system_module.name, function_start, function_end); 
				print("=======================================================================================================================================\n");
			}

			if (!cfg_function->next)
				break;

			cfg_function = cfg_function->next;
		}
	}

	KeUnstackDetachProcess(apc_state);

	ExFreePool(apc_state);

	//Freeing the link list of runtime functions is an excerise left to the reader (I'm to lazy)
	return STATUS_SUCCESS;
}

uint32_t get_self_ref_index()
{
	control_register cr3 = { .value = __readcr3() };
	page_map_level_4* pml4 = get_virtual_address<page_map_level_4*>(cr3.c3.pml4 << page_4kb_shift);

	for (int i = 255; i < 512; i++)
		if (pml4[i].page_frame_number == cr3.c3.pml4)
			return i;

	return 0;
}

page_table* get_pte(uint64_t address)
{
	static uint32_t self_ref_index = get_self_ref_index();

	virtual_address pte_va = { .unused = 0xFFFF }; //Canonical Addressing moment
	pte_va.pml4_index = self_ref_index;

	return (page_table*)(((address >> 9) & 0x7FFFFFFFF8) + pte_va.value);
}

page_directory* get_pde(uint64_t address)
{
	static uint32_t self_ref_index = get_self_ref_index();

	virtual_address pde_va = { .unused = 0xFFFF };
	pde_va.pml4_index = self_ref_index;
	pde_va.pdp_index = self_ref_index;
	return (page_directory*)(((address >> 18) & 0x3FFFFFF8) + pde_va.value);
}

bool is_data_pointer_present(uint64_t function_start, uint64_t function_end, module_metadata& system_module)
{
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	ZydisDecoderContext decoder_context;

	ZyanU64 runtime_address = function_start;
	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction = { };
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	uint64_t function_size = function_end - function_start;

	uint64_t module_end = system_module.base + system_module.nt_header->OptionalHeader.SizeOfImage;

	bool found = false;
	while (offset < function_size)
	{
		offset += instruction.length;
		runtime_address += instruction.length;

		ZydisDecoderDecodeInstruction(&decoder, &decoder_context, reinterpret_cast<void*>(function_start + offset), function_size - offset, &instruction);

		bool is_mov_instruction = (instruction.mnemonic >= ZYDIS_MNEMONIC_MOV) && (instruction.mnemonic <= ZYDIS_MNEMONIC_MOVZX);
		if (!is_mov_instruction)
			continue;

		ZydisDecoderDecodeOperands(&decoder, &decoder_context, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT);

		bool is_mov_rax = (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) && (operands[0].reg.value == ZYDIS_REGISTER_RAX);
		bool is_relative_address = (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) && (operands[1].mem.base == ZYDIS_REGISTER_RIP);

		if (!is_mov_rax || !is_relative_address)
			continue;

		//mov_target = rip + offset, let zydis do his for us
		uint64_t mov_target = 0;
		ZydisCalcAbsoluteAddress(&instruction, &operands[1], runtime_address, &mov_target);

		bool in_own_module = (mov_target > system_module.base) && (mov_target <= module_end);

		if (!in_own_module)
			continue;

		bool in_writable_section = get_pde(mov_target)->read_write;

		if (!in_writable_section)
			continue;

		uint64_t function_ptr = *reinterpret_cast<uint64_t*>(mov_target); 

		in_own_module = (function_ptr > system_module.base) && (function_ptr <= module_end);

		bool in_another_module = false;

		UNICODE_STRING other_module_name = { };

		if (!in_own_module)
			in_another_module = find_address_module(function_ptr, other_module_name);

		if (!(in_own_module || in_another_module))
			continue;

		bool no_execute = false;
		page_directory* pde = get_pde(function_ptr);

		if (pde->large_page)
		{
			no_execute = pde->large.no_execute;
		}
		else
		{
			page_table* pte = get_pte(function_ptr);
			no_execute = pte->no_execute;
		}

		if (no_execute)
			continue;

		if (in_own_module)
			print("[OWN] Instruction %p | Mov Target %p | Function Ptr %p \n", runtime_address, mov_target, function_ptr);

		if (in_another_module)
			print("[ANOTHER] Instruction %p | Mov Target %p | Function Ptr %p in %wZ \n", runtime_address, mov_target, function_ptr, &other_module_name);

		found = true;

	}

	return found;
}

bool is_cfg_present(uint64_t function_start, uint64_t function_end, uint64_t guard_dispatch_icall)
{
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	ZydisDecoderContext decoder_context = { };

	ZyanU64 runtime_address = function_start;
	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction = { };
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	uint64_t function_size = function_end - function_start;

	while (offset < function_size)
	{
		offset += instruction.length;
		runtime_address += instruction.length;

		ZydisDecoderDecodeInstruction(&decoder, &decoder_context, reinterpret_cast<void*>(function_start + offset), function_size - offset, &instruction);

		if (instruction.mnemonic != ZYDIS_MNEMONIC_CALL)
			continue;

		ZydisDecoderDecodeOperands(&decoder, &decoder_context, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT);

		if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[0].imm.is_relative)
		{
			//call_target = rip + offset, let zydis do this for us
			uint64_t call_target = 0;
			ZydisCalcAbsoluteAddress(&instruction, &operands[0], runtime_address, &call_target);

			if (call_target == guard_dispatch_icall)
				return true;
		}

	}

	return false;
}
