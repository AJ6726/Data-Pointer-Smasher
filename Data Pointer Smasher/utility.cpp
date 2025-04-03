#include <intrin.h>
#include "utility.h"
#include "nt.h"
#include "control_register.h"
#include "wrappers.h"

extern "C" PKLDR_DATA_TABLE_ENTRY PsLoadedModuleList;

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

PEPROCESS get_eprocess(const wchar_t* process_name)
{
	PLIST_ENTRY ActiveProcessLinks = reinterpret_cast<PLIST_ENTRY>(uint64_t(PsInitialSystemProcess) + 0x448);

	for (PLIST_ENTRY node = ActiveProcessLinks; node && node->Flink != ActiveProcessLinks; node = node->Flink)
	{
		uint64_t eprocess = reinterpret_cast<uint64_t>(node) - 0x448;

		uint64_t file_object = *reinterpret_cast<uint64_t*>(eprocess + 0x5a0);

		if (!file_object)
			continue;

		PUNICODE_STRING file_name = reinterpret_cast<PUNICODE_STRING>(file_object + 0x58);

		if (!file_name->Buffer)
			continue;

		if (!_wcsicmp(file_name->Buffer, process_name))
			return reinterpret_cast<PEPROCESS>(eprocess);
	};

	return 0;
};


uint64_t get_kernel_module(const wchar_t* module_name)
{
	for (PLIST_ENTRY node = &PsLoadedModuleList->InLoadOrderLinks; node->Flink && node->Flink != &PsLoadedModuleList->InLoadOrderLinks; node = node->Flink)
	{
		PKLDR_DATA_TABLE_ENTRY loaded_module = reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(node);
		if (!loaded_module->DllBase)
			continue;

		if (!_wcsicmp(loaded_module->BaseDllName.Buffer, module_name))
			return reinterpret_cast<uint64_t>(loaded_module->DllBase);
	};

	return 0;
};

bool find_address_module(uint64_t address, UNICODE_STRING& module_name)
{
	for (PLIST_ENTRY node = &PsLoadedModuleList->InLoadOrderLinks; node->Flink && node->Flink != &PsLoadedModuleList->InLoadOrderLinks; node = node->Flink)
	{
		PKLDR_DATA_TABLE_ENTRY loaded_module = reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(node);
		if (!loaded_module->DllBase)
			continue;

		uint64_t start = reinterpret_cast<uint64_t>(loaded_module->DllBase);
		uint64_t end = start + loaded_module->SizeOfImage;

		if (address > start && address <= end)
		{
			module_name = loaded_module->BaseDllName;
			return true;
		}
	}

	return false;
}

PIMAGE_SECTION_HEADER get_image_section(uint64_t module_base, const char* section_name)
{
	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
	PIMAGE_NT_HEADERS nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base + dos_header->e_lfanew);

	PIMAGE_SECTION_HEADER section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header + 1);

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_header++)
	{
		if (!_stricmp(reinterpret_cast<const char*>(section_header->Name), section_name))
			return section_header;
	}

	return nullptr;
};

PIMAGE_DATA_DIRECTORY get_data_directory(uint64_t module_base, uint32_t index)
{
	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
	PIMAGE_NT_HEADERS nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base + dos_header->e_lfanew);

	return nt_header->OptionalHeader.DataDirectory + index;
}

uint64_t pattern_scan(uint64_t image_base, const char* section_name, const char* pattern, const char* mask)
{
	return pattern_scan(image_base, section_name, (unsigned const char*)pattern, mask); 
}

uint64_t pattern_scan(uint64_t image_base, const char* section_name, unsigned const char* pattern, const char* mask)
{
	if (!image_base || !section_name || !pattern || !mask)
		return 0;

	PIMAGE_SECTION_HEADER section = get_image_section(image_base, section_name);

	uint8_t* data = allocate_pool<uint8_t*>(NonPagedPool, section->SizeOfRawData);

	memcpy(data, reinterpret_cast<void*>(image_base + section->VirtualAddress), section->SizeOfRawData);

	for (uint32_t i = 0; i < section->SizeOfRawData; i++)
	{
		if (data[i] == pattern[0])
		{
			bool found = true;

			for (uint32_t j = 0; j < strlen(mask); j++)
			{
				if (mask[j] == 'x' && data[i + j] != pattern[j])
				{
					found = false;
					break;
				}
			}

			if (found)
			{
				ExFreePool(data);
				return image_base + section->VirtualAddress + i;
			}
		}
	}
	ExFreePool(data);
	return 0;
}

uint64_t resolve_rva(uint64_t instruction, uint64_t offset, uint64_t instruction_size)
{
	int32_t rip_offset = *(int32_t*)(instruction + offset);
	return instruction + instruction_size + rip_offset;
}

bool in_discardable_section(uint64_t module_base, uint64_t address)
{
	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
	PIMAGE_NT_HEADERS nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(module_base + dos_header->e_lfanew);

	PIMAGE_SECTION_HEADER section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header + 1);

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_header++)
	{
		uint64_t section_start = module_base + section_header->VirtualAddress;
		uint64_t section_end = section_start + section_header->SizeOfRawData;
		if (address >= section_start && address < section_end)
			break;
	}

	//IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
	if (section_header->Characteristics & 0x02000000)
		return true;

	return false;
}
