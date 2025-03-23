#include "utility.h"
#include "nt.h"

extern "C" PKLDR_DATA_TABLE_ENTRY PsLoadedModuleList;

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
