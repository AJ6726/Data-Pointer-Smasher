#include <ntifs.h>
#include "types.h"
#include "paging.h"
#include "pe.h"


uint32_t get_self_ref_index();
page_table* get_pte(uint64_t address);
page_directory* get_pde(uint64_t address);

PEPROCESS get_eprocess(const wchar_t* process_name);
uint64_t get_kernel_module(const wchar_t* module_name);
bool find_address_module(uint64_t address, UNICODE_STRING& module_name);

PIMAGE_SECTION_HEADER get_image_section(uint64_t module_base, const char* section_name);
PIMAGE_DATA_DIRECTORY get_data_directory(uint64_t module_base, uint32_t index);

uint64_t pattern_scan(uint64_t image_base, const char* section_name, const char* pattern, const char* mask);
uint64_t pattern_scan(uint64_t image_base, const char* section_name, unsigned const char* pattern, const char* mask);
uint64_t resolve_rva(uint64_t instruction, uint64_t offset, uint64_t instruction_size);

bool in_discardable_section(uint64_t module_base, uint64_t address); 
