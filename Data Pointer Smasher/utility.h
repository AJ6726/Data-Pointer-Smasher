#include <ntifs.h>
#include "types.h"
#include "pe.h"

PIMAGE_SECTION_HEADER get_image_section(uint64_t module_base, const char* section_name);
PIMAGE_DATA_DIRECTORY get_data_directory(uint64_t module_base, uint32_t index);
uint64_t get_kernel_module(const wchar_t* module_name); 
bool find_address_module(uint64_t address, UNICODE_STRING& module_name); 
PEPROCESS get_eprocess(const wchar_t* process_name);
