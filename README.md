# Data Pointer Smasher
DPM is a kernel driver the scans for data pointers in various window drivers. 

### What is a "Data Pointer" and Control Flow Guard (CFG)
Data pointer is the common term for any function pointer that resides in a data section. Examples are the .data and .rdata sections. They are commonly overridden to redirect control flow, aka a hook. <br>
Control Flow Guard is a security mechanism by windows to protect indirect branches from a speculative execution attack. The following readings are optional: https://powerofcommunity.net/poc2014/mj0011.pdf | https://dl.acm.org/doi/pdf/10.1145/3664476.3670432

### How it works
1. Pattern scan for instructions that call the guard_dispatch_icall function, and resolve the call to get the guard_dispatch_icall function address. 
2. Find the start and end of every function using the RUNTIME_FUNCTION structure available in the .pdata section.
3. Analyzed the function with Zydis to find calls to guard_dispatch_icall, and if found, is stored in a link list.
4. The hopefully populated link list of functions is traversed and analyzed to find any instruction that preform a mov rax, [rip + offset].
5. The load address is resolved and checked to be within the module data section and dereferenced if so. 
6. The dereferenced data is treated as an address and checked to be in executable memory and in a module. If so, it is probably a function pointer. 

### Why this approach? 
A lot of snooping around and I found that functions protected by control flow guard usually referenced a overwritable function pointer aka data pointers. 

<details>
<summary>Click to see code</summary>
  
### Checks for the prescence of guard_dispatch_icall in a function
```c++
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
```
### Checks for the prescence of mov rax instructions and introspection of the load address
```c++
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

bool in_writable_section = false; 
page_directory* pde = get_pde(mov_target); 

if (pde->large_page)
	in_writable_section = pde->large.read_write;
else
{
	page_table* pte = get_pte(mov_target);
	in_writable_section = pte->read_write;
}

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
pde = get_pde(function_ptr);

if (pde->large_page)
	no_execute = pde->large.no_execute;
else
{
	page_table* pte = get_pte(function_ptr);
	no_execute = pte->no_execute;
}

if (no_execute)
	continue;


```

</details>

### Tested Versions
-Windows 10 Version 22H2

Works with kdmapper

Update/check signatures in module_metadata.h to support other versions

### List of scanned drivers
- ntoskrnl
- win32kbase
- win32k
- win32kfull
- dxgkrnl

To add more drivers, add the name of the driver and signatures needed for the guard_dispatch_icall function in the module_metadata.h.

# Output Examples
### ntoskrnl
![image](https://github.com/user-attachments/assets/9a91dc0c-f50d-4b32-9f77-f3d5f578522a)

### win32kbase 
![image](https://github.com/user-attachments/assets/b713f164-6a8a-4b49-ab39-847279e914e1)

# Problems 
1. The only scanned cfg function is guard_dispatch_icall, there are quite a few other cfg functions but guard_dispatch_icall has been the most used as far I've seen in window drivers.
3. Dxgkrnl presents a lot of mov from registers, only mov with relative addressing are checked.
4. Apart from ntoskrnl, on disk you'll see functions call guard_dispatch_icall_fptr. However, in memory those calls are patched to guard_dispatch_icall, and this is relevent as the type of the calls themselves change from indirect to direct (FF 15 to E8). <br>
   This requires patterns for the instructions AROUND the guard_dispatch_icall_fptr call. 




