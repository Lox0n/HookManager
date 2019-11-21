# HookManager
C++ Hook Manager, Detours and other types

##Easy to use hook manager, you just need to instantiate it or you can use it directly via Singleton.

######Via Singleton Example:

`
auto NtQueryVirtualMemory = PBYTE(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryVirtualMemory"));

oNtQueryVirtualMemory = (hNtQueryVirtualMemory)
		CHookManager::instance().InlineJump(NtQueryVirtualMemory, PBYTE(&hkNtQueryVirtualMemory));
`
    
######Instantiation Example:

`
CHookManager HookPresent(PBYTE(Device[17]), HOOK_TYPE::MOV_EAX);

if (HookPresent.Setup(PBYTE(&hkPresent), 8))
{
  oPresent = (hPresent)
      HookPresent.GetOriginal< hPresent >();
}
`

##Type of opcodes supported:

- JMP
- CALL
- MOV EAX 
