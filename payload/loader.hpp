#pragma once
#include "attributes.hpp"

#include <windows.h>
#include <type_traits>

struct Kernel32 {
  using load_library_t = std::add_pointer_t<decltype(LoadLibraryA)>;
  using get_proc_addr_t = std::add_pointer_t<decltype(GetProcAddress)>;
  using virtual_alloc_t = std::add_pointer_t<decltype(VirtualAlloc)>;

  load_library_t load_library;
  get_proc_addr_t get_proc_addr;
  virtual_alloc_t virtual_alloc;
};

struct NtDll {
  using nt_flush_icache_t = DWORD(WINAPI*)(HANDLE, void*, unsigned long);
  nt_flush_icache_t flush_icache;
};

struct BasicFunctionSet {
  Kernel32 kernel32;
  NtDll ntdll;
};

DLLEXPORT DWORD WINAPI ReflectiveLoader(void* parameter) ;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void* reserved) ;