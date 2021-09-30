#include "attributes.hpp"
#include "loader.hpp"

#include <windows.h>


template <class Ty>
static NOINLINE Ty* print_addr(Ty* ptr) {
  __debugbreak();
  return ptr;
}

BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE instance,
                    DWORD reason,
                    [[maybe_unused]] void* reserved)  {
  if (reason == DLL_PROCESS_ATTACH) {
    print_addr(&MessageBoxA);
    MessageBoxA(nullptr, "Hello!", "Reflective DLL Injection", MB_OK);
  }
  return true;
}