#include "attributes.hpp"
#include "loader.hpp"

#include <windows.h>

BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE instance,
                    DWORD reason,
                    [[maybe_unused]] void* reserved)  {
  if (reason == DLL_PROCESS_ATTACH) {
    MessageBoxA(nullptr, "Hello!", "Reflective DLL Injection", MB_OK);
  }
  return true;
}