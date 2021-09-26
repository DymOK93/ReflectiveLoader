#include "loader.hpp"

#include <intrin.h>

#pragma intrinsic(memcpy)
#pragma intrinsic(memcmp)
#pragma intrinsic(_ReturnAddress)

namespace details {
static NOINLINE const void* GetCaller() {
  return _ReturnAddress();
}

const IMAGE_DOS_HEADER* GetDosHeader(const void* image_base) {
  return static_cast<const IMAGE_DOS_HEADER*>(image_base);
}

const IMAGE_NT_HEADERS* GetNtHeader(const void* image_base) {
  const auto* image_base_byte_addr{static_cast<const std::byte*>(image_base)};
  return reinterpret_cast<const IMAGE_NT_HEADERS*>(
      image_base_byte_addr + GetDosHeader(image_base)->e_lfanew);
}

static void CopyMem(void* to, const void* from, size_t bytes_count) {
  memcpy(to, from, bytes_count);
}

static int CompareMem(const void* lhs, const void* rhs, size_t bytes_count) {
  const auto* lhs_ch{static_cast<const char*>(lhs)};
  const auto* rhs_ch{static_cast<const char*>(rhs)};
  while (bytes_count--) {
    if (*lhs_ch > *rhs_ch) {
      return 1;
    }
    if (*rhs_ch > *lhs_ch) {
      return -1;
    }
  }
  return 0;
}

static PPEB GetProcessEnvironmentBlock() {
#ifdef _M_AMD64
  return reinterpret_cast<PPEB>(__readgsqword(0x60));
#elif defined _M_IX86
  return reinterpret_cast<PPEB>(__readfsdword(0x30));
#else
#error Unsupported architecture
#endif
}

static const void* LocateImageBase() {
  const auto* current_addr{static_cast<const std::byte*>(GetCaller())};

  for (;;) {
    if (const auto* as_dos_header =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(current_addr);
        as_dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
      constexpr uint16_t nt_header_min_offset{sizeof(IMAGE_DOS_HEADER)},
          nt_header_max_offset{1024};

      if (const auto nt_header_offset = as_dos_header->e_lfanew;
          nt_header_offset >= nt_header_min_offset &&
          nt_header_offset < nt_header_max_offset) {
        if (const auto* nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                current_addr + nt_header_offset);
            nt_header->Signature == IMAGE_NT_SIGNATURE) {
          return current_addr;
        }
      }
    }
    --current_addr;
  }
}

template <size_t N>
bool IsEqualUnicodeStr(const UNICODE_STRING& str,
                       const wchar_t (&expected)[N]) {
  const size_t length_in_bytes{(N - 1) * sizeof(wchar_t)};
  if (length_in_bytes != str.Length) {
    return false;
  }
  return CompareMem(str.Buffer, expected, length_in_bytes) == 0;
}

template <size_t N>
bool IsEqualCStr(const char* str, const char (&expected)[N]) {
  size_t idx{0};
  for (; idx + 1 < N && str[idx]; ++idx) {
    if (str[idx] != expected[idx]) {
      return false;
    }
  }
  return idx + 1 == N;
}

template <class FnPtrTy, size_t N>
FnPtrTy LoadProcAddress(const void* image_base, const char (&fn_name)[N]) {
  const auto* image_base_byte_addr{static_cast<const std::byte*>(image_base)};
  const auto* nt_header{GetNtHeader(image_base)};

  const auto* raw_export_names{reinterpret_cast<const std::byte*>(
      nt_header->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT)};

  const auto* export_dir{reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
      image_base_byte_addr +
      reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(raw_export_names)
          ->VirtualAddress)};

  const auto* export_names{reinterpret_cast<const DWORD*>(
      image_base_byte_addr + export_dir->AddressOfNames)};

  const auto* name_ordinals{reinterpret_cast<const DWORD*>(
      image_base_byte_addr + export_dir->AddressOfNameOrdinals)};

  for (size_t idx = 0; idx < export_dir->NumberOfNames;
       ++idx, ++export_names, ++name_ordinals) {
    const auto* raw_exported_name{image_base_byte_addr + *export_names};

    if (const auto* exported_name =
            reinterpret_cast<const char*>(raw_exported_name);
        IsEqualCStr(exported_name, fn_name)) {
      const auto* functions{image_base_byte_addr +
                            export_dir->AddressOfFunctions};
      const auto* entry_ptr{reinterpret_cast<const DWORD*>(
          functions + LOWORD(name_ordinals) * sizeof(DWORD))};

      return reinterpret_cast<FnPtrTy>(image_base_byte_addr + *entry_ptr);
    }
  }
  return nullptr;
}

Kernel32 FillKernel32Imports(const LDR_DATA_TABLE_ENTRY& dll) {
  return {
      LoadProcAddress<Kernel32::load_library_t>(dll.DllBase, "LoadLibraryA"),
      LoadProcAddress<Kernel32::get_proc_addr_t>(dll.DllBase, "GetProcAddress"),
      LoadProcAddress<Kernel32::virtual_alloc_t>(dll.DllBase, "VirtualAlloc"),
  };
}

NtDll FillNtDllImports(const LDR_DATA_TABLE_ENTRY& dll) {
  return {LoadProcAddress<NtDll::nt_flush_icache_t>(dll.DllBase,
                                                    "NtFlushInstructionCache")};
}

BasicFunctionSet GetBasicFunctionSet(PPEB peb) {
  BasicFunctionSet basic_set{};

  const auto* peb_ldr_data{peb->pLdr};

  const auto& module_list{peb_ldr_data->InMemoryOrderModuleList};
  for (const auto* entry = module_list.Flink; entry != &module_list;
       entry = entry->Flink) {
    const auto* dynamic_library{
        reinterpret_cast<const LDR_DATA_TABLE_ENTRY*>(entry)};

    if (const UNICODE_STRING& base_dll_name = dynamic_library->BaseDllName;
        IsEqualUnicodeStr(base_dll_name, L"kernel32.dll")) {
      basic_set.kernel32 = FillKernel32Imports(*dynamic_library);
    } else if (IsEqualUnicodeStr(base_dll_name, L"ntdll.dll")) {
      basic_set.ntdll = FillNtDllImports(*dynamic_library);
    }
  }
  return basic_set;
}

void ReloadImage(void* new_base,
                 const void* image_base,
                 const IMAGE_NT_HEADERS& nt_header) {
  const auto* image_base_byte_addr{static_cast<const std::byte*>(image_base)};

  const auto& optional_header{nt_header.OptionalHeader};
  CopyMem(new_base, image_base, optional_header.SizeOfHeaders);

  const auto& file_header{nt_header.FileHeader};
  const auto* section_entry{
      reinterpret_cast<const IMAGE_SECTION_HEADER*>(&optional_header) +
      file_header.SizeOfOptionalHeader};

  for (size_t idx = 0; idx < file_header.NumberOfSections;
       ++idx, ++section_entry) {
    auto* virtual_addr{static_cast<std::byte*>(new_base) +
                       section_entry->VirtualAddress};
    const auto* raw_data{image_base_byte_addr +
                         section_entry->PointerToRawData};
    CopyMem(virtual_addr, raw_data, section_entry->SizeOfRawData);
  }
}

void ResolveImports(void* reloaded_image_base,
                    const IMAGE_NT_HEADERS& nt_header,
                    Kernel32::load_library_t dll_loader,
                    Kernel32::get_proc_addr_t fn_extractor) {
  auto* image_base_byte_addr{static_cast<std::byte*>(reloaded_image_base)};
  const auto* import_dir{nt_header.OptionalHeader.DataDirectory +
                         IMAGE_DIRECTORY_ENTRY_IMPORT};

  const auto* import_descriptor{
      reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
          image_base_byte_addr + import_dir->VirtualAddress)};

  while (import_descriptor->Name) {
    const auto* dll_name{reinterpret_cast<const char*>(
        image_base_byte_addr + import_descriptor->Name)};
    auto library_addr{reinterpret_cast<std::byte*>(dll_loader(dll_name))};

    auto* orig_first_thunk{reinterpret_cast<const IMAGE_THUNK_DATA*>(
        image_base_byte_addr + import_descriptor->OriginalFirstThunk)};
    auto* iat_first_thunk{reinterpret_cast<ULONG_PTR*>(
        image_base_byte_addr + import_descriptor->OriginalFirstThunk)};

    while (*iat_first_thunk) {
      if (orig_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        const auto* raw_export_names{reinterpret_cast<const std::byte*>(
            nt_header.OptionalHeader.DataDirectory +
            IMAGE_DIRECTORY_ENTRY_EXPORT)};

        const auto* export_dir{reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            image_base_byte_addr +
            reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(raw_export_names)
                ->VirtualAddress)};

        const auto* functions{image_base_byte_addr +
                              export_dir->AddressOfFunctions};

        const auto* entry_ptr{reinterpret_cast<const DWORD*>(
            functions + IMAGE_ORDINAL(orig_first_thunk->u1.Ordinal) -
            export_dir->Base * sizeof(DWORD))};

        *iat_first_thunk =
            reinterpret_cast<ULONG_PTR>(library_addr + *entry_ptr);
      } else {
        const auto* import_name{reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
            image_base_byte_addr + *iat_first_thunk)};
        *iat_first_thunk = reinterpret_cast<ULONG_PTR>(fn_extractor(
            reinterpret_cast<HMODULE>(library_addr), import_name->Name));
      }
      ++iat_first_thunk;

      auto* raw_orig_next_thunk{
          reinterpret_cast<const std::byte*>(orig_first_thunk) +
          sizeof(ULONG_PTR)};
      orig_first_thunk =
          reinterpret_cast<const IMAGE_THUNK_DATA*>(raw_orig_next_thunk);
    }
    ++import_descriptor;
  }
}

void RelocateIfNeeded(void* reloaded_image_base,
                      const IMAGE_NT_HEADERS& nt_header) {
  auto* image_base_byte_addr{static_cast<std::byte*>(reloaded_image_base)};
  const auto relocation_delta{
      image_base_byte_addr -
      reinterpret_cast<const std::byte*>(nt_header.OptionalHeader.ImageBase)};

  if (const auto* relocation_data_dir = nt_header.OptionalHeader.DataDirectory +
                                        IMAGE_DIRECTORY_ENTRY_BASERELOC;
      relocation_data_dir->Size > 0) {
    const auto* relocation_block{reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
        image_base_byte_addr + relocation_data_dir->VirtualAddress)};

    while (relocation_block->SizeOfBlock) {
      auto* relocation_target{image_base_byte_addr +
                              relocation_block->VirtualAddress};

      size_t entry_count{relocation_block->SizeOfBlock -
                         sizeof(IMAGE_BASE_RELOCATION) / sizeof(IMAGE_RELOC)};

      const auto* raw_relocation_block{
          reinterpret_cast<const std::byte*>(relocation_block)};
      const auto* relocation_entry{reinterpret_cast<const IMAGE_RELOC*>(
          raw_relocation_block + sizeof(IMAGE_BASE_RELOCATION))};

      while (entry_count--) {
        if (relocation_entry->type == IMAGE_REL_BASED_DIR64) {
          auto* cell{reinterpret_cast<ULONG_PTR*>(relocation_target +
                                                  relocation_entry->offset)};
          *cell += relocation_delta;
        } else if (relocation_entry->type == IMAGE_REL_BASED_HIGHLOW) {
          auto* cell{reinterpret_cast<DWORD*>(relocation_target +
                                              relocation_entry->offset)};
          *cell += static_cast<DWORD>(relocation_delta);

        } else if (relocation_entry->type == IMAGE_REL_BASED_HIGH) {
          auto* cell{reinterpret_cast<WORD*>(relocation_target +
                                             relocation_entry->offset)};
          *cell += HIWORD(relocation_delta);
        } else if (relocation_entry->type == IMAGE_REL_BASED_LOW) {
          auto* cell{reinterpret_cast<WORD*>(relocation_target +
                                             relocation_entry->offset)};
          *cell += LOWORD(relocation_delta);
        }
        ++relocation_entry;
      }

      raw_relocation_block += relocation_block->SizeOfBlock;
      relocation_block =
          reinterpret_cast<const IMAGE_BASE_RELOCATION*>(raw_relocation_block);
    }
  }
}
}  // namespace details

DLLEXPORT DWORD WINAPI ReflectiveLoader(void* parameter) {
  const auto* image_base{details::LocateImageBase()};

  const PPEB peb{details::GetProcessEnvironmentBlock()};
  const auto [kernel32, ntdll]{details::GetBasicFunctionSet(peb)};

  const auto* nt_header{details::GetNtHeader(image_base)};
  void* new_base{
      kernel32.virtual_alloc(nullptr, nt_header->OptionalHeader.SizeOfImage,
                             MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
  // details::ReloadImage(new_base, image_base, *nt_header);
  // details::ResolveImports(new_base, *nt_header, kernel32.load_library,
  //                        kernel32.get_proc_addr);
  // details::RelocateIfNeeded(new_base, *nt_header);

  // const auto process_handle{reinterpret_cast<HANDLE>(-1)};
  // ntdll.flush_icache(process_handle, nullptr, 0);

  // return DllMain(static_cast<HINSTANCE>(parameter), DLL_PROCESS_ATTACH,
  //               nullptr);
  return 0;
}