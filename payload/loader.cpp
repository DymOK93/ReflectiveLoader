#include "loader.hpp"
#include "hash.hpp"
#include "typedefs.hpp"

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
  for (const auto* current_addr = static_cast<const std::byte*>(GetCaller());
       ;) {
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

template <class Ty>
static NOINLINE Ty* print_addr(Ty* ptr) {
  __debugbreak();
  return ptr;
}

template <class FnPtrTy>
FnPtrTy LoadProcAddressByHash(const void* image_base, size_t fn_hash) {
  const auto* image_base_byte_addr{static_cast<const std::byte*>(image_base)};
  const auto* nt_header{GetNtHeader(image_base)};

  const auto* raw_exports{nt_header->OptionalHeader.DataDirectory +
                          IMAGE_DIRECTORY_ENTRY_EXPORT};

  const auto* export_dir{reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
      image_base_byte_addr + raw_exports->VirtualAddress)};

  const auto* export_names{reinterpret_cast<const DWORD*>(
      image_base_byte_addr + export_dir->AddressOfNames)};

  const auto* name_ordinals{reinterpret_cast<const WORD*>(
      image_base_byte_addr + export_dir->AddressOfNameOrdinals)};

  const auto* functions{image_base_byte_addr + export_dir->AddressOfFunctions};

  constexpr auto hash_comparator{[](const char* target, size_t expected) {
    const size_t result{Hash<const char*>{}(target)};
    return result == expected;
  }};

  for (size_t idx = 0; idx < export_dir->NumberOfNames; ++idx) {
    const auto* raw_exported_name{image_base_byte_addr + *export_names};

    if (const auto* exported_name =
            reinterpret_cast<const char*>(raw_exported_name);
        hash_comparator(exported_name, fn_hash)) {
      const auto* entry_ptr{reinterpret_cast<const DWORD*>(
          functions + *name_ordinals * sizeof(DWORD))};

      return reinterpret_cast<FnPtrTy>(image_base_byte_addr + *entry_ptr);
    }

    ++export_names;
    ++name_ordinals;
  }
  return nullptr;
}

BasicFunctionSet GetBasicFunctionSet(PPEB peb) {
  BasicFunctionSet basic_set{};

  const auto* peb_ldr_data{peb->pLdr};
  const auto& module_list{peb_ldr_data->InMemoryOrderModuleList};

  for (const auto* entry = module_list.Flink; entry != &module_list;
       entry = entry->Flink) {
    const auto* dynamic_library{CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY,
                                                  InMemoryOrderModuleList)};
    constexpr auto hash_comparator{
        [](const UNICODE_STRING& target, size_t expected) {
          const size_t result{
              Hash<UNICODE_STRING>{}(target, hash::case_insensitive_tag{})};
          return result == expected;
        }};

    if (const UNICODE_STRING& base_dll_name = dynamic_library->BaseDllName;
        hash_comparator(base_dll_name, hash::NTDLL_DLL)) {
      basic_set.ntdll = {LoadProcAddressByHash<NtDll::nt_flush_icache_t>(
          dynamic_library->DllBase, hash::NT_FLUSH_ICACHE)};

    } else if (hash_comparator(base_dll_name, hash::KERNEL32_DLL)) {
      basic_set.kernel32 = {
          LoadProcAddressByHash<Kernel32::load_library_t>(
              dynamic_library->DllBase, hash::LOAD_LIBRARY),
          LoadProcAddressByHash<Kernel32::get_proc_addr_t>(
              dynamic_library->DllBase, hash::GET_PROC_ADDRESS),
          LoadProcAddressByHash<Kernel32::virtual_alloc_t>(
              dynamic_library->DllBase, hash::VIRTUAL_ALLOC),
      };
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
  const auto* raw_section_entry{
      reinterpret_cast<const std::byte*>(&optional_header) +
      file_header.SizeOfOptionalHeader};
  const auto* section_entry{
      reinterpret_cast<const IMAGE_SECTION_HEADER*>(raw_section_entry)};

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
  /* auto* image_base_byte_addr{static_cast<std::byte*>(reloaded_image_base)};
   const auto* import_dir{nt_header.OptionalHeader.DataDirectory +
                          IMAGE_DIRECTORY_ENTRY_IMPORT};

   const auto* import_descriptor{
       reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
           image_base_byte_addr + import_dir->VirtualAddress)};

   while (import_descriptor->Name) {
     const auto* dll_name{reinterpret_cast<const char*>(
         image_base_byte_addr + import_descriptor->Name)};
     const auto dll_body_addr{
         reinterpret_cast<std::byte*>(dll_loader(dll_name))};

     auto* orig_first_thunk{reinterpret_cast<const IMAGE_THUNK_DATA*>(
         image_base_byte_addr + import_descriptor->OriginalFirstThunk)};
     auto* iat_first_thunk{reinterpret_cast<ULONG_PTR*>(
         image_base_byte_addr + import_descriptor->FirstThunk)};

     while (*iat_first_thunk) {
       const auto* fn_name{reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
           image_base_byte_addr + *iat_first_thunk)};

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
             functions +
             (IMAGE_ORDINAL(orig_first_thunk->u1.Ordinal) - export_dir->Base) *
                 sizeof(DWORD))};

         *iat_first_thunk =
             reinterpret_cast<ULONG_PTR>(dll_body_addr + *entry_ptr);
       } else {
         const auto* import_name{reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
             image_base_byte_addr + *iat_first_thunk)};
         *iat_first_thunk = reinterpret_cast<ULONG_PTR>(fn_extractor(
             reinterpret_cast<HMODULE>(dll_body_addr), import_name->Name));
       }
       ++iat_first_thunk;

       auto* raw_orig_next_thunk{
           reinterpret_cast<const std::byte*>(orig_first_thunk) +
           sizeof(ULONG_PTR)};
       orig_first_thunk =
           reinterpret_cast<const IMAGE_THUNK_DATA*>(raw_orig_next_thunk);
     }
     ++import_descriptor;
   }*/

#define DEREF(v) *(ULONG_PTR*)(v)
#define DEREF_32(v) *(DWORD*)(v)

  auto uiBaseAddress = (ULONG_PTR)reloaded_image_base;
  auto uiHeaderValue = (ULONG_PTR)&nt_header;
  auto uiLibraryAddress =
      uiBaseAddress -
      ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

  ULONG_PTR uiValueA, uiValueB, uiValueC, uiValueD, uiNameArray, uiExportDir,
      uiAddressArray;

  uiValueB = (ULONG_PTR) &
             ((PIMAGE_NT_HEADERS)uiHeaderValue)
                 ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  // we assume their is an import table to process
  // uiValueC is the first entry in the import table
  uiValueC =
      (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

  // itterate through all imports
  while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name) {
    // use LoadLibraryA to load the imported module into memory
    uiLibraryAddress = (ULONG_PTR)dll_loader(
        (LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

    // uiValueD = VA of the OriginalFirstThunk
    uiValueD = (uiBaseAddress +
                ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

    // uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
    uiValueA =
        (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

    // itterate through all imported functions, importing by ordinal if no name
    // present
    while (DEREF(uiValueA)) {
      // sanity check uiValueD as some compilers only import by FirstThunk
      if (uiValueD &&
          ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        // get the VA of the modules NT Header
        uiExportDir =
            uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

        // uiNameArray = the address of the modules export directory entry
        uiNameArray =
            (ULONG_PTR) &
            ((PIMAGE_NT_HEADERS)uiExportDir)
                ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        // get the VA of the export directory
        uiExportDir = (uiLibraryAddress +
                       ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

        // get the VA for the array of addresses
        uiAddressArray =
            (uiLibraryAddress +
             ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

        // use the import ordinal (- export ordinal base) as an index into the
        // array of addresses
        uiAddressArray +=
            ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) -
              ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) *
             sizeof(DWORD));

        // patch in the address for this imported function
        DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
      } else {
        // get the VA of this functions import by name struct
        uiValueB = (uiBaseAddress + DEREF(uiValueA));

        // use GetProcAddress and patch in the address for this imported
        // function
        DEREF(uiValueA) = (ULONG_PTR)fn_extractor(
            (HMODULE)uiLibraryAddress,
            (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
      }
      // get the next imported function
      uiValueA += sizeof(ULONG_PTR);
      if (uiValueD)
        uiValueD += sizeof(ULONG_PTR);
    }

    // get the next import
    uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
  }
}

void RelocateIfNeeded(void* reloaded_image_base,
                      const IMAGE_NT_HEADERS& nt_header) {
  // auto* image_base_byte_addr{static_cast<std::byte*>(reloaded_image_base)};
  // const auto relocation_delta{
  //    image_base_byte_addr -
  //    reinterpret_cast<const std::byte*>(nt_header.OptionalHeader.ImageBase)};

  // if (const auto* relocation_data_dir =
  // nt_header.OptionalHeader.DataDirectory +
  //                                      IMAGE_DIRECTORY_ENTRY_BASERELOC;
  //    relocation_data_dir->Size > 0) {
  //  const auto* relocation_block{reinterpret_cast<const
  //  IMAGE_BASE_RELOCATION*>(
  //      image_base_byte_addr + relocation_data_dir->VirtualAddress)};

  //  while (relocation_block->SizeOfBlock) {
  //    auto* relocation_target{image_base_byte_addr +
  //                            relocation_block->VirtualAddress};

  //    size_t entry_count{relocation_block->SizeOfBlock -
  //                       sizeof(IMAGE_BASE_RELOCATION) / sizeof(IMAGE_RELOC)};

  //    const auto* raw_relocation_block{
  //        reinterpret_cast<const std::byte*>(relocation_block)};
  //    const auto* relocation_entry{reinterpret_cast<const IMAGE_RELOC*>(
  //        raw_relocation_block + sizeof(IMAGE_BASE_RELOCATION))};

  //    while (entry_count--) {
  //      if (relocation_entry->type == IMAGE_REL_BASED_DIR64) {
  //        auto* cell{reinterpret_cast<ULONG_PTR*>(relocation_target +
  //                                                relocation_entry->offset)};
  //        *cell += relocation_delta;
  //      } else if (relocation_entry->type == IMAGE_REL_BASED_HIGHLOW) {
  //        auto* cell{reinterpret_cast<DWORD*>(relocation_target +
  //                                            relocation_entry->offset)};
  //        *cell += static_cast<DWORD>(relocation_delta);

  //      } else if (relocation_entry->type == IMAGE_REL_BASED_HIGH) {
  //        auto* cell{reinterpret_cast<WORD*>(relocation_target +
  //                                           relocation_entry->offset)};
  //        *cell += HIWORD(relocation_delta);
  //      } else if (relocation_entry->type == IMAGE_REL_BASED_LOW) {
  //        auto* cell{reinterpret_cast<WORD*>(relocation_target +
  //                                           relocation_entry->offset)};
  //        *cell += LOWORD(relocation_delta);
  //      }
  //      ++relocation_entry;
  //    }

  //    raw_relocation_block += relocation_block->SizeOfBlock;
  //    relocation_block =
  //        reinterpret_cast<const
  //        IMAGE_BASE_RELOCATION*>(raw_relocation_block);
  //  }
  //}

  auto uiBaseAddress = (ULONG_PTR)reloaded_image_base;
  auto uiHeaderValue = (ULONG_PTR)&nt_header;
  auto uiLibraryAddress =
      uiBaseAddress -
      ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

  ULONG_PTR uiValueA, uiValueB, uiValueC, uiValueD;

  // uiValueB = the address of the relocation directory
  uiValueB =
      (ULONG_PTR) &
      ((PIMAGE_NT_HEADERS)uiHeaderValue)
          ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    print_addr((void*)uiBaseAddress);
    print_addr((void*)((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase);
    print_addr((void*)((PIMAGE_DATA_DIRECTORY)uiValueB)->Size);

  // check if their are any relocations present
  if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size) {
    // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
    uiValueC =
        (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

    // and we itterate through all entries...
    while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock) {
      // uiValueA = the VA for this relocation block
      uiValueA =
          (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

      // uiValueB = number of entries in this relocation block
      uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock -
                  sizeof(IMAGE_BASE_RELOCATION)) /
                 sizeof(IMAGE_RELOC);

      // uiValueD is now the first entry in the current relocation block
      uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

      // we itterate through all the entries in the current block...
      while (uiValueB--) {
        // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as
        // required. we dont use a switch statement to avoid the compiler
        // building a jump table which would not be very position independent!
        if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
          *(ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) +=
              uiLibraryAddress;
        else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
          *(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) +=
              (DWORD)uiLibraryAddress;
        else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
          *(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) +=
              HIWORD(uiLibraryAddress);
        else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
          *(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) +=
              LOWORD(uiLibraryAddress);

        // get the next entry in the current relocation block
        uiValueD += sizeof(IMAGE_RELOC);
      }

      // get the next entry in the relocation directory
      uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
    }
  }
}
}  // namespace details

DLLEXPORT DWORD WINAPI ReflectiveLoader(void* parameter) {
  const auto* image_base{details::LocateImageBase()};

  PPEB peb{details::GetProcessEnvironmentBlock()};

  const auto [kernel32, ntdll]{details::GetBasicFunctionSet(peb)};

  const auto* nt_header{details::GetNtHeader(image_base)};
  void* new_base{
      kernel32.virtual_alloc(nullptr, nt_header->OptionalHeader.SizeOfImage,
                             MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};
  details::ReloadImage(new_base, image_base, *nt_header);

  details::ResolveImports(new_base, *nt_header, kernel32.load_library,
                          kernel32.get_proc_addr);
  details::RelocateIfNeeded(new_base, *nt_header);

  const auto entry_point{reinterpret_cast<entry_point_t>(
      static_cast<std::byte*>(new_base) +
      nt_header->OptionalHeader.AddressOfEntryPoint)};

  const auto process_handle{reinterpret_cast<HANDLE>(-1)};
  ntdll.flush_icache(process_handle, nullptr, 0);

  details::print_addr(entry_point);

  return entry_point(static_cast<HINSTANCE>(parameter), DLL_PROCESS_ATTACH,
                     nullptr);
}