#pragma once
#include <wil/resource.h>

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <optional>

#include <windows.h>

std::optional<int32_t> TryFindExportedEntry(const void* image_base,
                              std::string_view entry_name) noexcept;

wil::unique_handle OpenProcessById(uint32_t process_id, uint32_t access_mask);

void LoadRemoteLibrary(HANDLE target,
                       const std::byte* source,
                       size_t bytes_count,
                       size_t entry_point_offset,
                       void* entry_point_parameter);