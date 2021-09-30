#pragma once
#include <intrin.h>
#include <cstdint>

namespace hash {
inline constexpr uint32_t KERNEL32_DLL{0x6A4ABC5B};
inline constexpr uint32_t NTDLL_DLL{0x3CFA685D};

inline constexpr uint32_t LOAD_LIBRARY{0xEC0E4E8E};
inline constexpr uint32_t GET_PROC_ADDRESS{0x7C0DFCAA};
inline constexpr uint32_t VIRTUAL_ALLOC{0x91AFCA54};
inline constexpr uint32_t NT_FLUSH_ICACHE{0x534C0AB8};

inline constexpr uint32_t KEY{13};

namespace details {
uint32_t rotr(uint32_t value, _In_ int32_t shift) noexcept {
  return _rotr(value, shift);
}
}  // namespace details

struct case_insensitive_tag {};
};  // namespace hash

template <class Ty, class = void>
struct Hash;

template <>
struct Hash<const char*> {
  uint32_t operator()(const char* str) const noexcept {
    uint32_t result{0};
    for (size_t idx = 0; str[idx] != 0; ++idx) {
      result = hash::details::rotr(result, hash::KEY);
      result += *str;
    }
    return result;
  }

  uint32_t operator()(const char* str, size_t length) const noexcept {
    uint32_t result{0};
    for (size_t idx = 0; idx < length; ++idx) {
      result = hash::details::rotr(result, hash::KEY);
      result += *str;
    }
    return result;
  }
};

template <>
struct Hash<UNICODE_STRING> {
  uint32_t operator()(const UNICODE_STRING& str) const noexcept {
    const auto* as_chars{reinterpret_cast<const char*>(str.Buffer)};
    return Hash<const char*>{}(as_chars, str.Length);
  }

  uint32_t operator()(const UNICODE_STRING& str,
                      hash::case_insensitive_tag) const noexcept {
    uint32_t result{0};
    const auto* as_chars{reinterpret_cast<const char*>(str.Buffer)};
    for (size_t idx = 0; idx < str.Length; ++idx) {
      result = hash::details::rotr(result, hash::KEY);
      if (const auto ch = as_chars[idx]; ch >= 'a') {
        result += ch - 0x20;
      } else {
        result += ch;
      }
    }
    return result;
  }
};