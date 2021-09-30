#pragma once
#include "typedefs.hpp"

#include <intrin.h>
#include <cstdint>

namespace hash {
inline constexpr size_t KERNEL32_DLL    {0xA2e88830c762342a};
inline constexpr size_t NTDLL_DLL       {0x82f80830ba02602c};

inline constexpr size_t LOAD_LIBRARY    {0xa9db4996f60be122};
inline constexpr size_t GET_PROC_ADDRESS{0x4b2197bfd5be9ce6};
inline constexpr size_t VIRTUAL_ALLOC   {0xa6ddc5a6ac02dad2};
inline constexpr size_t NT_FLUSH_ICACHE {0xb4a38ae3a399c7b2};

inline constexpr size_t KEY{13};

namespace details {
inline size_t rotr(size_t value, int32_t shift) noexcept {
#ifdef _M_AMD64
  return _rotr64(value, shift);
#elif defined _M_IX86
  return _rotr(value, shift);
#else
#error Unsupported architecture
#endif
}
}  // namespace details

struct case_insensitive_tag {};
};  // namespace hash

template <class Ty, class = void>
struct Hash;

template <>
struct Hash<const char*> {
  size_t operator()(const char* str) const noexcept {
    constexpr size_t factor{53};
    size_t result{0}, pow{1};
    for (size_t idx = 0; str[idx] != 0; ++idx) {
      result += (static_cast<size_t>(str[idx]) - 'a' + 1) * pow;
      pow *= factor;
    }
    return result;
  }
};

template <>
struct Hash<UNICODE_STRING> {
  size_t operator()(const UNICODE_STRING& str,
                      hash::case_insensitive_tag) const noexcept {
    size_t result{0};
    const auto* as_chars{reinterpret_cast<const char*>(str.Buffer)};
    for (size_t idx = 0; idx < str.Length; ++idx) {
      result = hash::details::rotr(result, hash::KEY);
      if (const auto ch = as_chars[idx]; ch >= 'a') {
        result += static_cast<size_t>(ch) - 0x20;
      } else {
        result += ch;
      }
    }
    return result;
  }
};