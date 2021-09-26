#pragma once
#include <string>

#include <windows.h>

#define NOINLINE __declspec(noinline)
#define FORCEINLINE __forceinline

template <class Exc, class... Types>
[[noreturn]] NOINLINE void ThrowException(const Types&... args) {
  throw Exc{args...};
}

template <class Exc, class U, class... Types>
FORCEINLINE void ThrowExceptionIf(const U& cond, const Types&... args) {
  if (cond) {
    ThrowException<Exc>(args...);
  }
}

template <class Exc, class U, class... Types>
FORCEINLINE void ThrowExceptionIfNot(const U& cond, const Types&... args) {
  if (!cond) {
    ThrowException<Exc>(args...);
  }
}

inline std::string FormatWithLastError(const char* msg) {
  std::string str{msg};
  str += " [Last error: ";
  str += std::to_string(GetLastError());
  str += "]";
  return str;
}

#undef FORCEINLINE
#undef NOINLINE