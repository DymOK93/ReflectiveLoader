#include "privilege_manager.hpp"

#include <stdexcept>
#include <string>

using namespace std;

namespace winapi {
PrivilegeManager& PrivilegeManager::GetInstance() {
  static PrivilegeManager acm;  // Scott Meyers' singletone
  return acm;
}

PrivilegeManager::PrivilegeManager() : m_token{open_current_process_token()} {}

PrivilegeManager& PrivilegeManager::GetPrivileges(
    const char* privilege_request) {
  auto request{setup_privileges_request(privilege_request)};
  adjust_token_privileges(m_token.get(), request);
  return *this;
}

TOKEN_PRIVILEGES PrivilegeManager::setup_privileges_request(
    const char* privilege_request) {
  TOKEN_PRIVILEGES token_privileges{};
  if (!LookupPrivilegeValueA(
          nullptr,                                           /*Local PC*/
          privilege_request,                                 /*Privilege name*/
          addressof(token_privileges.Privileges[0].Luid))) { /*Luid*/
    throw runtime_error("Privilege value lookup has been failed");
  }
  token_privileges.PrivilegeCount = 1;
  token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  return token_privileges;
}

wil::unique_handle PrivilegeManager::open_current_process_token() {
  HANDLE process_token{nullptr};
  if (!OpenProcessToken(GetCurrentProcess(),  // Always -1 (0xFFFFFFFF)
                        TOKEN_ALL_ACCESS_P, addressof(process_token))) {
    throw runtime_error("Unable to open process token");
  }
  return wil::unique_handle{process_token};
}

void PrivilegeManager::adjust_token_privileges(
    HANDLE raw_access_token,
    TOKEN_PRIVILEGES& new_privileges) {
  if (!AdjustTokenPrivileges(raw_access_token, FALSE, addressof(new_privileges),
                             0, nullptr, nullptr)) {
    throw runtime_error("Token privilege adjustment denied");
  }
}
}  // namespace winapi
