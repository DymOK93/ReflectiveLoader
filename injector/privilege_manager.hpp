#pragma once
#include <wil/resource.h>

#include <comdef.h>

namespace winapi {
class PrivilegeManager {
 public:
  static PrivilegeManager& GetInstance();

  PrivilegeManager& GetPrivileges(const char* privilege_request);

 private:
  PrivilegeManager();

  static TOKEN_PRIVILEGES setup_privileges_request(const char* privilege_request);

  static wil::unique_handle open_current_process_token();

  static void adjust_token_privileges(HANDLE raw_access_token,
                                      TOKEN_PRIVILEGES& new_privileges);

 private:
  wil::unique_handle m_token; 
};
}  // namespace winapi