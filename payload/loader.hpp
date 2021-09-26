#pragma once
#include "attributes.hpp"

#include <windows.h>
#include <type_traits>

struct Kernel32 {
  using load_library_t = std::add_pointer_t<decltype(LoadLibraryA)>;
  using get_proc_addr_t = std::add_pointer_t<decltype(GetProcAddress)>;
  using virtual_alloc_t = std::add_pointer_t<decltype(VirtualAlloc)>;

  load_library_t load_library;
  get_proc_addr_t get_proc_addr;
  virtual_alloc_t virtual_alloc;
};

struct NtDll {
  using nt_flush_icache_t = DWORD(WINAPI*)(HANDLE, void*, unsigned long);
  nt_flush_icache_t flush_icache;
};

struct BasicFunctionSet {
  Kernel32 kernel32;
  NtDll ntdll;
};

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  SHORT LoadCount;
  SHORT TlsIndex;
  LIST_ENTRY HashTableEntry;
  ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA  //, 7 elements, 0x28 bytes
{
  DWORD dwLength;
  DWORD dwInitialized;
  LPVOID lpSsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK  // 2 elements, 0x8 bytes
{
  struct _PEB_FREE_BLOCK* pNext;
  DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

// WinDbg> dt -v ntdll!_PEB
typedef struct _PEB  // 65 elements, 0x210 bytes
{
  BYTE bInheritedAddressSpace;
  BYTE bReadImageFileExecOptions;
  BYTE bBeingDebugged;
  BYTE bSpareBool;
  LPVOID lpMutant;
  LPVOID lpImageBaseAddress;
  PPEB_LDR_DATA pLdr;
  LPVOID lpProcessParameters;
  LPVOID lpSubSystemData;
  LPVOID lpProcessHeap;
  PRTL_CRITICAL_SECTION pFastPebLock;
  LPVOID lpFastPebLockRoutine;
  LPVOID lpFastPebUnlockRoutine;
  DWORD dwEnvironmentUpdateCount;
  LPVOID lpKernelCallbackTable;
  DWORD dwSystemReserved;
  DWORD dwAtlThunkSListPtr32;
  PPEB_FREE_BLOCK pFreeList;
  DWORD dwTlsExpansionCounter;
  LPVOID lpTlsBitmap;
  DWORD dwTlsBitmapBits[2];
  LPVOID lpReadOnlySharedMemoryBase;
  LPVOID lpReadOnlySharedMemoryHeap;
  LPVOID lpReadOnlyStaticServerData;
  LPVOID lpAnsiCodePageData;
  LPVOID lpOemCodePageData;
  LPVOID lpUnicodeCaseTableData;
  DWORD dwNumberOfProcessors;
  DWORD dwNtGlobalFlag;
  LARGE_INTEGER liCriticalSectionTimeout;
  DWORD dwHeapSegmentReserve;
  DWORD dwHeapSegmentCommit;
  DWORD dwHeapDeCommitTotalFreeThreshold;
  DWORD dwHeapDeCommitFreeBlockThreshold;
  DWORD dwNumberOfHeaps;
  DWORD dwMaximumNumberOfHeaps;
  LPVOID lpProcessHeaps;
  LPVOID lpGdiSharedHandleTable;
  LPVOID lpProcessStarterHelper;
  DWORD dwGdiDCAttributeList;
  LPVOID lpLoaderLock;
  DWORD dwOSMajorVersion;
  DWORD dwOSMinorVersion;
  WORD wOSBuildNumber;
  WORD wOSCSDVersion;
  DWORD dwOSPlatformId;
  DWORD dwImageSubsystem;
  DWORD dwImageSubsystemMajorVersion;
  DWORD dwImageSubsystemMinorVersion;
  DWORD dwImageProcessAffinityMask;
  DWORD dwGdiHandleBuffer[34];
  LPVOID lpPostProcessInitRoutine;
  LPVOID lpTlsExpansionBitmap;
  DWORD dwTlsExpansionBitmapBits[32];
  DWORD dwSessionId;
  ULARGE_INTEGER liAppCompatFlags;
  ULARGE_INTEGER liAppCompatFlagsUser;
  LPVOID lppShimData;
  LPVOID lpAppCompatInfo;
  UNICODE_STRING usCSDVersion;
  LPVOID lpActivationContextData;
  LPVOID lpProcessAssemblyStorageMap;
  LPVOID lpSystemDefaultActivationContextData;
  LPVOID lpSystemAssemblyStorageMap;
  DWORD dwMinimumStackCommit;
} PEB, *PPEB;

typedef struct {
  WORD offset : 12;
  WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

DLLEXPORT DWORD WINAPI ReflectiveLoader(void* parameter) ;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void* reserved) ;