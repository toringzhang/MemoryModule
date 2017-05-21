#pragma once

#include <Windows.h>

#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif

//获得第n项DataDirectory
#define GET_HEADER_DICTIONARY(Module, Index)  &(Module)->NtHeaders->OptionalHeader.DataDirectory[Index]

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif

extern "C"
{

	typedef BOOL(APIENTRY *DllEntryProc)(HMODULE hModule, DWORD dwReason, LPVOID lpReserved);
	typedef int (WINAPI *ExeEntryProc)(void);

	typedef void *HMEMORYMODULE;

	typedef void *HMEMORYRSRC;

	typedef void *HCUSTOMMODULE;

	typedef LPVOID(*pfnAlloc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
	typedef BOOL(*pfnFree)(LPVOID, SIZE_T, DWORD, void*);
	typedef HCUSTOMMODULE(*pfnLoadLibrary)(LPCSTR, void*);
	typedef FARPROC(*pfnGetProcAddress)(HCUSTOMMODULE, LPCSTR, void*);
	typedef void(*pfnFreeLibrary)(HCUSTOMMODULE, void*);

	typedef struct _MEMORYMODULE {
		PIMAGE_NT_HEADERS NtHeaders;   //PE头
		unsigned char *pCodeBase;    //
		HCUSTOMMODULE *pModules;     //模块基地址
		int  nNumberOfModules;       //模块总数
		BOOL bInitialized;
		BOOL bIsDLL;
		BOOL bIsRelocated;
		pfnAlloc MyAlloc;
		pfnFree  MyFree;
		pfnLoadLibrary    MyLoadLibrary;
		pfnGetProcAddress MyGetProcAddress;
		pfnFreeLibrary    MyFreeLibrary;
		void *pUserData;
		ExeEntryProc ExeEntry;
		DWORD dwPageSize;
	} MEMORYMODULE, *PMEMORYMODULE;

	typedef struct _SECTIONFINALIZEDATA {
		LPVOID lpAddress;
		LPVOID lpAlignedAddress;
		SIZE_T Size;
		DWORD  dwCharacteristics;
		BOOL   bIsLast;
	} SECTIONFINALIZEDATA, *PSECTIONFINALIZEDATA;


	static int ProtectionFlags[2][2][2] = {
		{
			// 不可执行
			{ PAGE_NOACCESS, PAGE_WRITECOPY },
			{ PAGE_READONLY, PAGE_READWRITE },
		},{
			// 可执行
			{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
			{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE },
		},
	};

	static inline BOOL CheckSize(size_t Size, size_t Expected);

	static inline size_t AlignValueUp(size_t Value, size_t Alignment);

	static inline void * OffsetPointer(void * Data, ptrdiff_t Offset);

	static inline uintptr_t AlignValueDown(uintptr_t Value, uintptr_t Alignment);

	static inline LPVOID AlignAddressDown(LPVOID Address, uintptr_t Alignment);

	LPVOID MemoryDefaultAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD dwAllocationType, DWORD dwProtect, void * pUserData);

	BOOL MemoryDefaultFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType, void * pUserData);

	HCUSTOMMODULE MemoryDefaultLoadLibrary(LPCSTR szFileName, void * pUserData);

	FARPROC MemoryDefaultGetProcAddress(HCUSTOMMODULE hModule, LPCSTR szProcName, void * pUserData);

	void MemoryDefaultFreeLibrary(HCUSTOMMODULE hModule, void * pUserData);

	static SIZE_T GetRealSectionSize(PMEMORYMODULE Module, PIMAGE_SECTION_HEADER Section_Header);

	static BOOL CopySections(const unsigned char * Data, size_t Size, PIMAGE_NT_HEADERS Nt_Headers, PMEMORYMODULE Module);

	static BOOL PerformBaseRelocation(PMEMORYMODULE Module, ptrdiff_t Delta);

	static BOOL BuildImportTable(PMEMORYMODULE Module);

	static BOOL FinalizeSection(PMEMORYMODULE Module, PSECTIONFINALIZEDATA SectionData);

	static BOOL FinalizeSections(PMEMORYMODULE Module);

	static BOOL ExecuteTLS(PMEMORYMODULE Module);

	HMEMORYMODULE MemoryLoadLibrary(const void * Data, size_t Size);

	HMEMORYMODULE MemoryLoadLibraryEx(const void * Data, size_t Size, pfnAlloc MyAllocMemory, pfnFree MyFreeMemory, pfnLoadLibrary MyLoadLibrary, pfnGetProcAddress MyGetProcAddress, pfnFreeLibrary MyFreeLibrary, void * UserData);

	void MemoryFreeLibrary(HMEMORYMODULE Module);

	FARPROC MemoryGetProcAddress(HMEMORYMODULE Module, LPCSTR lpProcName);

	HMEMORYRSRC MemoryFindResource(HMEMORYMODULE Module, LPCTSTR ResourceName, LPCTSTR Type);

	HMEMORYRSRC MemoryFindResourceEx(HMEMORYMODULE Module, LPCTSTR ResourceName, LPCTSTR Type, WORD Language);

	static PIMAGE_RESOURCE_DIRECTORY_ENTRY _MemorySearchResourceEntry(void * Root, PIMAGE_RESOURCE_DIRECTORY ResourcesDirectory, LPCTSTR Key);

	DWORD MemorySizeofResource(HMEMORYMODULE Module, HMEMORYRSRC Resource);

	LPVOID MemoryLoadResource(HMEMORYMODULE Module, HMEMORYRSRC Resource);

	int MemoryLoadString(HMEMORYMODULE Module, UINT Id, LPTSTR Buffer, int MaxSize);

	int MemoryLoadStringEx(HMEMORYMODULE Module, UINT Id, LPTSTR Buffer, int MaxSize, WORD Language);

}