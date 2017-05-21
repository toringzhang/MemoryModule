// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

#pragma comment(linker,"/INCLUDE:__tls_used")
void NTAPI MY_TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved);


extern "C" __declspec(dllexport) void TestProc()
{
	MessageBox(NULL, L"Test Proc!", NULL, MB_OK);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		MessageBox(NULL, L"Load!", NULL, MB_OK);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	{
		MessageBox(NULL, L"UnLoad!", NULL, MB_OK);
		break;
	}
		break;
	}
	return TRUE;
}

//TLS回调函数测试
void NTAPI MY_TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
	{
		MessageBox(NULL, L"TLSTest!", NULL, MB_OK);
	}
}

#pragma data_seg(".CRT$XLX")
PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { MY_TLS_CALLBACK,0 };
#pragma data_seg()
