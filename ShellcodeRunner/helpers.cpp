#include "PEstructs.h"
#include "helpers.h"
#include <stdio.h>

typedef HMODULE(WINAPI* LoadLibrary_t)(LPCSTR lpFileName);
LoadLibrary_t pLoadLibraryA = NULL;

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

    // �������� �������� ����� ����� �������� (Process Environment Block)
#ifdef _M_IX86 
    PEB* ProcEnvBlk = (PEB*)__readfsdword(0x30);
#else
    PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
#endif

    // ���������� ������� ����� ����������� ������
    if (sModuleName == NULL)
        return (HMODULE)(ProcEnvBlk->ImageBaseAddress);

    PEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
    LIST_ENTRY* ModuleList = NULL;

    ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    for (LIST_ENTRY* pListEntry = pStartListEntry;  		// �������� � ������ InMemoryOrderModuleList
        pListEntry != ModuleList;	    	// �������� �� ���� ��������� ������
        pListEntry = pListEntry->Flink) {

        // �������� ������� ������ ������� ������
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        // ���������, ������ �� ������, � ���������� ��� ������� �����
        if (lstrcmpiW(pEntry->BaseDllName.Buffer, sModuleName) == 0)
            return (HMODULE)pEntry->DllBase;
    }

    // � ��������� ������:
    return NULL;
}

FARPROC hlpGetProcAddress(HMODULE hModule, const char* lpProcName) {
    char* pBaseAddr = (char*)hModule;

    // �������� ��������� �� �������� ���������/���������
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

    // ��������� ������ ������� �������������� �������, ������� ���� ������� � "������� ���������"
    DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    // ����� �������, ������� �� ����
    void* pProcAddr = NULL;

    // ��������� ������� �� ��������
    if (((DWORD_PTR)lpProcName >> 16) == 0) {
        WORD ordinal = (WORD)lpProcName & 0xFFFF;    // ����������� � WORD
        DWORD Base = pExportDirAddr->Base;            // ������ ����� ��������

        // ���������, ��� ������� �� ������� �� �������
        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
            return NULL;

        // �������� ����������� ����� ������� = RVA + BaseAddr
        pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
    }
    // ��������� ������� �� �����
    else {
        // �������� �� ������� ���� �������
        for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
            char* sTmpFuncName = (char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];

            if (strcmp(lpProcName, sTmpFuncName) == 0) {
                // �������, �������� ����������� ����� ������� = RVA + BaseAddr
                pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
                break;
            }
        }
    }

    // ���������, ������������� �� ��������� VA � ������� ���������� � �������
    if ((char*)pProcAddr >= (char*)pExportDirAddr &&
        (char*)pProcAddr < (char*)(pExportDirAddr + pExportDataDir->Size)) {

        char* sFwdDLL = _strdup((char*)pProcAddr); 	// �������� ����� ������ library.function
        if (!sFwdDLL) return NULL;

        // �������� ��� ������� �������
        char* sFwdFunction = strchr(sFwdDLL, '.');
        *sFwdFunction = 0;					// ������������� ����������� ������� ���� ��� ����� ������� ���������� -> library\x0function
        sFwdFunction++;						// ������� ��������� �� ������ ����� �������

        // ��������� ��������� �� ������� LoadLibrary, ������ ��� ��� ���������� ����������
        if (pLoadLibraryA == NULL) {
            pLoadLibraryA = (LoadLibrary_t)hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA");
            if (pLoadLibraryA == NULL) return NULL;
        }

        // ��������� ������� ����������
        HMODULE hFwd = pLoadLibraryA(sFwdDLL);
        free(sFwdDLL);							// ����������� ���������� ������ ��� ����� ������ lib.func
        if (!hFwd) return NULL;

        // �������� ����� �������, �� ������� ������������� �������� �����
        pProcAddr = hlpGetProcAddress(hFwd, sFwdFunction);
    }

    return (FARPROC)pProcAddr;
}
