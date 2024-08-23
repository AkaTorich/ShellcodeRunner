#include "PEstructs.h"
#include "helpers.h"
#include <stdio.h>

typedef HMODULE(WINAPI* LoadLibrary_t)(LPCSTR lpFileName);
LoadLibrary_t pLoadLibraryA = NULL;

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

    // Получаем смещение блока среды процесса (Process Environment Block)
#ifdef _M_IX86 
    PEB* ProcEnvBlk = (PEB*)__readfsdword(0x30);
#else
    PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);
#endif

    // Возвращаем базовый адрес вызывающего модуля
    if (sModuleName == NULL)
        return (HMODULE)(ProcEnvBlk->ImageBaseAddress);

    PEB_LDR_DATA* Ldr = ProcEnvBlk->Ldr;
    LIST_ENTRY* ModuleList = NULL;

    ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    for (LIST_ENTRY* pListEntry = pStartListEntry;  		// Начинаем с начала InMemoryOrderModuleList
        pListEntry != ModuleList;	    	// Проходим по всем элементам списка
        pListEntry = pListEntry->Flink) {

        // Получаем текущую запись таблицы данных
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

        // Проверяем, найден ли модуль, и возвращаем его базовый адрес
        if (lstrcmpiW(pEntry->BaseDllName.Buffer, sModuleName) == 0)
            return (HMODULE)pEntry->DllBase;
    }

    // В противном случае:
    return NULL;
}

FARPROC hlpGetProcAddress(HMODULE hModule, const char* lpProcName) {
    char* pBaseAddr = (char*)hModule;

    // Получаем указатели на основные заголовки/структуры
    IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
    IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

    // Разрешаем адреса таблицы экспортируемых функций, таблицы имен функций и "таблицы ординалов"
    DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    // Адрес функции, которую мы ищем
    void* pProcAddr = NULL;

    // Разрешаем функцию по ординалу
    if (((DWORD_PTR)lpProcName >> 16) == 0) {
        WORD ordinal = (WORD)lpProcName & 0xFFFF;    // Преобразуем в WORD
        DWORD Base = pExportDirAddr->Base;            // Первый номер ординала

        // Проверяем, что ординал не выходит за границы
        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
            return NULL;

        // Получаем виртуальный адрес функции = RVA + BaseAddr
        pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - Base]);
    }
    // Разрешаем функцию по имени
    else {
        // Проходим по таблице имен функций
        for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
            char* sTmpFuncName = (char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];

            if (strcmp(lpProcName, sTmpFuncName) == 0) {
                // Найдено, получаем виртуальный адрес функции = RVA + BaseAddr
                pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
                break;
            }
        }
    }

    // Проверяем, перенаправлен ли найденный VA в внешнюю библиотеку и функцию
    if ((char*)pProcAddr >= (char*)pExportDirAddr &&
        (char*)pProcAddr < (char*)(pExportDirAddr + pExportDataDir->Size)) {

        char* sFwdDLL = _strdup((char*)pProcAddr); 	// Получаем копию строки library.function
        if (!sFwdDLL) return NULL;

        // Получаем имя внешней функции
        char* sFwdFunction = strchr(sFwdDLL, '.');
        *sFwdFunction = 0;					// Устанавливаем завершающий нулевой байт для имени внешней библиотеки -> library\x0function
        sFwdFunction++;						// Смещаем указатель на начало имени функции

        // Разрешаем указатель на функцию LoadLibrary, храним его как глобальную переменную
        if (pLoadLibraryA == NULL) {
            pLoadLibraryA = (LoadLibrary_t)hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA");
            if (pLoadLibraryA == NULL) return NULL;
        }

        // Загружаем внешнюю библиотеку
        HMODULE hFwd = pLoadLibraryA(sFwdDLL);
        free(sFwdDLL);							// Освобождаем выделенную память для копии строки lib.func
        if (!hFwd) return NULL;

        // Получаем адрес функции, на которую перенаправлен исходный вызов
        pProcAddr = hlpGetProcAddress(hFwd, sFwdFunction);
    }

    return (FARPROC)pProcAddr;
}
