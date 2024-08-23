#pragma once

#include <windows.h>
#include <malloc.h>

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC hlpGetProcAddress(HMODULE hModule, const char* lpProcName);
