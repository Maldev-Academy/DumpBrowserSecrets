#pragma once

#ifndef DEBUG_HDR
#define DEBUG_HDR

// ============================================================================
// 
// _DEBUG   - Enables DBGA() macro for standard debug messages
// _VERBOSE - Enables DBGV() macro for verbose messages
// 
// Combinations:
//   (none)              - Release build, no strings compiled in
//   _DEBUG              - Debug messages only
//   _VERBOSE            - Verbose messages only
//   _DEBUG + _VERBOSE   - All messages enabled
// 
// ============================================================================
// Comment or uncomment to enable/disable debug/verbose output modes
// ============================================================================
#ifndef _DEBUG
#define _DEBUG              // Comment or uncomment
#endif

#ifndef _VERBOSE
#define _VERBOSE            // Comment or uncomment
#endif
// ============================================================================

#ifdef BUILD_AS_DLL // (DLL VERSION)

extern HANDLE   g_hPipe;
extern BOOL     g_bPipeInitialized;
extern CHAR     g_szProcessName[MAX_PATH];
extern DWORD    g_dwProcessId;

BOOL InitializeOutputPipe(HANDLE* phPipe);

#if defined(_DEBUG) || defined(_VERBOSE)
#define _DBG_INTERNAL(fmt, ...)                                                                 \
            do {                                                                                \
                if (!g_szProcessName[0]) {                                                      \
                    CHAR szModulePath[MAX_PATH] = { 0 };                                        \
                    GetModuleFileNameA(NULL, szModulePath, MAX_PATH);                           \
                    lstrcpyA(g_szProcessName, PathFindFileNameA(szModulePath));                 \
                    g_dwProcessId = GetCurrentProcessId();                                      \
                }                                                                               \
                                                                                                \
                if (!g_bPipeInitialized)                                                        \
                    g_bPipeInitialized = InitializeOutputPipe(&g_hPipe);                        \
                                                                                                \
                SYSTEMTIME stNow;                                                               \
                GetLocalTime(&stNow);                                                           \
                                                                                                \
                LPSTR szBuf = (LPSTR)LocalAlloc(LPTR, BUFFER_SIZE_1024);                        \
                if (szBuf) {                                                                    \
                    int nLen = wsprintfA(szBuf,                                                 \
                                         "[%02d:%02d:%02d.%03d-%s-%lu] " fmt "\n",              \
                                         stNow.wHour, stNow.wMinute, stNow.wSecond,             \
                                         stNow.wMilliseconds, g_szProcessName,                  \
                                         g_dwProcessId, ##__VA_ARGS__);                         \
                                                                                                \
                    if (g_hPipe != INVALID_HANDLE_VALUE) {                                      \
                        DWORD dwWritten;                                                        \
                        WriteFile(g_hPipe, szBuf, nLen, &dwWritten, NULL);                      \
                        FlushFileBuffers(g_hPipe);                                              \
                    }                                                                           \
                                                                                                \
                    OutputDebugStringA(szBuf);                                                  \
                    LocalFree(szBuf);                                                           \
                }                                                                               \
            } while (0)

#define _DBG_CLOSE()                                                                            \
            do {                                                                                \
                if (g_hPipe != INVALID_HANDLE_VALUE) {                                          \
                    CloseHandle(g_hPipe);                                                       \
                    g_hPipe = INVALID_HANDLE_VALUE;                                             \
                }                                                                               \
                g_bPipeInitialized = FALSE;                                                     \
            } while (0)
#else
#define _DBG_INTERNAL(fmt, ...)     ((void)0)
#define _DBG_CLOSE()                ((void)0)
#endif

#ifdef _DEBUG
#define DBGA(fmt, ...)              _DBG_INTERNAL(fmt, ##__VA_ARGS__)
#else
#define DBGA(fmt, ...)              ((void)0)
#endif

#ifdef _VERBOSE
#define DBGV(fmt, ...)              _DBG_INTERNAL(fmt, ##__VA_ARGS__)
#else
#define DBGV(fmt, ...)              ((void)0)
#endif

#define DBGA_CLOSE()                _DBG_CLOSE()

#else // !BUILD_AS_DLL (EXE VERSION)

#if defined(_DEBUG) || defined(_VERBOSE)
#define _DBG_INTERNAL(fmt, ...)     printf(fmt "\n", ##__VA_ARGS__)
#else
#define _DBG_INTERNAL(fmt, ...)     ((void)0)
#endif

#ifdef _DEBUG
#define DBGA(fmt, ...)              _DBG_INTERNAL(fmt, ##__VA_ARGS__)
#else
#define DBGA(fmt, ...)              ((void)0)
#endif

#ifdef _VERBOSE
#define DBGV(fmt, ...)              _DBG_INTERNAL(fmt, ##__VA_ARGS__)
#else
#define DBGV(fmt, ...)              ((void)0)
#endif

#define DBGA_CLOSE()                ((void)0)

#endif // BUILD_AS_DLL

#endif // !DEBUG_HDR