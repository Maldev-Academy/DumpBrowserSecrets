#include "Headers.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-===-==-==-==-==-==-==-==-==-==-===-==-==-==-==-==-==-==-==-==-==
// Extern Global (Defined in 'ResolvePrgrmAPIs.cpp')

extern DINMCLY_RSOLVD_FUNCTIONS g_ResolvedFunctions;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-===-==-==-==-==-==-==-==-==-==-===-==-==-==-==-==-==-==-==-==-==

BOOL RegisterProcessWithCsrss(
    IN      HANDLE               hProcess,
    IN      HANDLE               hThread,
    IN      PPS_CREATE_INFO      pCreateInfo,
    IN      PUNICODE_STRING      pWin32Path,
    IN      PUNICODE_STRING      pNtPath,
    IN      PCLIENT_ID           pClientId,
    IN      USHORT               DllCharacteristics
)
{
    CSR_API_MSG                 Msg                     = { 0 };
    SXS_UTILITY_STRUCT          sxsUtility              = { 0 };
    PCSR_CAPTURE_BUFFER         csrCaptureBuffer        = NULL;
    CSR_API_NUMBER              csrApiNumber            = 0x00;
    PUNICODE_STRING             pusStringsToCapture[4]  = { 0 };
    PBASE_CREATEPROCESS_MSG     pBaseCreateProcMsg      = &Msg.u.CreateProcessMsg;
    ULONG                       uOSBuildNumber          = (ULONG)(*(PULONG)(0x7FFE0000 + 0x260)); // Read from KUSER_SHARED_DATA
    HANDLE                      hToken                  = NULL;
    NTSTATUS                    ntStatus                = STATUS_SUCCESS;
    BOOL                        bResult                 = FALSE;

    if (!g_ResolvedFunctions.pInitialized) return FALSE;

    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pNtOpenProcessToken(NtCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))))
    {
        DBGA("[!] NtOpenProcessToken Failed With Error: 0x%0.8X", ntStatus);
        return FALSE;
    }

    // Initialize the create process message
    pBaseCreateProcMsg->ProcessHandle = hProcess;
    pBaseCreateProcMsg->ThreadHandle  = hThread;
    pBaseCreateProcMsg->ClientId      = *pClientId;
    pBaseCreateProcMsg->CreationFlags = EXTENDED_STARTUPINFO_PRESENT | IDLE_PRIORITY_CLASS | DETACHED_PROCESS;
    pBaseCreateProcMsg->VdmBinaryType = 0;
    pBaseCreateProcMsg->VdmTask       = 0;
    pBaseCreateProcMsg->hVDM          = NULL;

    RtlZeroMemory(&pBaseCreateProcMsg->Sxs, sizeof(BASE_SXS_CREATEPROCESS_MSG));

    ntStatus = g_ResolvedFunctions.pBasepConstructSxsCreateProcessMessage(
        pNtPath,                                                            // a1
        pWin32Path,                                                         // a2
        pCreateInfo->SuccessState.FileHandle,                               // a3
        hProcess,                                                           // a4
        pCreateInfo->SuccessState.SectionHandle,                            // a5
        hToken,                                                             // a6
        (pCreateInfo->InitState.u1.InitFlags & 0x4) != 0,                   // a7 - SxsCreateFlag
        NULL,                                                               // a8 - UnknowCompatCache
        NULL,                                                               // a9 - AppCompatSxsData
        0,                                                                  // a10 - AppCompatSxsDataSize
        (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) != 0,  // a11
        NULL,                                                               // a12 - AppXPath
        (PPEB)pCreateInfo->SuccessState.PebAddressNative,                   // a13
        (PVOID)pCreateInfo->SuccessState.ManifestAddress,                   // a14
        pCreateInfo->SuccessState.ManifestSize,                             // a15
        &pCreateInfo->SuccessState.CurrentParameterFlags,                   // a16
        &pBaseCreateProcMsg->Sxs,                                           // a17
        &sxsUtility                                                         // a18
    );

    if (!NT_SUCCESS(ntStatus))
    {
        DBGA("[!] BasepConstructSxsCreateProcessMessage Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    // Set PEB addresses and architecture
    pBaseCreateProcMsg->PebAddressNative      = pCreateInfo->SuccessState.PebAddressNative;
    pBaseCreateProcMsg->PebAddressWow64       = pCreateInfo->SuccessState.PebAddressWow64;
    pBaseCreateProcMsg->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;

    // Setup strings to capture: Win32Path, NtPath, CacheSxsLanguageBuffer, AssemblyIdentity
    pusStringsToCapture[0] = &pBaseCreateProcMsg->Sxs.Win32Path;
    pusStringsToCapture[1] = &pBaseCreateProcMsg->Sxs.NtPath;
    pusStringsToCapture[2] = &pBaseCreateProcMsg->Sxs.CacheSxsLanguageBuffer;
    pusStringsToCapture[3] = &pBaseCreateProcMsg->Sxs.AssemblyIdentity;

    // Capture strings
    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pCsrCaptureMessageMultiUnicodeStringsInPlace(&csrCaptureBuffer, ARRAYSIZE(pusStringsToCapture), pusStringsToCapture))))
    {
        DBGA("[!] CsrCaptureMessageMultiUnicodeStringsInPlace Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    // Windows 10 2004+ / Windows 11
    if (uOSBuildNumber >= 18985)  
        csrApiNumber = BASESRV_CREATE_PROCESS; 
    // Windows 10 pre-2004
    else
        csrApiNumber = BASESRV_CREATE_PROCESS_OLD;

    DBGV("[v] Using CSR API Number: 0x%08X", csrApiNumber);

    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pCsrClientCallServer(&Msg, csrCaptureBuffer, csrApiNumber, sizeof(BASE_CREATEPROCESS_MSG)))))
    {
        DBGA("[!] CsrClientCallServer Failed With Error: 0x%0.8X", ntStatus);
        goto _END_OF_FUNC;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (hToken)
        CloseHandle(hToken);

    return bResult;
}