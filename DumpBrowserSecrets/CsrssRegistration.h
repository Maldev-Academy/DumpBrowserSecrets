#pragma once
#ifndef CSRSS_REGISTRATION_H
#define CSRSS_REGISTRATION_H

#include <Windows.h>

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// CONSTANTS
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#define ALPC_MSGFLG_SYNC_REQUEST                0x20000

// CSRSS API Numbers
#define BASESRV_CREATE_PROCESS_OLD              0x10000   // Windows 10 pre-2004
#define BASESRV_CREATE_PROCESS                  0x1001D   // Windows 10 2004+ / Windows 11

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// PORT_MESSAGE
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef short CSHORT;
typedef ULONG CSR_API_NUMBER;

typedef struct _PORT_MESSAGE {
    union {
        struct {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            CSHORT Type;
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, *PPORT_MESSAGE;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// SXS CREATEPROCESS MESSAGE (Windows 10 2004+ / Windows 11)
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _BASE_SXS_CREATEPROCESS_MSG {
    ULONG               Flags;                      // 0x00
    ULONG               ProcessParameterFlags;      // 0x04
    HANDLE              FileHandle;                 // 0x08
    UNICODE_STRING      Win32Path;                  // 0x10
    UNICODE_STRING      NtPath;                     // 0x20
    PVOID               AppCompatSxsData;           // 0x30
    SIZE_T              AppCompatSxsDataSize;       // 0x38
    BYTE                Reserved1[8];               // 0x40
    BYTE                Reserved2[8];               // 0x48
    PVOID               ManifestAddress;            // 0x50
    ULONG               ManifestSize;               // 0x58
    BYTE                Reserved3[16];              // 0x5C -> 0x6C
    USHORT              UnknowFlags;                // 0x6C
    BYTE                Padding[2];                 // 0x6E -> 0x70
    BYTE                Reserved4[8];               // 0x70 -> 0x78
    UNICODE_STRING      AssemblyDirectory;          // 0x78 (this was MISSING in your version!)
    UNICODE_STRING      CacheSxsLanguageBuffer;     // 0x88
    ACTIVATION_CONTEXT_RUN_LEVEL_INFORMATION ActCtx_RunLevel;  // 0x98 (12 bytes)
    ULONG               UnknowAppCompat;            // 0xA4
    UNICODE_STRING      AssemblyIdentity;           // 0xA8
    BYTE                Reserved5[8];               // 0xB8
    PVOID               PackageActivationSxsInfo;   // 0xC0
    BYTE                Reserved6[256];             // 0xC8 -> 0x1C8
} BASE_SXS_CREATEPROCESS_MSG, *PBASE_SXS_CREATEPROCESS_MSG;  // Total: 0x1C8 (456 bytes)

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// BASE CREATEPROCESS MESSAGE
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _BASE_CREATEPROCESS_MSG {
    HANDLE                      ProcessHandle;          // 0x00
    HANDLE                      ThreadHandle;           // 0x08
    CLIENT_ID                   ClientId;               // 0x10
    ULONG                       CreationFlags;          // 0x20
    ULONG                       VdmBinaryType;          // 0x24
    ULONG                       VdmTask;                // 0x28
    HANDLE                      hVDM;                   // 0x30
    BASE_SXS_CREATEPROCESS_MSG  Sxs;                    // 0x38
    ULONGLONG                   PebAddressNative;       // 0x200
    ULONGLONG                   PebAddressWow64;        // 0x208
    USHORT                      ProcessorArchitecture;  // 0x210
} BASE_CREATEPROCESS_MSG, *PBASE_CREATEPROCESS_MSG;     // Total: 0x218 (536 bytes)

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// SXS UTILITY STRUCT 
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _BASE_MSG_SXS_HANDLES {
    HANDLE File;
    HANDLE Process;
    HANDLE Section;
    PVOID  ViewBase;
} BASE_MSG_SXS_HANDLES, *PBASE_MSG_SXS_HANDLES;

typedef struct _SXS_UTILITY_STRUCT {
    BASE_MSG_SXS_HANDLES ManifestHandles;       // 0x00
    BASE_MSG_SXS_HANDLES PolicyHandles;         // 0x20
    PVOID                SxsStringBuffers;      // 0x40
    PVOID                ReservedStringsBuffers;// 0x48
    HANDLE               FileHandle;            // 0x50
} SXS_UTILITY_STRUCT, *PSXS_UTILITY_STRUCT;     // 0x58 (88 bytes)

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// CSR STRUCTURES
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

typedef struct _CSR_CAPTURE_BUFFER {
    ULONG                        Length;
    struct _CSR_CAPTURE_BUFFER*  RelatedCaptureBuffer;
    ULONG                        CountMessagePointers;
    PCHAR                        FreeSpace;
    ULONG_PTR                    MessagePointerOffsets[1];
} CSR_CAPTURE_BUFFER, *PCSR_CAPTURE_BUFFER;

typedef struct _CSR_API_CONNECTINFO {
    PVOID SharedSectionBase;
    PVOID SharedStaticServerData;
    PVOID ServerProcessId;
    PVOID Reserved;
    DWORD Reserved2;
    DWORD Reserved3;
    PVOID Reserved4;
} CSR_API_CONNECTINFO, *PCSR_API_CONNECTINFO;

typedef struct _CSR_CLIENTCONNECT_MSG {
    ULONG ServerDllIndex;
    PVOID ConnectionInformation;
    ULONG ConnectionInformationLength;
} CSR_CLIENTCONNECT_MSG, *PCSR_CLIENTCONNECT_MSG;


typedef struct _CSR_API_MSG {
    PORT_MESSAGE            h;                      // 0x00 (40 bytes)
    PCSR_CAPTURE_BUFFER     CaptureBuffer;          // 0x28
    CSR_API_NUMBER          ApiNumber;              // 0x30
    ULONG                   ReturnValue;            // 0x34
    ULONG                   Reserved;               // 0x38
    union {
        CSR_CLIENTCONNECT_MSG   ClientConnect;
        BASE_CREATEPROCESS_MSG  CreateProcessMsg;
        ULONG_PTR               ApiMessageData[0x50];
    } u;                                            // 0x40
} CSR_API_MSG, *PCSR_API_MSG;

#endif // CSRSS_REGISTRATION_H