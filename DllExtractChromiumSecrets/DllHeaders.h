#pragma once
#ifndef DLL_HEADERS_H
#define DLL_HEADERS_H

// Set The DLL's DBGA Macro Version
#define BUILD_AS_DLL    
#include "Common.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// IElevator Interface (For Chrome And Brave)

typedef enum _PROTECTION_LEVEL
{
    PROTECTION_NONE                 = 0,
    PROTECTION_PATH_VALIDATION_OLD  = 1,
    PROTECTION_PATH_VALIDATION      = 2,
    PROTECTION_MAX                  = 3

} PROTECTION_LEVEL;

typedef struct IElevator IElevator;

typedef struct IElevatorVtbl
{
    // IUnknown
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IElevator* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IElevator* This);
    ULONG(STDMETHODCALLTYPE* Release)(IElevator* This);

    // IElevator
    HRESULT(STDMETHODCALLTYPE* RunRecoveryCRXElevated)(
        IElevator*      This,
        const WCHAR*    crx_path,
        const WCHAR*    browser_appid,
        const WCHAR*    browser_version,
        const WCHAR*    session_id,
        DWORD           caller_proc_id,
        ULONG_PTR*      proc_handle
    );

    HRESULT(STDMETHODCALLTYPE* EncryptData)(
        IElevator*          This,
        PROTECTION_LEVEL    protection_level,
        const BSTR          plaintext,
        BSTR*               ciphertext,
        DWORD*              last_error
    );

    HRESULT(STDMETHODCALLTYPE* DecryptData)(
        IElevator*      This,
        const BSTR      ciphertext,
        BSTR*           plaintext,
        DWORD*          last_error
    );

} IElevatorVtbl;

struct IElevator
{
    IElevatorVtbl* lpVtbl;
};

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// IElevatorEdge Interface

typedef struct IElevatorEdge IElevatorEdge;

typedef struct IElevatorEdgeVtbl
{
    // IUnknown (vtable slots 0-2)
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IElevatorEdge* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IElevatorEdge* This);
    ULONG(STDMETHODCALLTYPE* Release)(IElevatorEdge* This);

    // Edge base interface placeholders (vtable slots 3-5)
    HRESULT(STDMETHODCALLTYPE* _Placeholder1)(IElevatorEdge* This);
    HRESULT(STDMETHODCALLTYPE* _Placeholder2)(IElevatorEdge* This);
    HRESULT(STDMETHODCALLTYPE* _Placeholder3)(IElevatorEdge* This);

    // IElevator methods (vtable slots 6-8)
    HRESULT(STDMETHODCALLTYPE* RunRecoveryCRXElevated)(
        IElevatorEdge*  This,
        const WCHAR*    crx_path,
        const WCHAR*    browser_appid,
        const WCHAR*    browser_version,
        const WCHAR*    session_id,
        DWORD           caller_proc_id,
        ULONG_PTR*      proc_handle
    );

    HRESULT(STDMETHODCALLTYPE* EncryptData)(
        IElevatorEdge*      This,
        PROTECTION_LEVEL    protection_level,
        const BSTR          plaintext,
        BSTR*               ciphertext,
        DWORD*              last_error
    );

    HRESULT(STDMETHODCALLTYPE* DecryptData)(
        IElevatorEdge*  This,
        const BSTR      ciphertext,
        BSTR*           plaintext,
        DWORD*          last_error
    );

} IElevatorEdgeVtbl;

struct IElevatorEdge
{
    IElevatorEdgeVtbl* lpVtbl;
};



#endif // !DLL_HEADERS_H

