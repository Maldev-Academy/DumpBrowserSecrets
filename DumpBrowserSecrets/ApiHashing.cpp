/*
    All ResolveApi* Functions/Logic are Refactored From: https://github.com/ajkhoury/ApiSet 
*/

#include "Headers.h"

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region RESOLVEAPIS_DEFINTIONS

#define APISETAPI NTAPI

#define API_SET_SCHEMA_VERSION_V2       0x00000002
#define API_SET_SCHEMA_VERSION_V3       0x00000003 
#define API_SET_SCHEMA_VERSION_V4       0x00000004
#define API_SET_SCHEMA_VERSION_V6       0x00000006
    
#define CHAR_TO_LOWER_W(wc)             (((WCHAR)((wc) - L'A') <= (L'Z' - L'A')) ? ((wc) | 0x20) : (wc))

typedef struct _API_SET_NAMESPACE {
    ULONG Version;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

typedef struct _API_SET_NAMESPACE_V6 {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;  // API_SET_NAMESPACE_ENTRY_V6
    ULONG HashOffset;   // API_SET_NAMESPACE_HASH_ENTRY_V6
    ULONG HashFactor;
} API_SET_NAMESPACE_V6, * PAPI_SET_NAMESPACE_V6;

typedef struct _API_SET_NAMESPACE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY_V6, * PAPI_SET_NAMESPACE_ENTRY_V6;

typedef struct _API_SET_HASH_ENTRY_V6 {
    ULONG Hash;
    ULONG Index;
} API_SET_HASH_ENTRY_V6, * PAPI_SET_HASH_ENTRY_V6;

typedef struct _API_SET_VALUE_ENTRY_V6 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V6, * PAPI_SET_VALUE_ENTRY_V6;

typedef const API_SET_VALUE_ENTRY_V6* PCAPI_SET_VALUE_ENTRY_V6;
typedef const API_SET_HASH_ENTRY_V6* PCAPI_SET_HASH_ENTRY_V6;
typedef const API_SET_NAMESPACE_ENTRY_V6* PCAPI_SET_NAMESPACE_ENTRY_V6;
typedef const API_SET_NAMESPACE_V6* PCAPI_SET_NAMESPACE_V6;

typedef struct _API_SET_VALUE_ENTRY_V4 {
    ULONG Flags;        // 0x00
    ULONG NameOffset;   // 0x04
    ULONG NameLength;   // 0x08
    ULONG ValueOffset;  // 0x0C
    ULONG ValueLength;  // 0x10
} API_SET_VALUE_ENTRY_V4, * PAPI_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_VALUE_ARRAY_V4 {
    ULONG Flags;        // 0x00
    ULONG Count;        // 0x04
    API_SET_VALUE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V4, * PAPI_SET_VALUE_ARRAY_V4;

typedef struct _API_SET_NAMESPACE_ENTRY_V4 {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG AliasOffset;
    ULONG AliasLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V4
} API_SET_NAMESPACE_ENTRY_V4, * PAPI_SET_NAMESPACE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_ARRAY_V4 {
    ULONG Version;      // 0x00
    ULONG Size;         // 0x04
    ULONG Flags;        // 0x08
    ULONG Count;        // 0x0C
    API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V4, * PAPI_SET_NAMESPACE_ARRAY_V4;

typedef const API_SET_VALUE_ENTRY_V4* PCAPI_SET_VALUE_ENTRY_V4;
typedef const API_SET_VALUE_ARRAY_V4* PCAPI_SET_VALUE_ARRAY_V4;
typedef const API_SET_NAMESPACE_ENTRY_V4* PCAPI_SET_NAMESPACE_ENTRY_V4;
typedef const API_SET_NAMESPACE_ARRAY_V4* PCAPI_SET_NAMESPACE_ARRAY_V4;

typedef struct _API_SET_VALUE_ENTRY_V3 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V3, * PAPI_SET_VALUE_ENTRY_V3;

typedef struct _API_SET_VALUE_ARRAY_V3 {
    ULONG Count;
    API_SET_VALUE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V3, * PAPI_SET_VALUE_ARRAY_V3;

typedef struct _API_SET_NAMESPACE_ENTRY_V3 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V3
} API_SET_NAMESPACE_ENTRY_V3, * PAPI_SET_NAMESPACE_ENTRY_V3;

typedef struct _API_SET_NAMESPACE_ARRAY_V3 {
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V3, * PAPI_SET_NAMESPACE_ARRAY_V3;

typedef const API_SET_VALUE_ENTRY_V3* PCAPI_SET_VALUE_ENTRY_V3;
typedef const API_SET_VALUE_ARRAY_V3* PCAPI_SET_VALUE_ARRAY_V3;
typedef const API_SET_NAMESPACE_ENTRY_V3* PCAPI_SET_NAMESPACE_ENTRY_V3;
typedef const API_SET_NAMESPACE_ARRAY_V3* PCAPI_SET_NAMESPACE_ARRAY_V3;

typedef struct _API_SET_VALUE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, * PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2 {
    ULONG Count;
    API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V2, * PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2 {
    ULONG NameOffset;
    ULONG NameLength;
    ULONG DataOffset;   // API_SET_VALUE_ARRAY_V2
} API_SET_NAMESPACE_ENTRY_V2, * PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2 {
    ULONG Version;
    ULONG Count;
    API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V2, * PAPI_SET_NAMESPACE_ARRAY_V2;

typedef const API_SET_VALUE_ENTRY_V2* PCAPI_SET_VALUE_ENTRY_V2;
typedef const API_SET_VALUE_ARRAY_V2* PCAPI_SET_VALUE_ARRAY_V2;
typedef const API_SET_NAMESPACE_ENTRY_V2* PCAPI_SET_NAMESPACE_ENTRY_V2;
typedef const API_SET_NAMESPACE_ARRAY_V2* PCAPI_SET_NAMESPACE_ARRAY_V2;


#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region RESOLVEAPIS_FUNCTIONS

static PAPI_SET_NAMESPACE_ENTRY_V6 SearchApiSetV6(IN PAPI_SET_NAMESPACE_V6 pApiSetMap, IN PWSTR pwszApiSetName, IN USHORT usNameLen)
{
    PWCHAR                      pwcCurrent         = NULL;
    DWORD                       dwHashKey          = 0x00;
    DWORD                       dwLeft             = 0x00;
    DWORD                       dwRight            = 0x00;
    DWORD                       dwMid              = 0x00;
    USHORT                      usCount            = 0x00;
    PAPI_SET_HASH_ENTRY_V6      pHashEntry         = NULL;
    PAPI_SET_NAMESPACE_ENTRY_V6 pFoundEntry        = NULL;
    PWCHAR                      pwszEntryName      = NULL;

    if (!pApiSetMap || !pwszApiSetName || !usNameLen) return NULL;

    // Calculate hash for API Set name
    pwcCurrent = pwszApiSetName;
    usCount = usNameLen;
    while (usCount)
    {
        dwHashKey = dwHashKey * pApiSetMap->HashFactor + (USHORT)CHAR_TO_LOWER_W(*pwcCurrent);
        pwcCurrent++;
        usCount--;
    }

    // Binary search in hash table
    dwLeft = 0x00;
    dwRight = pApiSetMap->Count - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pHashEntry = (PAPI_SET_HASH_ENTRY_V6)((PBYTE)pApiSetMap + pApiSetMap->HashOffset + (dwMid * sizeof(API_SET_HASH_ENTRY_V6)));

        if (dwHashKey < pHashEntry->Hash)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (dwHashKey > pHashEntry->Hash)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            // Found hash match - get entry
            pFoundEntry = (PAPI_SET_NAMESPACE_ENTRY_V6)((PBYTE)pApiSetMap + pApiSetMap->EntryOffset + (pHashEntry->Index * sizeof(API_SET_NAMESPACE_ENTRY_V6)));
            break;
        }
    }

    if (!pFoundEntry) return NULL;

    // Verify name match (hash collision check)
    pwszEntryName = (PWCHAR)((PBYTE)pApiSetMap + pFoundEntry->NameOffset);
    
    // Manual case-insensitive comparison
    for (DWORD i = 0; i < pFoundEntry->HashedLength / sizeof(WCHAR); i++)
    {
        WCHAR wc1 = CHAR_TO_LOWER_W(pwszApiSetName[i]);
        WCHAR wc2 = CHAR_TO_LOWER_W(pwszEntryName[i]);
        if (wc1 != wc2) return NULL;
    }

    return pFoundEntry;
}

static PAPI_SET_VALUE_ENTRY_V6 SearchApiSetHostV6(IN PAPI_SET_NAMESPACE_V6 pApiSetMap, IN PAPI_SET_NAMESPACE_ENTRY_V6 pEntry, IN PWSTR pwszParentName, IN USHORT usParentLen)
{
    DWORD                   dwLeft         = 0x00;
    DWORD                   dwRight        = 0x00;
    DWORD                   dwMid          = 0x00;
    PAPI_SET_VALUE_ENTRY_V6 pValueEntry    = NULL;
    PAPI_SET_VALUE_ENTRY_V6 pHostEntry     = NULL;
    PWCHAR                  pwszHostName   = NULL;
    LONG                    lCompare       = 0x00;

    if (!pEntry || !pApiSetMap) return NULL;

    // Get default entry (first one)
    pValueEntry = (PAPI_SET_VALUE_ENTRY_V6)((PBYTE)pApiSetMap + pEntry->ValueOffset);
    
    // If only one entry or no parent specified, return default
    if (pEntry->ValueCount <= 1 || !pwszParentName || !usParentLen)
        return pValueEntry;

    // Binary search for matching host (skip first entry)
    dwLeft = 1;
    dwRight = pEntry->ValueCount - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pHostEntry = (PAPI_SET_VALUE_ENTRY_V6)((PBYTE)pApiSetMap + pEntry->ValueOffset + (dwMid * sizeof(API_SET_VALUE_ENTRY_V6)));
        pwszHostName = (PWCHAR)((PBYTE)pApiSetMap + pHostEntry->NameOffset);

        // Compare names
        DWORD dwCompareLen = min(usParentLen, pHostEntry->NameLength / sizeof(WCHAR));
        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParentName[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(pwszHostName[i]);
            if (wc1 < wc2)
            {
                lCompare = -1;
                break;
            }
            else if (wc1 > wc2)
            {
                lCompare = 1;
                break;
            }
            lCompare = 0;
        }
        
        if (lCompare == 0 && usParentLen != pHostEntry->NameLength / sizeof(WCHAR))
            lCompare = (usParentLen < pHostEntry->NameLength / sizeof(WCHAR)) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pHostEntry;
        }
    }

    return pValueEntry; // Return default if not found
}

static BOOL ResolveApiSetV6(IN PAPI_SET_NAMESPACE_V6 pApiSetMap, IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    ULONGLONG                   ullPrefix          = 0x00;
    PWCHAR                      pwcCurrent         = NULL;
    DWORD                       dwApiSetLen        = 0x00;
    USHORT                      usNameNoExtLen     = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V6 pNamespaceEntry    = NULL;
    PAPI_SET_VALUE_ENTRY_V6     pValueEntry        = NULL;
    PWCHAR                      pwszResolvedName   = NULL;
    DWORD                       dwResolvedLen      = 0x00;
    DWORD                       dwParentLen        = 0x00;

    if (!pApiSetMap || !pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    // Check minimum length
    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);
    if (dwApiSetLen < 4) return FALSE; // Need at least "api-" or "ext-"

    // Verify prefix (api- or ext-)
    ullPrefix = *(ULONGLONG*)pwszApiSetName;
    ullPrefix &= ~(ULONGLONG)0x0000002000200020; // Convert to uppercase
    
    if (ullPrefix != 0x002D004900500041 && // "API-"
        ullPrefix != 0x002D005400580045)    // "EXT-"
        return FALSE;

    // Find length without version suffix (stop at last hyphen)
    pwcCurrent = (PWCHAR)pwszApiSetName + dwApiSetLen;
    usNameNoExtLen = (USHORT)dwApiSetLen;
    while (usNameNoExtLen > 0)
    {
        pwcCurrent--;
        usNameNoExtLen--;
        if (*pwcCurrent == L'-') break;
    }
    
    if (!usNameNoExtLen) return FALSE;

    // Search for API Set entry
    pNamespaceEntry = SearchApiSetV6(pApiSetMap, (PWSTR)pwszApiSetName, usNameNoExtLen);
    if (!pNamespaceEntry) return FALSE;

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

    // Find appropriate host entry
    if (pNamespaceEntry->ValueCount > 1 && pwszParentName)
    {
        pValueEntry = SearchApiSetHostV6(pApiSetMap, pNamespaceEntry, (PWSTR)pwszParentName, (USHORT)dwParentLen);
    }
    else if (pNamespaceEntry->ValueCount > 0)
    {
        pValueEntry = (PAPI_SET_VALUE_ENTRY_V6)((PBYTE)pApiSetMap + pNamespaceEntry->ValueOffset);
    }
    else
    {
        return FALSE;
    }

    if (!pValueEntry) return FALSE;

    // Copy resolved name
    pwszResolvedName = (PWCHAR)((PBYTE)pApiSetMap + pValueEntry->ValueOffset);
    dwResolvedLen = pValueEntry->ValueLength / sizeof(WCHAR);
    
    if (dwResolvedLen >= dwMaxLen) return FALSE;

    for (DWORD i = 0; i < dwResolvedLen; i++)
        pwszResolved[i] = pwszResolvedName[i];
    pwszResolved[dwResolvedLen] = L'\0';

    return TRUE;
}

static PAPI_SET_NAMESPACE_ENTRY_V4 SearchApiSetV4(IN PAPI_SET_NAMESPACE_ARRAY_V4 pApiSetArray, IN PWSTR pwszApiSetName, IN USHORT usNameLen)
{
    DWORD                       dwLeft             = 0x00;
    DWORD                       dwRight            = 0x00;
    DWORD                       dwMid              = 0x00;
    LONG                        lCompare           = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V4 pNamespaceEntry    = NULL;
    PWCHAR                      pwszEntryName      = NULL;
    DWORD                       dwEntryNameLen     = 0x00;
    DWORD                       dwCompareLen       = 0x00;

    if (!pApiSetArray || !pwszApiSetName || !usNameLen) return NULL;

    dwLeft = 0x00;
    dwRight = pApiSetArray->Count - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pNamespaceEntry = (PAPI_SET_NAMESPACE_ENTRY_V4)(pApiSetArray->Array + dwMid);
        pwszEntryName = (PWCHAR)((PBYTE)pApiSetArray + pNamespaceEntry->NameOffset);
        dwEntryNameLen = pNamespaceEntry->NameLength / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usNameLen, dwEntryNameLen);
        lCompare = 0x00;
        
        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszApiSetName[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(pwszEntryName[i]);
            
            if (wc1 < wc2)
            {
                lCompare = -1;
                break;
            }
            else if (wc1 > wc2)
            {
                lCompare = 1;
                break;
            }
        }
        
        if (lCompare == 0 && usNameLen != dwEntryNameLen)
            lCompare = (usNameLen < dwEntryNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pNamespaceEntry;
        }
    }

    return NULL;
}

static PAPI_SET_VALUE_ENTRY_V4 SearchApiSetHostV4(IN PAPI_SET_NAMESPACE_ARRAY_V4 pApiSetArray, IN PAPI_SET_VALUE_ARRAY_V4 pValueArray, IN PWSTR pwszParentName, IN USHORT usParentLen)
{
    DWORD                   dwLeft         = 0x00;
    DWORD                   dwRight        = 0x00;
    DWORD                   dwMid          = 0x00;
    LONG                    lCompare       = 0x00;
    PAPI_SET_VALUE_ENTRY_V4 pHostEntry     = NULL;
    PWCHAR                  pwszHostName   = NULL;
    DWORD                   dwHostNameLen  = 0x00;
    DWORD                   dwCompareLen   = 0x00;

    if (!pValueArray || !pApiSetArray || pValueArray->Count <= 1) return NULL;
    if (!pwszParentName || !usParentLen) return NULL;

    // Skip first entry (default)
    dwLeft = 1;
    dwRight = pValueArray->Count - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pHostEntry = (PAPI_SET_VALUE_ENTRY_V4)(pValueArray->Array + dwMid);
        pwszHostName = (PWCHAR)((PBYTE)pApiSetArray + pHostEntry->NameOffset);
        dwHostNameLen = pHostEntry->NameLength / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usParentLen, dwHostNameLen);
        lCompare = 0x00;
        
        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParentName[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(pwszHostName[i]);
            
            if (wc1 < wc2)
            {
                lCompare = -1;
                break;
            }
            else if (wc1 > wc2)
            {
                lCompare = 1;
                break;
            }
        }
        
        if (lCompare == 0 && usParentLen != dwHostNameLen)
            lCompare = (usParentLen < dwHostNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pHostEntry;
        }
    }

    return NULL;
}

static BOOL ResolveApiSetV4(IN PAPI_SET_NAMESPACE_ARRAY_V4 pApiSetArray, IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    ULONGLONG                   ullPrefix          = 0x00;
    DWORD                       dwApiSetLen        = 0x00;
    DWORD                       dwSkipLen          = 0x00;
    PWSTR                       pwszNameNoPrefix   = NULL;
    USHORT                      usNameNoExtLen     = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V4 pNamespaceEntry    = NULL;
    PAPI_SET_VALUE_ARRAY_V4     pValueArray        = NULL;
    PAPI_SET_VALUE_ENTRY_V4     pValueEntry        = NULL;
    PWCHAR                      pwszResolvedName   = NULL;
    DWORD                       dwResolvedLen      = 0x00;
    DWORD                       dwParentLen        = 0x00;

    if (!pApiSetArray || !pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    // Get API Set name length
    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);
    
    // Check minimum length (need at least "api-xxxx")
    if (dwApiSetLen < 8) return FALSE;

    // Verify prefix (api- or ext-)
    ullPrefix = *(ULONGLONG*)pwszApiSetName;
    ullPrefix &= ~(ULONGLONG)0x0000002000200020; // Convert to uppercase
    
    if (ullPrefix != 0x002D004900500041 && // "API-"
        ullPrefix != 0x002D005400580045)    // "EXT-"
        return FALSE;

    // Skip prefix ("api-" or "ext-" = 4 chars)
    pwszNameNoPrefix = (PWSTR)(pwszApiSetName + 4);
    usNameNoExtLen = (USHORT)(dwApiSetLen - 4);

    // Remove .dll extension if present
    if (usNameNoExtLen >= 4)
    {
        if (pwszNameNoPrefix[usNameNoExtLen - 4] == L'.' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 3]) == L'd' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 2]) == L'l' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 1]) == L'l')
        {
            usNameNoExtLen -= 4;
        }
    }

    if (!usNameNoExtLen) return FALSE;

    // Search for API Set entry
    pNamespaceEntry = SearchApiSetV4(pApiSetArray, pwszNameNoPrefix, usNameNoExtLen);
    if (!pNamespaceEntry) return FALSE;

    // Get value array
    pValueArray = (PAPI_SET_VALUE_ARRAY_V4)((PBYTE)pApiSetArray + pNamespaceEntry->DataOffset);
    if (!pValueArray || pValueArray->Count == 0) return FALSE;

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

    // Find appropriate host entry
    if (pValueArray->Count > 1 && pwszParentName && dwParentLen)
    {
        pValueEntry = SearchApiSetHostV4(pApiSetArray, pValueArray, (PWSTR)pwszParentName, (USHORT)dwParentLen);
        if (!pValueEntry)
            pValueEntry = &pValueArray->Array[0]; // Default to first entry
    }
    else
    {
        pValueEntry = &pValueArray->Array[0]; // Use first entry
    }

    if (!pValueEntry) return FALSE;

    // Copy resolved name
    pwszResolvedName = (PWCHAR)((PBYTE)pApiSetArray + pValueEntry->ValueOffset);
    dwResolvedLen = pValueEntry->ValueLength / sizeof(WCHAR);
    
    if (dwResolvedLen >= dwMaxLen) return FALSE;

    for (DWORD i = 0; i < dwResolvedLen; i++)
        pwszResolved[i] = pwszResolvedName[i];
    pwszResolved[dwResolvedLen] = L'\0';

    return TRUE;
}

static PAPI_SET_VALUE_ENTRY_V3 SearchApiSetHostV3(IN PAPI_SET_NAMESPACE_ARRAY_V3 pApiSetArray, IN PAPI_SET_VALUE_ARRAY_V3 pValueArray, IN PWSTR pwszParentName, IN USHORT usParentLen)
{
    DWORD                   dwLeft         = 0x00;
    DWORD                   dwRight        = 0x00;
    DWORD                   dwMid          = 0x00;
    LONG                    lCompare       = 0x00;
    PAPI_SET_VALUE_ENTRY_V3 pValueEntry    = NULL;
    PWCHAR                  pwszHostName   = NULL;
    DWORD                   dwHostNameLen  = 0x00;
    DWORD                   dwCompareLen   = 0x00;

    if (!pValueArray || !pApiSetArray || pValueArray->Count <= 1) return NULL;
    if (!pwszParentName || !usParentLen) return NULL;

    // Skip first entry (default)
    dwLeft = 1;
    dwRight = pValueArray->Count - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pValueEntry = (PAPI_SET_VALUE_ENTRY_V3)(pValueArray->Array + dwMid);
        pwszHostName = (PWCHAR)((PBYTE)pApiSetArray + pValueEntry->NameOffset);
        dwHostNameLen = pValueEntry->NameLength / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usParentLen, dwHostNameLen);
        lCompare = 0x00;
        
        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParentName[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(pwszHostName[i]);
            
            if (wc1 < wc2)
            {
                lCompare = -1;
                break;
            }
            else if (wc1 > wc2)
            {
                lCompare = 1;
                break;
            }
        }
        
        if (lCompare == 0 && usParentLen != dwHostNameLen)
            lCompare = (usParentLen < dwHostNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pValueEntry;
        }
    }

    return NULL;
}

static BOOL ResolveApiSetV3(IN PAPI_SET_NAMESPACE_ARRAY_V3 pApiSetArray, IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    ULONGLONG                   ullPrefix          = 0x00;
    DWORD                       dwApiSetLen        = 0x00;
    PWSTR                       pwszNameNoPrefix   = NULL;
    USHORT                      usNameNoExtLen     = 0x00;
    DWORD                       dwLeft             = 0x00;
    DWORD                       dwRight            = 0x00;
    DWORD                       dwMid              = 0x00;
    LONG                        lCompare           = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V3 pNamespaceEntry    = NULL;
    PAPI_SET_VALUE_ARRAY_V3     pValueArray        = NULL;
    PAPI_SET_VALUE_ENTRY_V3     pValueEntry        = NULL;
    PWCHAR                      pwszEntryName      = NULL;
    PWCHAR                      pwszResolvedName   = NULL;
    DWORD                       dwEntryNameLen     = 0x00;
    DWORD                       dwCompareLen       = 0x00;
    DWORD                       dwResolvedLen      = 0x00;
    DWORD                       dwParentLen        = 0x00;

    if (!pApiSetArray || !pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    // Get API Set name length
    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);
    
    // Check minimum length (need at least "api-xxxx")
    if (dwApiSetLen < 8) return FALSE;

    // Verify prefix (api- or ext-)
    ullPrefix = *(ULONGLONG*)pwszApiSetName;
    ullPrefix &= ~(ULONGLONG)0x0000002000200020; // Convert to uppercase
    
    if (ullPrefix != 0x002D004900500041 && // "API-"
        ullPrefix != 0x002D005400580045)    // "EXT-"
        return FALSE;

    // Skip prefix ("api-" or "ext-" = 4 chars)
    pwszNameNoPrefix = (PWSTR)(pwszApiSetName + 4);
    usNameNoExtLen = (USHORT)(dwApiSetLen - 4);

    // Remove .dll extension if present
    if (usNameNoExtLen >= 4)
    {
        if (pwszNameNoPrefix[usNameNoExtLen - 4] == L'.' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 3]) == L'd' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 2]) == L'l' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 1]) == L'l')
        {
            usNameNoExtLen -= 4;
        }
    }

    if (!usNameNoExtLen) return FALSE;

    // Binary search for API Set entry
    pNamespaceEntry = NULL;
    dwLeft = 0x00;
    dwRight = pApiSetArray->Count - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pNamespaceEntry = (PAPI_SET_NAMESPACE_ENTRY_V3)(pApiSetArray->Array + dwMid);
        pwszEntryName = (PWCHAR)((PBYTE)pApiSetArray + pNamespaceEntry->NameOffset);
        dwEntryNameLen = pNamespaceEntry->NameLength / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usNameNoExtLen, dwEntryNameLen);
        lCompare = 0x00;
        
        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszNameNoPrefix[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(pwszEntryName[i]);
            
            if (wc1 < wc2)
            {
                lCompare = -1;
                break;
            }
            else if (wc1 > wc2)
            {
                lCompare = 1;
                break;
            }
        }
        
        if (lCompare == 0 && usNameNoExtLen != dwEntryNameLen)
            lCompare = (usNameNoExtLen < dwEntryNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            break; // Found
        }
    }

    // Check if we found it
    if (dwLeft > dwRight) return FALSE;
    if (!pNamespaceEntry) return FALSE;

    // Get value array
    pValueArray = (PAPI_SET_VALUE_ARRAY_V3)((PBYTE)pApiSetArray + pNamespaceEntry->DataOffset);
    if (!pValueArray) return FALSE;

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

    // Find appropriate host entry
    pValueEntry = NULL;
    if (pValueArray->Count > 1 && pwszParentName && dwParentLen)
    {
        pValueEntry = SearchApiSetHostV3(pApiSetArray, pValueArray, (PWSTR)pwszParentName, (USHORT)dwParentLen);
    }
    
    // Default to first entry if not found or no parent specified
    if (!pValueEntry && pValueArray->Count > 0)
    {
        pValueEntry = &pValueArray->Array[0];
    }

    if (!pValueEntry) return FALSE;

    // Copy resolved name
    pwszResolvedName = (PWCHAR)((PBYTE)pApiSetArray + pValueEntry->ValueOffset);
    dwResolvedLen = pValueEntry->ValueLength / sizeof(WCHAR);
    
    if (dwResolvedLen >= dwMaxLen) return FALSE;

    for (DWORD i = 0; i < dwResolvedLen; i++)
        pwszResolved[i] = pwszResolvedName[i];
    pwszResolved[dwResolvedLen] = L'\0';

    return TRUE;
}

static PAPI_SET_VALUE_ENTRY_V2 SearchApiSetHostV2(IN PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetArray, IN PAPI_SET_VALUE_ARRAY_V2 pValueArray, IN PWSTR pwszParentName, IN USHORT usParentLen)
{
    DWORD                   dwLeft         = 0x00;
    DWORD                   dwRight        = 0x00;
    DWORD                   dwMid          = 0x00;
    LONG                    lCompare       = 0x00;
    PAPI_SET_VALUE_ENTRY_V2 pValueEntry    = NULL;
    PWCHAR                  pwszHostName   = NULL;
    DWORD                   dwHostNameLen  = 0x00;
    DWORD                   dwCompareLen   = 0x00;

    if (!pValueArray || !pApiSetArray || pValueArray->Count <= 1) return NULL;
    if (!pwszParentName || !usParentLen) return NULL;

    // Skip first entry (default)
    dwLeft = 1;
    dwRight = pValueArray->Count - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pValueEntry = &pValueArray->Array[dwMid];
        pwszHostName = (PWCHAR)((PBYTE)pApiSetArray + pValueEntry->NameOffset);
        dwHostNameLen = pValueEntry->NameLength / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usParentLen, dwHostNameLen);
        lCompare = 0x00;
        
        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszParentName[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(pwszHostName[i]);
            
            if (wc1 < wc2)
            {
                lCompare = -1;
                break;
            }
            else if (wc1 > wc2)
            {
                lCompare = 1;
                break;
            }
        }
        
        if (lCompare == 0 && usParentLen != dwHostNameLen)
            lCompare = (usParentLen < dwHostNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            return pValueEntry;
        }
    }

    return NULL;
}

static BOOL ResolveApiSetV2(IN PAPI_SET_NAMESPACE_ARRAY_V2 pApiSetArray, IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    ULONGLONG                   ullPrefix          = 0x00;
    DWORD                       dwApiSetLen        = 0x00;
    PWSTR                       pwszNameNoPrefix   = NULL;
    USHORT                      usNameNoExtLen     = 0x00;
    DWORD                       dwLeft             = 0x00;
    DWORD                       dwRight            = 0x00;
    DWORD                       dwMid              = 0x00;
    LONG                        lCompare           = 0x00;
    PAPI_SET_NAMESPACE_ENTRY_V2 pNamespaceEntry    = NULL;
    PAPI_SET_VALUE_ARRAY_V2     pValueArray        = NULL;
    PAPI_SET_VALUE_ENTRY_V2     pValueEntry        = NULL;
    PWCHAR                      pwszEntryName      = NULL;
    PWCHAR                      pwszResolvedName   = NULL;
    DWORD                       dwEntryNameLen     = 0x00;
    DWORD                       dwCompareLen       = 0x00;
    DWORD                       dwResolvedLen      = 0x00;
    DWORD                       dwParentLen        = 0x00;

    if (!pApiSetArray || !pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    // Get API Set name length
    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);
    
    // Check minimum length (need at least "api-xxxx")
    if (dwApiSetLen < 8) return FALSE;

    // Verify prefix (v2 only supports "api-")
    ullPrefix = *(ULONGLONG*)pwszApiSetName;
    ullPrefix &= ~(ULONGLONG)0x0000002000200020; // Convert to uppercase
    
    if (ullPrefix != 0x002D004900500041) // "API-"
        return FALSE;

    // Skip prefix ("api-" = 4 chars)
    pwszNameNoPrefix = (PWSTR)(pwszApiSetName + 4);
    usNameNoExtLen = (USHORT)(dwApiSetLen - 4);

    // Remove .dll extension if present
    if (usNameNoExtLen >= 4)
    {
        if (pwszNameNoPrefix[usNameNoExtLen - 4] == L'.' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 3]) == L'd' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 2]) == L'l' &&
            CHAR_TO_LOWER_W(pwszNameNoPrefix[usNameNoExtLen - 1]) == L'l')
        {
            usNameNoExtLen -= 4;
        }
    }

    if (!usNameNoExtLen) return FALSE;

    // Binary search for API Set entry
    pNamespaceEntry = NULL;
    dwLeft = 0x00;
    dwRight = pApiSetArray->Count - 1;

    while (dwLeft <= dwRight)
    {
        dwMid = dwLeft + (dwRight - dwLeft) / 2;
        pNamespaceEntry = (PAPI_SET_NAMESPACE_ENTRY_V2)((PBYTE)pApiSetArray + sizeof(API_SET_NAMESPACE_ARRAY_V2) + (dwMid * sizeof(API_SET_NAMESPACE_ENTRY_V2)));
        pwszEntryName = (PWCHAR)((PBYTE)pApiSetArray + pNamespaceEntry->NameOffset);
        dwEntryNameLen = pNamespaceEntry->NameLength / sizeof(WCHAR);

        // Manual case-insensitive comparison
        dwCompareLen = min(usNameNoExtLen, dwEntryNameLen);
        lCompare = 0x00;
        
        for (DWORD i = 0; i < dwCompareLen; i++)
        {
            WCHAR wc1 = CHAR_TO_LOWER_W(pwszNameNoPrefix[i]);
            WCHAR wc2 = CHAR_TO_LOWER_W(pwszEntryName[i]);
            
            if (wc1 < wc2)
            {
                lCompare = -1;
                break;
            }
            else if (wc1 > wc2)
            {
                lCompare = 1;
                break;
            }
        }
        
        if (lCompare == 0 && usNameNoExtLen != dwEntryNameLen)
            lCompare = (usNameNoExtLen < dwEntryNameLen) ? -1 : 1;

        if (lCompare < 0)
        {
            if (dwMid == 0) break;
            dwRight = dwMid - 1;
        }
        else if (lCompare > 0)
        {
            dwLeft = dwMid + 1;
        }
        else
        {
            break; // Found
        }
    }

    // Check if we found it
    if (dwLeft > dwRight) return FALSE;
    if (!pNamespaceEntry) return FALSE;

    // Get value array
    pValueArray = (PAPI_SET_VALUE_ARRAY_V2)((PBYTE)pApiSetArray + pNamespaceEntry->DataOffset);
    if (!pValueArray) return FALSE;

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

    // Find appropriate host entry
    pValueEntry = NULL;
    if (pValueArray->Count > 1 && pwszParentName && dwParentLen)
    {
        pValueEntry = SearchApiSetHostV2(pApiSetArray, pValueArray, (PWSTR)pwszParentName, (USHORT)dwParentLen);
    }
    
    // Default to first entry if not found or no parent specified
    if (!pValueEntry && pValueArray->Count > 0)
    {
        pValueEntry = &pValueArray->Array[0];
    }

    if (!pValueEntry) return FALSE;

    // Copy resolved name
    pwszResolvedName = (PWCHAR)((PBYTE)pApiSetArray + pValueEntry->ValueOffset);
    dwResolvedLen = pValueEntry->ValueLength / sizeof(WCHAR);
    
    if (dwResolvedLen >= dwMaxLen) return FALSE;

    for (DWORD i = 0; i < dwResolvedLen; i++)
        pwszResolved[i] = pwszResolvedName[i];
    pwszResolved[dwResolvedLen] = L'\0';

    return TRUE;
}

static BOOL ResolveApiSet(IN PCWSTR pwszApiSetName, IN OPTIONAL PCWSTR pwszParentName, OUT PWSTR pwszResolved, IN DWORD dwMaxLen)
{
    PPEB                    pPeb            = NULL;
    PAPI_SET_NAMESPACE      pApiSetMap      = NULL;
    DWORD                   dwApiSetLen     = 0x00;
    DWORD                   dwParentLen     = 0x00;
    DWORD                   dwResolvedLen   = 0x00;
    PWCHAR                  pwszResolvedPtr = NULL;
    BOOL                    bResolved       = FALSE;

    if (!pwszApiSetName || !pwszResolved || !dwMaxLen) return FALSE;

    for (dwApiSetLen = 0; pwszApiSetName[dwApiSetLen]; dwApiSetLen++);
    
    if (dwApiSetLen < 8) return FALSE; 

    // Get parent length if specified
    if (pwszParentName)
    {
        for (dwParentLen = 0; pwszParentName[dwParentLen]; dwParentLen++);
    }

#ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
#else
    pPeb = NULL;
#endif

    if (!pPeb) return FALSE;

    pApiSetMap = (PAPI_SET_NAMESPACE)pPeb->ApiSetMap;
    if (!pApiSetMap) return FALSE;

    switch (pApiSetMap->Version)
    {
        case API_SET_SCHEMA_VERSION_V2:
        {
            bResolved = ResolveApiSetV2((PAPI_SET_NAMESPACE_ARRAY_V2)pApiSetMap, pwszApiSetName, pwszParentName, pwszResolved, dwMaxLen);
            break;
        }

        case API_SET_SCHEMA_VERSION_V3:
        {
            bResolved = ResolveApiSetV3((PAPI_SET_NAMESPACE_ARRAY_V3)pApiSetMap, pwszApiSetName, pwszParentName, pwszResolved, dwMaxLen);
            break;
        }

        case API_SET_SCHEMA_VERSION_V4:
        {
            bResolved = ResolveApiSetV4((PAPI_SET_NAMESPACE_ARRAY_V4)pApiSetMap, pwszApiSetName, pwszParentName, pwszResolved, dwMaxLen);
            break;
        }

        case API_SET_SCHEMA_VERSION_V6:
        {
            bResolved = ResolveApiSetV6((PAPI_SET_NAMESPACE_V6)pApiSetMap, pwszApiSetName, pwszParentName, pwszResolved, dwMaxLen);
            break;
        }

        default:
            return FALSE;
    }

    return bResolved;
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region STRING_HASHING_FUNCTIONS

static DWORD WINAPI ComputeFnv1aCharacterHash(IN LPCVOID pvString, IN BOOL bIsUnicode)
{
    DWORD   dwFnvHash       = 0x811C9DC5,
            dwCharValue     = 0x00;
    LPCSTR  pszAnsiPtr      = (LPCSTR)pvString;
    LPCWSTR pwszUnicodePtr  = (LPCWSTR)pvString;
    
    if (bIsUnicode)
    {
        while (*pwszUnicodePtr)
        {
            dwCharValue = (DWORD)*pwszUnicodePtr;
            
            dwFnvHash ^= dwCharValue;
            dwFnvHash *= 0x01000193;
            
            pwszUnicodePtr++;
        }
    }
    else
    {
        while (*pszAnsiPtr)
        {
            dwCharValue = (DWORD)((BYTE)*pszAnsiPtr);
            
            dwFnvHash ^= dwCharValue;
            dwFnvHash *= 0x01000193;
            
            pszAnsiPtr++;
        }
    }
    
    return dwFnvHash;
}

DWORD WINAPI HashStringFnv1aCharA(IN LPCSTR pszString, IN BOOL bCaseInsensitive)
{
    LPSTR   pszLowerBuffer  = NULL;
    DWORD   dwLength        = 0x00,
            dwHash          = 0x00;

    if (!pszString) return 0x00;
    
    while (pszString[dwLength]) dwLength++;
    
    if (bCaseInsensitive)
    {
        if (!(pszLowerBuffer = (LPSTR)LocalAlloc(LPTR, dwLength + 1))) return 0;
        
        for (DWORD i = 0; i < dwLength; i++)
        {
            if (pszString[i] >= 'A' && pszString[i] <= 'Z')
                pszLowerBuffer[i] = pszString[i] + 32;
            else
                pszLowerBuffer[i] = pszString[i];
        }
        
        dwHash = ComputeFnv1aCharacterHash((LPCVOID)pszLowerBuffer, FALSE);
        LocalFree(pszLowerBuffer);
        return dwHash;
    }
    
    return ComputeFnv1aCharacterHash((LPCVOID)pszString, FALSE);
}

DWORD WINAPI HashStringFnv1aCharW(IN LPCWSTR pwszString, IN BOOL bCaseInsensitive)
{
    LPWSTR  pwszLowerBuffer = NULL;
    DWORD   dwLength        = 0x00,
            dwHash          = 0x00;
    
    if (!pwszString) return 0x00;
    
    while (pwszString[dwLength]) dwLength++;
    
    if (bCaseInsensitive)
    {
        if (!(pwszLowerBuffer = (LPWSTR)LocalAlloc(LPTR, (dwLength + 1) * sizeof(WCHAR)))) return 0;
        
        for (DWORD i = 0; i < dwLength; i++)
        {
            if (pwszString[i] >= L'A' && pwszString[i] <= L'Z')
                pwszLowerBuffer[i] = pwszString[i] + 32;
            else
                pwszLowerBuffer[i] = pwszString[i];
        }
        
        dwHash = ComputeFnv1aCharacterHash((LPCVOID)pwszLowerBuffer, TRUE);
        LocalFree(pwszLowerBuffer);
        return dwHash;
    }

    return ComputeFnv1aCharacterHash((LPCVOID)pwszString, TRUE);
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#pragma region CUSTOM_GETAPI_FUNCTIONS

static HMODULE GetModuleHandleH(IN DWORD dwModuleNameHash) 
{
    PPEB                        pPeb            = NtCurrentPeb();
    PPEB_LDR_DATA               pLdr            = NULL;
    PLDR_DATA_TABLE_ENTRY       pEntry          = NULL;
    PLIST_ENTRY                 pListHead       = NULL, 
                                pListEntry      = NULL;

    if (!pPeb || !pPeb->Ldr) return NULL;

    pLdr        = (PPEB_LDR_DATA)pPeb->Ldr;
    pListHead   = &pLdr->InLoadOrderModuleList;
    pListEntry  = pListHead->Flink;
    pEntry      = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (!dwModuleNameHash) return (HMODULE)pEntry->DllBase;

    while (pListEntry != pListHead)
    {
        pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (pEntry->BaseDllName.Buffer)
        {
            if (dwModuleNameHash == HASH_STRING_W_CI(pEntry->BaseDllName.Buffer)) return (HMODULE)pEntry->DllBase;
        }
        
        pListEntry = pListEntry->Flink;

    }

	return NULL;
}

static FARPROC GetProcAddressH(IN HMODULE hModule, IN DWORD dwProcNameHash)
{

    PIMAGE_DOS_HEADER           pDosImgHdr          = NULL;
    PIMAGE_NT_HEADERS           pNtImgHdrs          = NULL;
    PIMAGE_EXPORT_DIRECTORY     pExportDir          = NULL;
    PIMAGE_DATA_DIRECTORY       pDataDir            = NULL;
    PDWORD                      pFuncNamesArray     = NULL;
    PDWORD                      pFuncAddrsArray     = NULL;
    PWORD                       pNameOrdsArray      = NULL;
    DWORD                       dwFunctionRva       = 0x00,
                                dwIndex             = 0x00;
    FARPROC                     pFunctionAddr       = NULL;

    if (!hModule || !dwProcNameHash) return NULL;

    pDosImgHdr = (PIMAGE_DOS_HEADER)hModule;
    if (pDosImgHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    pNtImgHdrs = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosImgHdr->e_lfanew);
    if (pNtImgHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;

    pDataDir        = &pNtImgHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    pExportDir      = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + pDataDir->VirtualAddress);
    pFuncAddrsArray = (PDWORD)((PBYTE)hModule + pExportDir->AddressOfFunctions);

    // Resolve Function By Ordinal
    if (HIWORD(dwProcNameHash) == 0)
    {
        WORD wOrdinal = LOWORD(dwProcNameHash);

        if (wOrdinal < pExportDir->Base || wOrdinal >= pExportDir->Base + pExportDir->NumberOfFunctions)
            return NULL;

        dwFunctionRva = pFuncAddrsArray[wOrdinal - pExportDir->Base];
    }
    // Resolve Function By Name 
    else
    {
        pFuncNamesArray = (PDWORD)((PBYTE)hModule + pExportDir->AddressOfNames);
        pNameOrdsArray  = (PWORD)((PBYTE)hModule + pExportDir->AddressOfNameOrdinals);
        
        for (dwIndex = 0; dwIndex < pExportDir->NumberOfNames; dwIndex++)
        {
            PCHAR pFuncName = (PCHAR)((PBYTE)hModule + pFuncNamesArray[dwIndex]);

            if (dwProcNameHash == HASH_STRING_A(pFuncName))
            {
                dwFunctionRva = pFuncAddrsArray[pNameOrdsArray[dwIndex]];
                break;
            }
        }

        if (dwIndex == pExportDir->NumberOfNames) return NULL;
    }

    // Calculate The Function Address Based On The RVA
    pFunctionAddr = (FARPROC)((PBYTE)hModule + dwFunctionRva);

    // Check If The Function Is Forwarded
    if (dwFunctionRva >= pDataDir->VirtualAddress && dwFunctionRva < (pDataDir->VirtualAddress + pDataDir->Size))
    {
        CHAR            szFuncName[MAX_PATH]    = { 0 };
        WCHAR           wszLibName[MAX_PATH]    = { 0 }; 
        PCHAR           pForwardFuncName        = (PCHAR)pFunctionAddr;
        DWORD           dwDotIdx                = 0x00;
        HMODULE         hForwardMod             = NULL;

        // Find The Dot Separator and Validate It's Within Export Directory Bounds
        while (pForwardFuncName[dwDotIdx] && 
               pForwardFuncName[dwDotIdx] != '.' &&
               (PBYTE)&pForwardFuncName[dwDotIdx] < ((PBYTE)pExportDir + pDataDir->Size))
        {
            dwDotIdx++;
        }

        if (!pForwardFuncName[dwDotIdx] || (PBYTE)&pForwardFuncName[dwDotIdx] >= ((PBYTE)pExportDir + pDataDir->Size))
        {
            DBGA("[!] Invalid Forwarded Function Format: %s", pForwardFuncName);
            return NULL;
        }

        // Copy Module Name
        for (DWORD i = 0; i < dwDotIdx && i < MAX_PATH - 5; i++) {
            wszLibName[i]   = (WCHAR)pForwardFuncName[i];
        }

        wszLibName[dwDotIdx]        = L'.';        
        wszLibName[dwDotIdx + 1]    = L'd';       
        wszLibName[dwDotIdx + 2]    = L'l'; 
        wszLibName[dwDotIdx + 3]    = L'l';
        wszLibName[dwDotIdx + 4]    = L'\0';  

        // Handle API Set DLLs (e.g., api-ms-win-core-memory-l1-1-0.dll, api-ms-win-crt-runtime-l1-1-0.dll)
        if ((wszLibName[0] == L'a' && wszLibName[1] == L'p' && wszLibName[2] == L'i' && wszLibName[3] == L'-') ||
            (wszLibName[0] == L'e' && wszLibName[1] == L'x' && wszLibName[2] == L't' && wszLibName[3] == L'-'))
        {
            if (!ResolveApiSet(wszLibName, NULL, wszLibName, MAX_PATH))
            {
                DBGA("[!] Failed To Resolve ApiSet: %ws", wszLibName);
                return NULL;
            }
        }

        // Copy Function Name or Ordinal
        for (DWORD i = 0; 
             pForwardFuncName[dwDotIdx + 1 + i] && 
             i < MAX_PATH - 1 &&
             (PBYTE)&pForwardFuncName[dwDotIdx + 1 + i] < ((PBYTE)pExportDir + pDataDir->Size);
             i++)
        {
            szFuncName[i] = pForwardFuncName[dwDotIdx + 1 + i];
        }

        // Get Module Base Address (Load It If Not Loaded)
        if (!(hForwardMod = GetModuleHandleH(HASH_STRING_W(wszLibName))))
        {
            if (!(hForwardMod = LoadLibraryW(wszLibName)))
            {
                DBGA("[!] LoadLibraryW Failed Loading %ws With Error: %d", wszLibName, GetLastError());
                return NULL;
            }
        }

        // Check If It's An Ordinal Forward (#123)
        if (szFuncName[0] == '#')
        {
            WORD wOrdinal = 0x00;

            for (DWORD i = 1; szFuncName[i]; i++)
            {
                if (szFuncName[i] >= '0' && szFuncName[i] <= '9')
                    wOrdinal = wOrdinal * 10 + (szFuncName[i] - '0');
                else
                {
                    DBGA("[!] Invalid Forwarded Ordinal: %s", szFuncName);
                    return NULL;
                }
            }
            // Resolve by ordinal
            pFunctionAddr = GetProcAddressH(hForwardMod, (DWORD)wOrdinal);
            return pFunctionAddr;
        }
        else
        {
            // Resolve by function name
            pFunctionAddr = GetProcAddressH(hForwardMod, HASH_STRING_A(szFuncName));
            return pFunctionAddr;
        }
    }

    return pFunctionAddr;
}

#pragma endregion

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
// Global Variables

DINMCLY_RSOLVD_FUNCTIONS g_ResolvedFunctions = { 0 };

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitializeAllDynamicFunctions()
{
    HMODULE     hNtdllModule        = NULL, 
                hKernel32Module     = NULL;
    SIZE_T      cbElementCount      = 0x00,
                cbFailedElement     = 0x00;
    PVOID*      ppCurrentElement    = NULL;
    
    if (g_ResolvedFunctions.pInitialized) return TRUE;

    RtlSecureZeroMemory(&g_ResolvedFunctions, sizeof(DINMCLY_RSOLVD_FUNCTIONS));
    
    if (!(hNtdllModule = GetModuleHandleH(FNV1A_NTDLLDLL)) || !(hKernel32Module = GetModuleHandleH(FNV1A_KERNEL32DLL)))
    {
        DBGA("[!] GetModuleHandleH Failed To Resolve Modules");
        return FALSE;
    }

    // CRSS Functions
    g_ResolvedFunctions.pBasepConstructSxsCreateProcessMessage        = (fnBasepConstructSxsCreateProcessMessage)GetProcAddressH(hKernel32Module, FNV1A_BASEPCONSTRUCTSXSCREATEPROCESSMESSAGE);
    g_ResolvedFunctions.pCsrCaptureMessageMultiUnicodeStringsInPlace  = (fnCsrCaptureMessageMultiUnicodeStringsInPlace)GetProcAddressH(hNtdllModule, FNV1A_CSRCAPTUREMESSAGEMULTIUNICODESTRINGSINPLACE);
    g_ResolvedFunctions.pCsrClientCallServer                          = (fnCsrClientCallServer)GetProcAddressH(hNtdllModule, FNV1A_CSRCLIENTCALLSERVER);
    
    // NTAPI Functions
    g_ResolvedFunctions.pNtCreateUserProcess                          = (fnNtCreateUserProcess)GetProcAddressH(hNtdllModule, FNV1A_NTCREATEUSERPROCESS);
    g_ResolvedFunctions.pRtlCreateProcessParametersEx                 = (fnRtlCreateProcessParametersEx)GetProcAddressH(hNtdllModule, FNV1A_RTLCREATEPROCESSPARAMETERSEX);
    g_ResolvedFunctions.pRtlDestroyProcessParameters                  = (fnRtlDestroyProcessParameters)GetProcAddressH(hNtdllModule, FNV1A_RTLDESTROYPROCESSPARAMETERS);
    g_ResolvedFunctions.pNtCreateDebugObject                          = (fnNtCreateDebugObject)GetProcAddressH(hNtdllModule, FNV1A_NTCREATEDEBUGOBJECT);
    g_ResolvedFunctions.pNtWaitForDebugEvent                          = (fnNtWaitForDebugEvent)GetProcAddressH(hNtdllModule, FNV1A_NTWAITFORDEBUGEVENT);
    g_ResolvedFunctions.pNtDebugContinue                              = (fnNtDebugContinue)GetProcAddressH(hNtdllModule, FNV1A_NTDEBUGCONTINUE);
    g_ResolvedFunctions.pNtRemoveProcessDebug                         = (fnNtRemoveProcessDebug)GetProcAddressH(hNtdllModule, FNV1A_NTREMOVEPROCESSDEBUG);
    g_ResolvedFunctions.pNtQueryInformationProcess                    = (fnNtQueryInformationProcess)GetProcAddressH(hNtdllModule, FNV1A_NTQUERYINFORMATIONPROCESS);
    g_ResolvedFunctions.pNtReadVirtualMemory                          = (fnNtReadVirtualMemory)GetProcAddressH(hNtdllModule, FNV1A_NTREADVIRTUALMEMORY);
    g_ResolvedFunctions.pNtWriteVirtualMemory                         = (fnNtWriteVirtualMemory)GetProcAddressH(hNtdllModule, FNV1A_NTWRITEVIRTUALMEMORY);
    g_ResolvedFunctions.pNtOpenProcessToken                           = (fnNtOpenProcessToken)GetProcAddressH(hNtdllModule, FNV1A_NTOPENPROCESSTOKEN);


    // Validate all function pointers (skipping pInitialized)
    cbElementCount      = (sizeof(DINMCLY_RSOLVD_FUNCTIONS) / sizeof(PVOID)) - 1;
    ppCurrentElement    = (PVOID*)&g_ResolvedFunctions + 1;

    for (SIZE_T i = 0; i < cbElementCount; i++)
    {
        if (ppCurrentElement[i] == NULL)
        {
            DBGA("[!] GetProcAddressH Failed For Function Of Index: %llu", i);
            return FALSE;
        }
    }

    g_ResolvedFunctions.pInitialized = (PVOID)TRUE;
    return TRUE;
}

