"""
FNV-1a Hash implementation matching the C implementation for both ANSI and Unicode strings.
"""

import sys
import os


def compute_fnv1a_hash(data: bytes, is_unicode: bool = False) -> int:
    FNV_OFFSET_BASIS    = 0x811C9DC5
    FNV_PRIME           = 0x01000193
    
    hash_value = FNV_OFFSET_BASIS
    
    if is_unicode:
        # Process as 16-bit characters (UTF-16LE, little-endian)
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                char_value = data[i] | (data[i + 1] << 8)
            else:
                char_value = data[i]
            
            hash_value ^= char_value
            hash_value = (hash_value * FNV_PRIME) & 0xFFFFFFFF
    else:
        # Process as 8-bit characters (ANSI)
        for byte in data:
            hash_value ^= byte
            hash_value = (hash_value * FNV_PRIME) & 0xFFFFFFFF
    
    return hash_value


def to_lower_ascii(s: str) -> str:
    result = []
    for c in s:
        if 'A' <= c <= 'Z':
            result.append(chr(ord(c) + 32))
        else:
            result.append(c)
    return ''.join(result)


def hash_string_fnv1a_ansi(string: str, case_insensitive: bool = False) -> int:
    if not string:
        return 0
    
    if case_insensitive:
        string = to_lower_ascii(string)
    
    # Encode as ANSI (latin-1 for single-byte encoding)
    data = string.encode('latin-1')
    return compute_fnv1a_hash(data, is_unicode=False)


def hash_string_fnv1a_unicode(string: str, case_insensitive: bool = False) -> int:
    if not string:
        return 0
    
    if case_insensitive:
        string = to_lower_ascii(string)
    
    # Encode as UTF-16LE (Windows wide string format)
    data = string.encode('utf-16-le')
    return compute_fnv1a_hash(data, is_unicode=True)


def make_define_name(name: str) -> str:
    # Convert to uppercase and add prefix
    return "FNV1A_" + name.upper()


def print_aligned_defines(results: list[tuple[str, int]]) -> None:
    # Print all #define statements with aligned columns
    if not results:
        return
    
    print()
    
    # Generate all define names and find the maximum length
    define_names = [make_define_name(name) for name, _ in results]
    max_name_len = max(len(name) for name in define_names)
    
    # Print each line with proper alignment
    for define_name, (_, hash_value) in zip(define_names, results):
        padding = ' ' * (max_name_len - len(define_name))
        print(f"#define {define_name}{padding}    0x{hash_value:08X}")
    
    print()



def print_help(script_name: str) -> None:
    print(f"Usage: {script_name} [options] <string1> [string2] ...")
    print()
    print("Options:")
    print("  -a, --ansi              Use ANSI encoding (default)")
    print("  -u, --unicode           Use Unicode (UTF-16LE) encoding")
    print("  -i, --case-insensitive  Convert to lowercase before hashing")
    print("  -s, --case-sensitive    Case-sensitive hashing (default)")
    print("  -h, --help              Show this help message")
    print()
    print("Examples:")
    print(f"  {script_name} -i kernel32.dll ntdll.dll")
    print(f"  {script_name} NtAllocateVirtualMemory LoadLibraryA")
    print(f"  {script_name} -i HelloWorld HELLOWORLD helloworld")
    print(f"  {script_name} -u NtCreateFile VirtualAlloc")
    print()
    print("Note: ANSI and Unicode produce identical hashes for ASCII-only strings (characters 0-127)")  # Differences only appear with non-ASCII characters


def main():
    # Default to ANSI mode and case-sensitive
    use_unicode         = False
    case_insensitive    = False
    strings             = []
    script_name         = os.path.basename(sys.argv[0])
    
    # Parse command line arguments
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('-u', '--unicode'):
            use_unicode = True
        elif arg in ('-a', '--ansi'):
            use_unicode = False
        elif arg in ('-i', '--case-insensitive'):
            case_insensitive = True
        elif arg in ('-s', '--case-sensitive'):
            case_insensitive = False
        elif arg in ('-h', '--help'):
            print_help(script_name)
            return
        else:
            strings.append(arg)
        i += 1
    
    # If no strings provided, print help
    if not strings:
        print_help(script_name)
        return
    
    # Collect all results first
    results = []
    for s in strings:
        if use_unicode:
            hash_value = hash_string_fnv1a_unicode(s, case_insensitive)
        else:
            hash_value = hash_string_fnv1a_ansi(s, case_insensitive)
        results.append((s, hash_value))
    
    # Print with aligned columns
    print_aligned_defines(results)


if __name__ == "__main__":
    main()