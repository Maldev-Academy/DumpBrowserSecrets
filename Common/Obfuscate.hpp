#ifndef OBFUSCATE_HPP
#define OBFUSCATE_HPP

#include <cstdint>
#include <cstddef>
#include <utility>

namespace Obf {

    constexpr uint32_t GenerateSeed() {
        uint32_t dwSeed = 0x5A5A5A5A;
        // Using __DATE__ (e.g., "Jan  9 2026") 
        for (const char c : __DATE__) {
            dwSeed ^= (dwSeed << 5) + (dwSeed >> 2) + static_cast<uint32_t>(c);
        }
        // Using __TIME__ (e.g., "14:32:07")
        for (const char c : __TIME__) {
            dwSeed ^= (dwSeed << 3) + (dwSeed >> 4) + static_cast<uint32_t>(c);
        }
        return dwSeed; // This is later XOR'd with __LINE__ 
    }
    constexpr uint8_t GetKeyByte(uint32_t dwSeed, size_t idx) {
        return static_cast<uint8_t>((dwSeed >> ((idx % 4) * 8)) ^ (idx * 0x13));
    }

    // ---------------------------------------------------------------------------------------------------------
    // ANSI STRING OBFUSCATION 

    template <size_t N, uint32_t Seed>
    class ObfuscatedStringA {
    private:
        char m_szEncrypted[N]{};

        constexpr char EncryptChar(char c, size_t idx) const {
            return static_cast<char>(c ^ GetKeyByte(Seed, idx));
        }

    public:
        template <size_t... Is>
        constexpr ObfuscatedStringA(const char(&str)[N], std::index_sequence<Is...>)
            : m_szEncrypted{ EncryptChar(str[Is], Is)... } {}

        constexpr ObfuscatedStringA(const char(&str)[N])
            : ObfuscatedStringA(str, std::make_index_sequence<N>{}) {}

        __forceinline void Decrypt(char* pszBuffer, size_t cbBuffer) const {
            size_t i = 0;
            for (; i < N - 1 && i < cbBuffer - 1; ++i) {
                pszBuffer[i] = m_szEncrypted[i] ^ GetKeyByte(Seed, i);
            }
            pszBuffer[i] = '\0';
        }

        __forceinline char operator[](size_t idx) const {
            return (idx < N - 1) ? (m_szEncrypted[idx] ^ GetKeyByte(Seed, idx)) : '\0';
        }

        constexpr size_t Size() const { return N; }
    };

    // ---------------------------------------------------------------------------------------------------------
    // WIDE STRING OBFUSCATION 

    template <size_t N, uint32_t Seed>
    class ObfuscatedStringW {
    private:
        wchar_t m_wszEncrypted[N]{};

        constexpr wchar_t EncryptChar(wchar_t c, size_t idx) const {
            return static_cast<wchar_t>(c ^ (GetKeyByte(Seed, idx) | (GetKeyByte(Seed, idx + 1) << 8)));
        }

    public:
        template <size_t... Is>
        constexpr ObfuscatedStringW(const wchar_t(&str)[N], std::index_sequence<Is...>)
            : m_wszEncrypted{ EncryptChar(str[Is], Is)... } {}

        constexpr ObfuscatedStringW(const wchar_t(&str)[N])
            : ObfuscatedStringW(str, std::make_index_sequence<N>{}) {}

        __forceinline void Decrypt(wchar_t* pwszBuffer, size_t cchBuffer) const {
            size_t i = 0;
            for (; i < N - 1 && i < cchBuffer - 1; ++i) {
                pwszBuffer[i] = m_wszEncrypted[i] ^ (GetKeyByte(Seed, i) | (GetKeyByte(Seed, i + 1) << 8));
            }
            pwszBuffer[i] = L'\0';
        }

        constexpr size_t Size() const { return N; }
    };

    // ---------------------------------------------------------------------------------------------------------
    // GUID OBFUSCATION

    struct OBFGUID_T {
        uint32_t Data1;
        uint16_t Data2;
        uint16_t Data3;
        uint8_t  Data4[8];
    };

    template <uint32_t Seed>
    class ObfuscatedGuid {
    private:
        OBFGUID_T m_GuidEncrypted{};

        static constexpr uint8_t EncryptByte(uint8_t b, size_t idx) {
            return b ^ GetKeyByte(Seed, idx);
        }

    public:
        constexpr ObfuscatedGuid(uint32_t d1, uint16_t d2, uint16_t d3,
                                  uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3,
                                  uint8_t b4, uint8_t b5, uint8_t b6, uint8_t b7)
            : m_GuidEncrypted{
                d1 ^ ((uint32_t)GetKeyByte(Seed, 0) | ((uint32_t)GetKeyByte(Seed, 1) << 8) |
                      ((uint32_t)GetKeyByte(Seed, 2) << 16) | ((uint32_t)GetKeyByte(Seed, 3) << 24)),
                static_cast<uint16_t>(d2 ^ (GetKeyByte(Seed, 4) | (GetKeyByte(Seed, 5) << 8))),
                static_cast<uint16_t>(d3 ^ (GetKeyByte(Seed, 6) | (GetKeyByte(Seed, 7) << 8))),
                {
                    EncryptByte(b0, 8),  EncryptByte(b1, 9),
                    EncryptByte(b2, 10), EncryptByte(b3, 11),
                    EncryptByte(b4, 12), EncryptByte(b5, 13),
                    EncryptByte(b6, 14), EncryptByte(b7, 15)
                }
            } {}

        __forceinline void Decrypt(void* pGuid) const {
            OBFGUID_T* p = static_cast<OBFGUID_T*>(pGuid);
            p->Data1 = m_GuidEncrypted.Data1 ^
                ((uint32_t)GetKeyByte(Seed, 0) | ((uint32_t)GetKeyByte(Seed, 1) << 8) |
                 ((uint32_t)GetKeyByte(Seed, 2) << 16) | ((uint32_t)GetKeyByte(Seed, 3) << 24));
            p->Data2 = m_GuidEncrypted.Data2 ^ (GetKeyByte(Seed, 4) | (GetKeyByte(Seed, 5) << 8));
            p->Data3 = m_GuidEncrypted.Data3 ^ (GetKeyByte(Seed, 6) | (GetKeyByte(Seed, 7) << 8));
            for (int i = 0; i < 8; ++i) {
                p->Data4[i] = m_GuidEncrypted.Data4[i] ^ GetKeyByte(Seed, 8 + i);
            }
        }
    };

    // ---------------------------------------------------------------------------------------------------------
    // BYTE ARRAY OBFUSCATION

    template <size_t N, uint32_t Seed>
    class ObfuscatedBytes {
    private:
        uint8_t m_pbEncrypted[N];

    public:
        // Runtime encryption (still hidden in binary - encrypted at startup)
        template <typename... Args>
        constexpr ObfuscatedBytes(Args... args) : m_pbEncrypted{} {
            uint8_t temp[N] = { static_cast<uint8_t>(args)... };
            for (size_t i = 0; i < N; ++i) {
                m_pbEncrypted[i] = temp[i] ^ GetKeyByte(Seed, i);
            }
        }

        __forceinline void Decrypt(uint8_t* pBuffer, size_t cbBuffer) const {
            for (size_t i = 0; i < N && i < cbBuffer; ++i) {
                pBuffer[i] = m_pbEncrypted[i] ^ GetKeyByte(Seed, i);
            }
        }

        constexpr size_t Size() const { return N; }
    };

} // namespace Obf


// =============================================================================================================
// =============================================================================================================
// EXPRESSION MACROS - LOCAL THREAD

#define OBFA_S(str)                                                                                             \
    ([]() -> char* {                                                                                            \
        constexpr static ::Obf::ObfuscatedStringA<sizeof(str), ::Obf::GenerateSeed() ^ __LINE__> obf(str);      \
        static thread_local char buffer[sizeof(str)];                                                           \
        obf.Decrypt(buffer, sizeof(buffer));                                                                    \
        return buffer;                                                                                          \
    }())

#define OBFW_S(str)                                                                                                             \
    ([]() -> wchar_t* {                                                                                                         \
        constexpr static ::Obf::ObfuscatedStringW<sizeof(str)/sizeof(wchar_t), ::Obf::GenerateSeed() ^ __LINE__> obf(str);      \
        static thread_local wchar_t buffer[sizeof(str)/sizeof(wchar_t)];                                                        \
        obf.Decrypt(buffer, sizeof(str)/sizeof(wchar_t));                                                                       \
        return buffer;                                                                                                          \
    }())

#define OBFGUID_S(d1, d2, d3, b0, b1, b2, b3, b4, b5, b6, b7)                                    \
    ([]() -> GUID* {                                                                             \
        constexpr static ::Obf::ObfuscatedGuid<::Obf::GenerateSeed() ^ __LINE__> obf(            \
            d1, d2, d3, b0, b1, b2, b3, b4, b5, b6, b7                                           \
        );                                                                                       \
        static thread_local GUID guid;                                                           \
        obf.Decrypt(&guid);                                                                      \
        return &guid;                                                                            \
    }())


#define OBFBYTES_S(count, ...)                                                                      \
    ([]() -> uint8_t* {                                                                             \
        static ::Obf::ObfuscatedBytes<count, ::Obf::GenerateSeed() ^ __LINE__> obf(__VA_ARGS__);    \
        static thread_local uint8_t buffer[count];                                                  \
        obf.Decrypt(buffer, count);                                                                 \
        return buffer;                                                                              \
    }())


// =============================================================================================================
// RAW MACROS - HEAP ALLOCATED

#define OBFA(str)                                                                                                   \
        ([]() -> const auto& {                                                                                      \
            constexpr static ::Obf::ObfuscatedStringA<sizeof(str), ::Obf::GenerateSeed() ^ __LINE__> obf(str);      \
            return obf;                                                                                             \
        }())

#define OBFW(str)                                                                                                                   \
        ([]() -> const auto& {                                                                                                      \
            constexpr static ::Obf::ObfuscatedStringW<sizeof(str)/sizeof(wchar_t), ::Obf::GenerateSeed() ^ __LINE__> obf(str);      \
            return obf;                                                                                                             \
        }())

#define OBFGUID(d1, d2, d3, b0, b1, b2, b3, b4, b5, b6, b7)                                         \
        ([]() -> const auto& {                                                                      \
            constexpr static ::Obf::ObfuscatedGuid<::Obf::GenerateSeed() ^ __LINE__> obf(           \
                d1, d2, d3, b0, b1, b2, b3, b4, b5, b6, b7                                          \
            );                                                                                      \
            return obf;                                                                             \
        }())

#define OBFBYTES(count, ...)                                                                        \
    ([]() -> const auto& {                                                                          \
        static ::Obf::ObfuscatedBytes<count, ::Obf::GenerateSeed() ^ __LINE__> obf(__VA_ARGS__);    \
        return obf;                                                                                 \
    }())


#endif // OBFUSCATE_HPP