#include <random>
#include <limits>

#if defined(_MSC_VER)
#define NO_OPTIMIZE __declspec(noinline)
#elif defined(__clang__)
#define NO_OPTIMIZE [[gnu::noinline, clang::optnone]]
#elif defined(__GNUC__)
#define NO_OPTIMIZE [[gnu::noinline, gnu::optimize(0)]] __attribute__((__visibility__("hidden")))
#else
#error Unknown compiler
#endif

#define DECLARE_SIZE_ENLARGER() static volatile unsigned long long a = 5;
#define SIZE_ENLARGER() \
    switch (a) {        \
        case 1:         \
            a = 0;      \
            break;      \
        case 2:         \
            a = 4;      \
            break;      \
        case 3:         \
            a = 5;      \
            break;      \
    }

#ifdef KTHOOK_32
#define CCONV TEST_CCONV
#define TEST_THISCALL CTHISCALL
#define TEST_FASTCALL CFASTCALL
#ifdef IS_THISCALL
#define THISCALL_REPLACEMENT CSTDCALL
#else
#define THISCALL_REPLACEMENT TEST_CCONV
#endif
#else
#define THISCALL_REPLACEMENT
#define CCONV
#define TEST_THISCALL
#define TEST_FASTCALL
#endif

#define GET_RANDOM_BYTE() [] {     std::random_device dev;\
                                    std::mt19937 rng(dev());\
                                    std::uniform_int_distribution<unsigned char> dist(std::numeric_limits<unsigned char>::min(),std::numeric_limits<unsigned char>::max());\
                                    return dist(rng);\
                           }()

#define GET_RANDOM_WORD() [] {     std::random_device dev;\
                                    std::mt19937 rng(dev());\
                                    std::uniform_int_distribution<unsigned short> dist(std::numeric_limits<unsigned short>::min(),std::numeric_limits<unsigned short>::max());\
                                    return dist(rng);\
                           }()

#define GET_RANDOM_DWORD() [] {     std::random_device dev;\
                                    std::mt19937 rng(dev());\
                                    std::uniform_int_distribution<unsigned long> dist(std::numeric_limits<unsigned long>::min(),std::numeric_limits<unsigned long>::max());\
                                    return dist(rng);\
                            }()

#define GET_RANDOM_QWORD() [] {     std::random_device dev;\
                                    std::mt19937 rng(dev());\
                                    std::uniform_int_distribution<unsigned long long> dist(std::numeric_limits<unsigned long long>::min(),std::numeric_limits<unsigned long long>::max());\
                                    return dist(rng);\
                            }()

#define GET_RANDOM_INT() [] {     std::random_device dev;\
                                    std::mt19937 rng(dev());\
                                    std::uniform_int_distribution<int> dist(std::numeric_limits<int>::min(),std::numeric_limits<int>::max());\
                                    return dist(rng);\
                          }()

#if defined(KTHOOK_64_WIN)
#define IARG1 rcx
#define IARG2 rdx
#define IARG3 r8
#define IARG4 r9
#elif defined(KTHOOK_64_GCC)
#define IARG1 rdi
#define IARG2 rsi
#define IARG3 rdx
#define IARG4 rcx
#else
#define IARG1 ecx
#endif
