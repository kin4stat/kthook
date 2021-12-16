#if defined(_MSC_VER)
#define NO_OPTIMIZE __declspec(noinline)
#elif defined(__GNUC__)
#define NO_OPTIMIZE [[gnu::noinline, gnu::optimize(0)]] __attribute__((__visibility__("hidden")))
#elif defined(__clang__)
#define NO_OPTIMIZE [[gnu::noinline, clang::optnone]]
#else
#error Unknown compiler
#endif

#define DECLARE_SIZE_ENLARGER() volatile unsigned long long a = 5;
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