#include "kthook/kthook.hpp"
#include <iostream>

#if defined(_MSC_VER)
#define NO_OPTIMIZE __declspec(noinline)
#elif defined(__clang__)
#define NO_OPTIMIZE [[gnu::noinline, clang::optnone]]
#elif defined(__GNUC__)
#define NO_OPTIMIZE [[gnu::noinline, gnu::optimize(0)]] __attribute__((__visibility__("hidden")))
#else
#error Unknown compiler
#endif

#define SIZE_ENLARGER()                       \
    static volatile unsigned long long a = 5; \
    switch (a) {                              \
        case 1:                               \
            a = 0;                            \
            break;                            \
        case 2:                               \
            a = 4;                            \
            break;                            \
        case 3:                               \
            a = 5;                            \
            break;                            \
    }

void foo(int, float, double) {
  SIZE_ENLARGER()
}

int main() {
  kthook::hook_safe<decltype(&foo)> hook;
  hook.set_dest(static_cast<void*>(&foo));
  hook.set_callback_wrapped(kthook::keep<1> +
                            [](kthook::interface auto& interface, int i) {
                              std::cout << i << " " << "0x" <<std::hex << interface.return_address() << std::endl;
                              auto x = interface.return_address();
                            });
  hook.install();

  foo(3, 2, 1);
  foo(1, 2, 3);
}