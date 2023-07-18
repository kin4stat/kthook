#include "gtest/gtest.h"
#include "kthook/kthook.hpp"
#include "test_common.hpp"

using test_signature = void (*)();
constexpr std::uintptr_t null_mem = 0x1000;

TEST(kthook_simple, null_func) {
    kthook::kthook_simple<test_signature> hook{null_mem};
    EXPECT_FALSE(hook.install());
}

#ifdef KTHOOK_USE_SIGNALS
TEST(kthook_signal, null_func) {
    kthook::kthook_signal<test_signature> hook{null_mem};
    EXPECT_FALSE(hook.install());
}
#endif

TEST(kthook_naked, null_func) {
    kthook::kthook_naked hook{null_mem};
    EXPECT_FALSE(hook.install());
}