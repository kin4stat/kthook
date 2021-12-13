#include "gtest/gtest.h"
#include "kthook/kthook.hpp"

using test_signature = void (*)();
constexpr std::uintptr_t null_mem = 0x1000;

TEST(KthookSimpleTest, HandlesKthookSimple) {
    kthook::kthook_simple<test_signature> hook{null_mem};
    EXPECT_FALSE(hook.install());
}

TEST(KthookSiginalTest, HandlesKthookSignal) {
    kthook::kthook_signal<test_signature> hook{null_mem};
    EXPECT_FALSE(hook.install());
}