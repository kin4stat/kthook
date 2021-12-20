#include "gtest/gtest.h"
#include "kthook/kthook.hpp"
#include "test_common.hpp"

using test_signature = void (*)();
constexpr std::uintptr_t null_mem = 0x1000;

#ifdef _WIN32
TEST(KthookSimpleTest, CREATE_NAME(HandlesKthookSimple)) {
    kthook::kthook_simple<test_signature> hook{null_mem};
    EXPECT_FALSE(hook.install());
}

TEST(KthookSiginalTest, CREATE_NAME(HandlesKthookSignal)) {
    kthook::kthook_signal<test_signature> hook{null_mem};
    EXPECT_FALSE(hook.install());
}
#else
TEST(empty, empty) {}
#endif