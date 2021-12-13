#include "gtest/gtest.h"
#include "kthook/kthook.hpp"

constexpr int return_default = 10;
constexpr int test_val = 5;

int
#ifdef KTHOOK_32
    TEST_CCONV
#endif
    test_func(int value) {

    return value;
}

TEST(KthookSimpleTest, HandlesSimpleUsage) {
    kthook::kthook_simple<decltype(&test_func)> hook{&test_func};
    hook.install();

    hook.set_cb([](const auto& hook, int& value) {
        hook.get_trampoline()(value);
        return return_default;
    });

    EXPECT_EQ(test_func(test_val), return_default);

    hook.set_cb([](const auto& hook, int& value) { return hook.get_trampoline()(return_default); });

    EXPECT_EQ(test_func(test_val), return_default);
}

TEST(KthookSiginalTest, HandlesSimpleUsage) {
    kthook::kthook_signal<decltype(&test_func)> hook{&test_func};

    {
        auto connection = hook.before.scoped_connect([](const auto& hook, int& value) {
            value = return_default;
            return std::nullopt;
        });

        EXPECT_EQ(test_func(test_val), return_default);
    }

    {
        auto connection =
            hook.before.scoped_connect([](const auto& hook, int& value) { return std::make_optional(return_default); });

        EXPECT_EQ(test_func(test_val), return_default);
    }

    {
        auto connection = hook.after.scoped_connect(
            [](const auto& hook, int& return_value, int& value) { return_value = return_default; });

        EXPECT_EQ(test_func(test_val), return_default);
    }
}