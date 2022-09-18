#include "gtest/gtest.h"
#include "kthook/kthook.hpp"
#include "test_common.hpp"

constexpr int return_default = 10;
constexpr int test_val = 5;

DECLARE_SIZE_ENLARGER();

class A {
public:
    NO_OPTIMIZE static int CCONV
    test_func(int value) {
        SIZE_ENLARGER();
        return value;
    }
};

class AT {
public:
    NO_OPTIMIZE static int TEST_THISCALL
    test_func(int value) {
        SIZE_ENLARGER();
        return value;
    }
};

class AF {
public:
    NO_OPTIMIZE static int TEST_FASTCALL
    test_func(int value) {
        SIZE_ENLARGER();
        return value;
    }
};

TEST(kthook_simple, function) {
    kthook::kthook_simple<decltype(&A::test_func)> hook{&A::test_func};
    hook.install();

    hook.set_cb([](const auto& hook, int& value) {
        hook.get_trampoline()(value);
        return return_default;
    });

    EXPECT_EQ(A::test_func(test_val), return_default);

    hook.set_cb([](const auto& hook, int& value) { return hook.get_trampoline()(return_default); });

    EXPECT_EQ(A::test_func(test_val), return_default);
}

TEST(kthook_naked, thiscall_function) {
    kthook::kthook_naked hook{reinterpret_cast<std::uintptr_t>(&AT::test_func)};
    hook.install();

    hook.set_cb([](const kthook::kthook_naked& hook) {
        auto& ctx = hook.get_context();

        auto arg1 = ctx.IARG1;
        EXPECT_EQ(arg1, test_val);
    });

    AT::test_func(test_val);
}

TEST(kthook_naked, fastcall_function) {
    kthook::kthook_naked hook{reinterpret_cast<std::uintptr_t>(&AF::test_func)};
    hook.install();

    hook.set_cb([](const kthook::kthook_naked& hook) {
        auto& ctx = hook.get_context();

        auto arg1 = ctx.IARG1;
        EXPECT_EQ(arg1, test_val);
    });

    AF::test_func(test_val);
}

TEST(kthook_signal, function) {
    kthook::kthook_signal<decltype(&A::test_func)> hook{&A::test_func};

    {
        auto connection = hook.before.scoped_connect([](const auto& hook, int& value) {
            value = return_default;
            return std::nullopt;
        });

        EXPECT_EQ(A::test_func(test_val), return_default);
    }

    {
        auto connection =
            hook.before.scoped_connect([&](const auto& hook, int& value) {
                return std::make_optional(return_default);
            });

        EXPECT_EQ(A::test_func(test_val), return_default);
    }

    {
        auto connection = hook.after.scoped_connect(
            [&](const auto& hook, int& return_value, int& value) { return_value = return_default; });

        EXPECT_EQ(A::test_func(test_val), return_default);
    }
}
