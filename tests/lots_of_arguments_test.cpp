#include "gtest/gtest.h"
#include "kthook/kthook.hpp"
#include "test_common.hpp"

constexpr std::tuple<int, float, long long, double, short, char, int, long double, float, int, int, long, long long,
                     int, int, int>
    test_args{1, 2.0f, 3, 4.0, 5, 6, 7, 8.0, 9.0f, 10, 11, 12, 13, 14, 15, 16};

#define EQUALITY_CHECK(x)                                           \
    if (std::get<x>(test_args) != std::get<x>(rhs)) {               \
        return testing::AssertionFailure() << "not equal at " << x; \
    }

inline testing::AssertionResult check_equality(decltype(test_args) rhs) {
    EQUALITY_CHECK(0);
    EQUALITY_CHECK(1);
    EQUALITY_CHECK(2);
    EQUALITY_CHECK(3);
    EQUALITY_CHECK(4);
    EQUALITY_CHECK(5);
    EQUALITY_CHECK(6);
    EQUALITY_CHECK(7);
    EQUALITY_CHECK(8);
    EQUALITY_CHECK(9);
    EQUALITY_CHECK(10);
    EQUALITY_CHECK(11);
    EQUALITY_CHECK(12);
    EQUALITY_CHECK(13);
    EQUALITY_CHECK(14);
    EQUALITY_CHECK(15);
    return testing::AssertionSuccess() << "args are equal";
}

DECLARE_SIZE_ENLARGER();

#undef EQUALITY_CHECK

class A {
public:
    NO_OPTIMIZE static void CCONV
        test_func(int v1, float v2, long long v3, double v4, short v5, char v6, int v7, long double v8, float v9,
                  int v10, int v11, long v12, long long v13, int v14, int v15, int v16) {
        SIZE_ENLARGER();
    }
};

TEST(kthook_simple, function) {
    kthook::kthook_simple<decltype(&A::test_func)> hook{&A::test_func};
    hook.install();

    int counter = 0;
    hook.set_cb([&counter](const auto& hook, auto&&... args) {
        EXPECT_TRUE(check_equality(decltype(test_args){args...}));
        ++counter;
        hook.get_trampoline()(args...);
    });
    std::apply(&A::test_func, test_args);
    EXPECT_EQ(counter, 1);
}

TEST(kthook_simple, arg_skip) {
    kthook::kthook_simple<decltype(&A::test_func)> hook{&A::test_func};
    hook.install();

    int counter = 0;
    hook.set_cb_wrapped([&counter](const auto& h, kthook::take<8> v1_v8, float v9, kthook::take<7> v10_v16) {

        ++counter;

        return h.call_trampoline(v1_v8, v9, v10_v16);
    });

    std::apply(&A::test_func, test_args);
    EXPECT_EQ(counter, 1);
}

TEST(kthook_signal_before, function) {
    kthook::kthook_signal<decltype(&A::test_func)> hook{&A::test_func};
    int counter = 0;
    hook.before += [&counter](const auto& hook, auto&&... args) {
        EXPECT_TRUE(check_equality(decltype(test_args){args...}));
        ++counter;
        return true;
    };
    std::apply(&A::test_func, test_args);
    EXPECT_EQ(counter, 1);
}

TEST(kthook_signal_after, function) {
    kthook::kthook_signal<decltype(&A::test_func)> hook{&A::test_func};
    int counter = 0;
    hook.after += [&counter](const auto& hook, auto&&... args) {
        EXPECT_TRUE(check_equality(decltype(test_args){args...}));
        ++counter;
    };
    std::apply(&A::test_func, test_args);
    EXPECT_EQ(counter, 1);
}