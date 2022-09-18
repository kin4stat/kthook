#include "gtest/gtest.h"
#include "kthook/kthook.hpp"
#include "test_common.hpp"

#define EQUALITY_CHECK(x)                                                \
    if (this->x != rhs.x) {                                              \
        return testing::AssertionFailure() << "this->" << (#x) << " != " \
                                           << "rhs." << (#x);            \
    }

struct BigAggregate {
    float v1;
    int v2;
    int v3;
    double v4;

    testing::AssertionResult operator==(const BigAggregate& rhs) const {
        EQUALITY_CHECK(v1);
        EQUALITY_CHECK(v2);
        EQUALITY_CHECK(v3);
        EQUALITY_CHECK(v4);
        return testing::AssertionSuccess() << "this is equal to rhs";
    }
};

struct MediumAggregate {
    int v1, v2, v3, v4;

    testing::AssertionResult operator==(const MediumAggregate& rhs) const {
        EQUALITY_CHECK(v1);
        EQUALITY_CHECK(v2);
        EQUALITY_CHECK(v3);
        EQUALITY_CHECK(v4);
        return testing::AssertionSuccess() << "this is equal to rhs";
    }
};

struct SmallAggregate {
    int v1, v2;

    testing::AssertionResult operator==(const SmallAggregate& rhs) const {
        EQUALITY_CHECK(v1);
        EQUALITY_CHECK(v2);
        return testing::AssertionSuccess() << "this is equal to rhs";
    }
};

constexpr BigAggregate big_args{1.0f, 2, 3, 4.0};
constexpr MediumAggregate medium_args{1, 2, 3, 4};
constexpr SmallAggregate small_args{1, 2};

DECLARE_SIZE_ENLARGER();

class A {
public:
    NO_OPTIMIZE static BigAggregate CCONV
        big_test_func(BigAggregate value) {
        SIZE_ENLARGER();
        return value;
    }
    NO_OPTIMIZE static MediumAggregate CCONV
        medium_test_func(MediumAggregate value) {
        SIZE_ENLARGER();
        return value;
    }
    NO_OPTIMIZE static SmallAggregate CCONV
        small_test_func(SmallAggregate value) {
        SIZE_ENLARGER();
        return value;
    }
};

TEST(kthook_simple, big_aggregate) {
    kthook::kthook_simple<decltype(&A::big_test_func)> hook{&A::big_test_func};
    hook.install();

    int counter = 0;
    hook.set_cb([&counter](const auto& hook, BigAggregate& value) {
        EXPECT_TRUE(big_args == value);
        ++counter;
        BigAggregate ret_val = hook.get_trampoline()(value);
        EXPECT_TRUE(big_args == ret_val);
        ++counter;
        return ret_val;
    });
    EXPECT_TRUE(A::big_test_func(big_args) == big_args);
    EXPECT_EQ(counter, 2);
}

TEST(kthook_signal, big_aggregate) {
    kthook::kthook_signal<decltype(&A::big_test_func)> hook{&A::big_test_func};

    {
        int counter = 0;
        auto conn = hook.before.scoped_connect(
            [&counter](const auto& hook, BigAggregate& value) -> std::optional<BigAggregate> {
                EXPECT_TRUE(big_args == value);
                ++counter;
                return std::nullopt;
            });
        EXPECT_TRUE(A::big_test_func(big_args) == big_args);
        EXPECT_EQ(counter, 1);
    }
    {
        int counter = 0;
        auto conn = hook.after.scoped_connect([&counter](const auto& hook, BigAggregate& ret_val, BigAggregate& value) {
            EXPECT_TRUE(big_args == value);
            ++counter;
            EXPECT_TRUE(ret_val == value);
            ++counter;
        });
        EXPECT_TRUE(A::big_test_func(big_args) == big_args);
        EXPECT_EQ(counter, 2);
    }
}

TEST(kthook_simple, medium_aggregate) {
    kthook::kthook_simple<decltype(&A::medium_test_func)> hook{&A::medium_test_func};
    hook.install();

    int counter = 0;

    hook.set_cb([&counter](const auto& hook, MediumAggregate& value) {
        EXPECT_TRUE(medium_args == value);
        ++counter;
        MediumAggregate ret_val = hook.get_trampoline()(value);
        EXPECT_TRUE(medium_args == ret_val);
        ++counter;
        return ret_val;
    });
    EXPECT_TRUE(A::medium_test_func(medium_args) == medium_args);
    EXPECT_EQ(counter, 2);
}

TEST(kthook_signal, medium_aggregate) {
    kthook::kthook_signal<decltype(&A::medium_test_func)> hook{&A::medium_test_func};

    {
        int counter = 0;
        auto conn = hook.before.scoped_connect(
            [&counter](const auto& hook, MediumAggregate& value) -> std::optional<MediumAggregate> {
                EXPECT_TRUE(medium_args == value);
                ++counter;
                return std::nullopt;
            });
        EXPECT_TRUE(A::medium_test_func(medium_args) == medium_args);
        EXPECT_EQ(counter, 1);
    }
    {
        int counter = 0;
        auto conn =
            hook.after.scoped_connect([&counter](const auto& hook, MediumAggregate& ret_val, MediumAggregate& value) {
                EXPECT_TRUE(medium_args == value);
                ++counter;
                EXPECT_TRUE(ret_val == value);
                ++counter;
            });
        EXPECT_TRUE(A::medium_test_func(medium_args) == medium_args);
        EXPECT_EQ(counter, 2);
    }
}

TEST(kthook_simple, small_aggregate) {
    kthook::kthook_simple<decltype(&A::small_test_func)> hook{&A::small_test_func};
    hook.install();

    int counter = 0;
    hook.set_cb([&counter](const auto& hook, SmallAggregate& value) {
        EXPECT_TRUE(small_args == value);
        ++counter;
        SmallAggregate ret_val = hook.get_trampoline()(value);
        EXPECT_TRUE(small_args == ret_val);
        ++counter;
        return ret_val;
    });
    EXPECT_TRUE(A::small_test_func(small_args) == small_args);
    EXPECT_EQ(counter, 2);
}

TEST(kthook_signal, small_aggregate) {
    kthook::kthook_signal<decltype(&A::small_test_func)> hook{&A::small_test_func};

    {
        int counter = 0;
        auto conn = hook.before.scoped_connect(
            [&counter](const auto& hook, SmallAggregate& value) -> std::optional<SmallAggregate> {
                EXPECT_TRUE(small_args == value);
                ++counter;
                return std::nullopt;
            });
        EXPECT_TRUE(A::small_test_func(small_args) == small_args);
        EXPECT_EQ(counter, 1);
    }
    {
        int counter = 0;
        auto conn =
            hook.after.scoped_connect([&counter](const auto& hook, SmallAggregate& ret_val, SmallAggregate& value) {
                EXPECT_TRUE(small_args == value);
                ++counter;
                EXPECT_TRUE(ret_val == value);
                ++counter;
            });
        EXPECT_TRUE(A::small_test_func(small_args) == small_args);
        EXPECT_EQ(counter, 2);
    }
}