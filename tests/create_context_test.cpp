#include "gtest/gtest.h"
#include "kthook/kthook.hpp"
#include "test_common.hpp"

#include "xbyak/xbyak.h"

#define EQUALITY_CHECK(x)                                           \
    if (lhs.x != rhs.x) {               \
        return testing::AssertionFailure() << "lhs." << #x << "(" << lhs.x << ") != " << "rhs." << #x << "(" << rhs.x << ")"; \
    }

#define IMM(X) reinterpret_cast<std::uintptr_t>(X)

DECLARE_SIZE_ENLARGER();

class A {
public:
    NO_OPTIMIZE static void THISCALL_REPLACEMENT
    test_func() {
        SIZE_ENLARGER();
    }
};

Xbyak::CodeGenerator gen;
kthook::cpu_ctx ctx;
bool inited = [] {
    ctx.flags = new kthook::cpu_ctx::eflags;
    return true;
}();

testing::AssertionResult operator==(const kthook::cpu_ctx::eflags& lhs, const kthook::cpu_ctx::eflags& rhs) {
    EQUALITY_CHECK(CF)
    EQUALITY_CHECK(PF)
    EQUALITY_CHECK(AF)
    EQUALITY_CHECK(ZF)
    EQUALITY_CHECK(SF)
    EQUALITY_CHECK(TF)
    EQUALITY_CHECK(IF)
    EQUALITY_CHECK(DF)
    EQUALITY_CHECK(OF)
    EQUALITY_CHECK(IOPL)
    EQUALITY_CHECK(NT)
    EQUALITY_CHECK(RF)
    EQUALITY_CHECK(VM)
    EQUALITY_CHECK(AC)
    EQUALITY_CHECK(VIF)
    EQUALITY_CHECK(VIP)
    EQUALITY_CHECK(ID)
    return testing::AssertionSuccess() << "args are equal";
}

#ifdef KTHOOK_32
auto generate_code() {
    using namespace Xbyak::util;
    gen.pushfd();
    gen.push(eax);
    gen.push(ebx);
    gen.mov(eax, ptr[esp + 8]);
    gen.mov(ebx, ptr[IMM(&ctx.flags)]);
    gen.mov(ptr[ebx], eax);
    gen.pop(ebx);
    gen.pop(eax);
    gen.popfd();
    gen.mov(ptr[IMM(&ctx.eax)], eax);
    gen.mov(ptr[IMM(&ctx.edi)], edi);
    gen.mov(ptr[IMM(&ctx.esi)], esi);
    gen.mov(ptr[IMM(&ctx.ebp)], ebp);
    gen.mov(ptr[IMM(&ctx.ebx)], ebx);
    gen.mov(ptr[IMM(&ctx.edx)], edx);
    gen.mov(ptr[IMM(&ctx.ecx)], ecx);
    gen.mov(ptr[IMM(&ctx.eax)], eax);
    gen.jmp(reinterpret_cast<void*>(&A::test_func));
    return gen.getCode<decltype(&A::test_func)>();
}
testing::AssertionResult operator==(const kthook::cpu_ctx& lhs, const kthook::cpu_ctx& rhs) {
    EQUALITY_CHECK(edi)
    EQUALITY_CHECK(esi)
    EQUALITY_CHECK(ebp)
    EQUALITY_CHECK(ebx)
    EQUALITY_CHECK(edx)
    EQUALITY_CHECK(ecx)
    EQUALITY_CHECK(eax)
    return testing::AssertionSuccess() << "args are equal";
}
#else
auto generate_code() {
#define WRAP_MEM_REG(X) gen.mov(rax, X); gen.mov(ptr[IMM(&ctx.X)], rax)

    using namespace Xbyak::util;
    gen.pushfq();
    gen.push(rax);
    gen.mov(rax, ptr[rsp + 8]);
    gen.mov(ptr[IMM(ctx.flags)], rax);
    WRAP_MEM_REG(rbx);
    WRAP_MEM_REG(rcx);
    WRAP_MEM_REG(rdx);
    gen.add(rsp, sizeof(std::uintptr_t) * 2);
    WRAP_MEM_REG(rsp);
    gen.sub(rsp, sizeof(std::uintptr_t) * 2);
    WRAP_MEM_REG(rbp);
    WRAP_MEM_REG(rsi);
    WRAP_MEM_REG(rdi);
    WRAP_MEM_REG(r8);
    WRAP_MEM_REG(r9);
    WRAP_MEM_REG(r10);
    WRAP_MEM_REG(r11);
    WRAP_MEM_REG(r12);
    WRAP_MEM_REG(r13);
    WRAP_MEM_REG(r14);
    WRAP_MEM_REG(r15);
    gen.pop(rax);
    gen.mov(ptr[IMM(&ctx.rax)], rax);
    gen.popfq();
    gen.jmp(ptr[rip]);
    gen.db(IMM(&A::test_func), 8);
    return gen.getCode<decltype(&A::test_func)>();

#undef WRAP_MEM_REG
}

testing::AssertionResult operator==(const kthook::cpu_ctx& lhs, const kthook::cpu_ctx& rhs) {
    EQUALITY_CHECK(rax)
    EQUALITY_CHECK(rbx)
    EQUALITY_CHECK(rcx)
    EQUALITY_CHECK(rdx)
    EQUALITY_CHECK(rsp)
    EQUALITY_CHECK(rbp)
    EQUALITY_CHECK(rsi)
    EQUALITY_CHECK(rdi)
    EQUALITY_CHECK(r8)
    EQUALITY_CHECK(r9)
    EQUALITY_CHECK(r10)
    EQUALITY_CHECK(r11)
    EQUALITY_CHECK(r12)
    EQUALITY_CHECK(r13)
    EQUALITY_CHECK(r14)
    EQUALITY_CHECK(r15)
    return testing::AssertionSuccess() << "args are equal";
}
#endif

#undef EQUALITY_CHECK

TEST(kthook_simple, function) {
    kthook::kthook_simple<decltype(&A::test_func), kthook::kthook_option::kCreateContext> hook{&A::test_func};
    EXPECT_TRUE(hook.install());

    hook.set_cb([](const auto& hook, auto&&... args) {
        EXPECT_TRUE(hook.get_context() == ctx);
    });

    std::memset(ctx.flags, 0, sizeof(*ctx.flags));
    std::memset(&ctx, 0, sizeof(ctx) - sizeof(ctx.flags));
    generate_code()();
}

TEST(kthook_signal, function) {
    kthook::kthook_signal<decltype(&A::test_func), kthook::kthook_option::kCreateContext> hook{&A::test_func, false};
    EXPECT_TRUE(hook.install());

    hook.before.connect([](const auto& hook, auto&&... args) {
        EXPECT_TRUE(hook.get_context() == ctx);
        return false;
    });

    std::memset(ctx.flags, 0, sizeof(*ctx.flags));
    std::memset(&ctx, 0, sizeof(ctx) - sizeof(ctx.flags));
    generate_code()();
}

TEST(kthook_naked, function) {
    kthook::kthook_naked hook{reinterpret_cast<std::uintptr_t>(&A::test_func)};
    EXPECT_TRUE(hook.install());

    hook.set_cb([](const auto& hook, auto&&... args) {
        EXPECT_TRUE(hook.get_context() == ctx);
    });

    std::memset(ctx.flags, 0, sizeof(*ctx.flags));
    std::memset(&ctx, 0, sizeof(ctx) - sizeof(ctx.flags));
    generate_code()();
}
