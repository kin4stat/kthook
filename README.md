# kthook

X86 hooking library with functor callbacks support, so you can use lambdas with state, std::bind values etc...

[![Windows](https://github.com/kin4stat/kthook/actions/workflows/windows-build.yml/badge.svg)](https://github.com/kin4stat/kthook/actions/workflows/windows-build.yml)
[![Linux-x64](https://github.com/kin4stat/kthook/actions/workflows/linux-x64.yml/badge.svg)](https://github.com/kin4stat/kthook/actions/workflows/linux-x64.yml)
[![Linux-X86](https://github.com/kin4stat/kthook/actions/workflows/linux-x86.yml/badge.svg)](https://github.com/kin4stat/kthook/actions/workflows/linux-x86.yml)
[![Format check](https://github.com/kin4stat/kthook/actions/workflows/format_check.yml/badge.svg)](https://github.com/kin4stat/kthook/actions/workflows/format_check.yml)
## Usage

Clone repository and simply include kthook.hpp. C++17 compatible compiler required

## Examples

Callbacks backend is [ktsignal](https://github.com/KiN4StAt/ktsignal)

All hooks are automatically removed in the `kthook` destructor

All examples are shown based on this function

```cpp
int FASTCALL func1(float a, float b) {
    print_info(a, b);
    a = 50; b = 100;
    return 5;
}
```

### Basics

Creating hook and binding callback \
All callbacks are given a reference to kthook as the first argument. You can get return address and trampoline pointer from hook object. \
Hooks are installed after construction by default(last parameter can be set to false to prevent this)

```cpp
int main() {
    // func_ptr is pointer to function
    auto func_ptr = &func1;

    // func_type is int(CFASTCALL*)(float, float)
    using func_type = decltype(&func1);

    // Creating simple hook object with function type is template parameter and function pointer in constructor
    kthook::kthook_simple<func_type> hook{ func_ptr };

    // Connecting lambda callback that receiving function arguments by references
    hook.before += [](const auto& hook, float& a, float& b) {
        print_info(a, b);
        return std::nullopt;
    };

    /*
    [operator () at 31]: a = 30; b = 20
    [func1 at 16 ]: a = 30; b = 20
    */
    func1(30.f, 20.f);
}
```

Same thing with common hooks:
```cpp
int main() {
    // func_ptr is pointer to function
    auto func_ptr = &func1;

    // func_type is int(CFASTCALL*)(float, float)
    using func_type = decltype(&func1);

    auto cb = [](const auto& hook, float a, float b) {
        print_info(a, b);
        return hook.get_trampoline()(a, b);
    };

    // Creating simple hook object with function type is template parameter and function pointer in constructor
    kthook::kthook_simple<func_type> hook{ func_ptr, cb };

    /*
    [operator () at 31]: a = 30; b = 20
    [func1 at 16 ]: a = 30; b = 20
    */
    func1(30.f, 20.f);
}
```

Also you can bind after original function execution callbacks \
If original function return value is non void, return value reference passed at 2 argument

```cpp
int main() {
    auto func_ptr = &func1;
    using func_type = decltype(&func1);

    kthook::kthook_simple_t<func_type> hook{ func_ptr };

    hook.before.connect([](const auto& hook, float& a, float& b) { 
        print_info(a, b);
        // changing arguments
        a = 50.f, b = 30.f; 
        return std::nullopt;
        });

    // connect after callback
    hook.after.connect([](const auto& hook, int& return_value, float& a, float& b) {
        print_info(a, b);
        print_return_value(return_value);

        // changing return_value
        return_value = 20;
    });

    /*
    [operator () at 31]: a = 30; b = 20
    [func1 at 16 ]: a = 50; b = 30
    [operator () at 34]: a = 50; b = 30
    [operator () at 34]: return_value = 5;
    [main at 20]: return_value = 20;
    */
    auto ret_val = func1(30.f, 20.f);
    print_return_value(ret_val)
}
```

You can bind multiple before/after callbacks

```cpp
int main() {
    auto func_ptr = &func1;
    using func_type = decltype(&func1);

    kthook::kthook_simple_t<func_type> hook{ func_ptr };

    hook.before.connect([](const auto& hook, float& a, float& b) { print_info(a, b); return std::nullopt; });
    hook.before.connect([](const auto& hook, float& a, float& b) { a = 20; b = 30; return std::nullopt; });
    hook.after.connect([](const auto& hook, int& ret_val, float& a, float& b) { print_info(a, b); });
    hook.after.connect([](const auto& hook, int& ret_val, float& a, float& b) { print_info(a, b); });
    /*
    [operator () at 31]: a = 0; b = 0
    [func1 at 16]: a = 20; b = 30
    [operator () at 33]: a = 20; b = 30
    [operator () at 34]: a = 20; b = 30
    [main at 20]: return_value = 5;
    */
    auto ret_val = func1(30.f, 20.f);
    print_return_value(ret_val)
}
```

####  important notes
- Function return type must be default-constructible
- If any before callback wiil return false, and function return type is non void, the original function and after callback are not called. Default constructed value is returned
- If all before callbacks will return true, original function and after callbacks will be called

### Advanced Usage

There is a kthook that allows you to change the return value from a function without calling the original function \
For generating true return value, you can use `std::make_optional(value)` function \
For generating false return value, you can use `std::nullopt`

If function return type is void, then you can just return true/false see [notes](#important-notes)

```cpp
int main() {
    auto func_ptr = &func1;
    using func_type = decltype(&func1);

    kthook::kthook_signal<func_type> hook{ func_ptr };
    
    hook.before.connect([](const auto& hook, float& a, float& b) { print_info(a, b); return std::nullopt; });
    hook.after.connect([](const auto& hook, int& ret_val, float& a, float& b) { ret_val = 20; print_info(a, b); });
    /*
    [operator () at 44]: a = 30; b = 20
    [func1 at 16]: a = 30; b = 20
    [operator () at 45]: a = 30; b = 20
    [main at 20]: return_value = 20;
    */
    auto ret_val = func1(30.f, 20.f);
    print_return_value(ret_val)
}
```

Return false example

```cpp
int main() {
    auto func_ptr = &func1;
    using func_type = decltype(&func1);

    kthook::kthook_signal<func_type> hook{ func_ptr };
    
    hook.before.connect([](auto& hook, float& a, float& b) { print_info(a, b); return std::make_optional(20); });
    hook.after.connect([](auto& hook, int& ret_val, float& a, float& b) { ret_val = 20; print_info(a, b); });
    /*
    [operator () at 44]: a = 30; b = 20
    [main at 20]: return_value = 20;
    */
    auto ret_val = func1(30.f, 20.f);
    print_return_value(ret_val)
}
```

More examples can be found [here](https://github.com/kin4stat/kthook/tree/master/tests)

# Credits

[xbyak](https://github.com/herumi/xbyak) - x86/x86-64 JIT assembler \
[ktsignal](https://github.com/KiN4StAt/ktsignal) - C++17 signals library
# License

kthook is licensed under the MIT License, see LICENSE.txt for more information.
