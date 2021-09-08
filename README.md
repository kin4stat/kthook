# kthook

X86 hooking library with functor callbacks support, so you can use lambdas with state, std::bind values etc...

## Usage

Clone repository and simply include kthook.hpp. C++17 compatible compiler required

## Examples

Callbacks backend is [ktsignal](https://github.com/KiN4StAt/ktsignal)

All hooks are automatically removed in the `kthook` destructor

All examples are shown based on this function

```cpp
int CFASTCALL func1(float a, float b) {
    print_info(a, b);
    a = 50; b = 100;
    return 5;
}
```

### Basics

Creating hook and binding callback \
In a simple hook object, the before event can return true to continue execution, or false to abort(useful in hooks with void return type) \
All hooks are installed after object creation by default

```cpp
int main() {
    // func_ptr is pointer to function
    auto func_ptr = &func1;

    // func_type is int(CFASTCALL*)(float, float)
    using func_type = decltype(&func1);

    // Creating simple hook object with function type is template parameter and function pointer in constructor
    kthook::kthook_simple_t<func_type> hook{ func_ptr };

    // Connecting lambda callback that receiving function arguments by references
    hook.before.connect([](float& a, float& b) { print_info(a, b); return true; });

    /*
    [operator () at 31]: a = 30; b = 20
    [func1 at 16 ]: a = 30; b = 20
    */
    func1(30.f, 20.f);
}
```

Creating a hook with a deferred installation, as well as deleting it

```cpp
int main() {
    // func_ptr is pointer to function
    auto func_ptr = &func1;

    // func_type is int(CFASTCALL*)(float, float)
    using func_type = decltype(&func1);

    // Creating simple hook object with function type is template parameter and function pointer in constructor
    kthook::kthook_simple_t<func_type> hook{ func_ptr, false };

    // Connecting lambda callback that receiving function arguments by references
    hook.before.connect([](float& a, float& b) { print_info(a, b); return true; });

    /*
    [func1 at 16 ]: a = 30; b = 20
    */
    func1(30.f, 20.f);
    
    // hook installing
    hook.install();

    /*
    [operator () at 31]: a = 30; b = 20
    [func1 at 16 ]: a = 30; b = 20
    */
    func1(30.f, 20.f);

    // hook removing
    hook.remove();

    /*
    [func1 at 16 ]: a = 30; b = 20
    */
    func1(30.f, 20.f);
}
```

Also you can bind after original function execution callbacks \
If original function return value is non void, return value reference passed at 1 argument

```cpp
int main() {
    auto func_ptr = &func1;
    using func_type = decltype(&func1);

    kthook::kthook_simple_t<func_type> hook{ func_ptr };

    hook.before.connect([](float& a, float& b) { 
        print_info(a, b);
        // changing arguments
        a = 50.f, b = 30.f; 
        return true;
        });

    // connect after callback
    hook.after.connect([](int& return_value, float& a, float& b) {
        print_info(a, b);
        print_return_value(return_value);

        // changing return_value
        return_value = 20;
        return true;
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

    hook.before.connect([](float& a, float& b) { print_info(a, b); return true; });
    hook.before.connect([](float& a, float& b) { a = 20; b = 30; return true; });
    hook.after.connect([](int& ret_val, float& a, float& b) { print_info(a, b); });
    hook.after.connect([](int& ret_val, float& a, float& b) { print_info(a, b); });
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

A few important notes about `kthook_simple_t`
- Function return type must be default-constructible
- If any before callback returns false, and function return type is non void, the original function and after callback are not called. Default constructed value is returned

### Advanced Usage

There is a kthook_t that allows you to change the return value from a function without calling the original function \
For generating true return value, you can use `kthook::return_value<T>::make_true()` function \
For generating false return value, you can use `kthook::return_value<T>::make_false(T value)` function

```cpp
int main() {
    auto func_ptr = &func1;
    using func_type = decltype(&func1);

    // creating kthook_t object with same interface as kthook_simple_t
    kthook::kthook_t<func_type> hook{ func_ptr };
    // binding callback returning true using helper function make_true
    hook.before.connect([](float& a, float& b) { print_info(a, b); return kthook::return_value<int>::make_true(); });
    hook.after.connect([](int& ret_val, float& a, float& b) { ret_val = 20; print_info(a, b); });
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

    kthook::kthook_t<func_type> hook{ func_ptr };
    // binding callback returning true using helper function make_false
    hook.before.connect([](float& a, float& b) { print_info(a, b); return kthook::return_value<int>::make_false(20); });
    hook.after.connect([](int& ret_val, float& a, float& b) { ret_val = 20; print_info(a, b); });
    /*
    [operator () at 44]: a = 30; b = 20
    [main at 20]: return_value = 20;
    */
    auto ret_val = func1(30.f, 20.f);
    print_return_value(ret_val)
}
```

### Complex Usage

`kthook_complex_t` gives you the opportunity to combine `kthook_simple_t` and `kthook_t`

```cpp
int main() {
    auto func_ptr = &func1;
    using func_type = decltype(&func1);

    // creating kthook_complex_t object with same interface as kthook_simple_t
    kthook::kthook_complex_t<func_type> hook{ func_ptr };
    // binding callback returning true using helper function make_true
    hook.before_simple.connect([](float& a, float& b) { print_info(a, b); return true; });
    hook.before.connect([](float& a, float& b) { print_info(a, b); return kthook::return_value<int>::make_true(); });
    hook.after.connect([](int& ret_val, float& a, float& b) { ret_val = 20; print_info(a, b); });
    /*
    [operator () at 31]: a = 30; b = 20
    [operator () at 45]: a = 30; b = 20
    [func1 at 16]: a = 30; b = 20
    [main at 20]: return_value = 20;
    */
    auto ret_val = func1(30.f, 20.f);
    print_return_value(ret_val)
}
```

# Credits

[xbyak](https://github.com/herumi/xbyak) - x86/x86-64 JIT assembler \
[ktsignal](https://github.com/KiN4StAt/ktsignal) - C++17 signals library
# License

kthook is licensed under the MIT License, see LICENSE.txt for more information.
