#ifndef KTHOOK_BASE_UTILS_HPP_
#define KTHOOK_BASE_UTILS_HPP_

namespace kthook::utils{
template<typename Function>
class scope_exit {
public:
    scope_exit(Function f) : finalizer(std::move(f)) {}
    ~scope_exit() { finalizer(); }
private:
    Function finalizer;
};
}
#endif // KTHOOK_BASE_UTILS_HPP_