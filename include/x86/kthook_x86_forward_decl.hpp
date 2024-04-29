#ifndef KTHOOK_X86_FORWARD_DECL_HPP_
#define KTHOOK_X86_FORWARD_DECL_HPP_

namespace kthook {
template <std::size_t... Is>
struct range {
  using value = std::index_sequence<Is...>;
};

/**
 * @brief Can be used to consume unused parameters inside callback
 *
 * Intended to be used with #keep
 *
 * See #keep documentation for usage example
 *
 * @note Can be used in user code only via reference
 */
struct discarded {
public:
  discarded(const discarded& other) = delete;
  discarded(discarded&& other) noexcept = delete;
  discarded& operator=(const discarded& other) = delete;
  discarded& operator=(discarded&& other) noexcept = delete;
  ~discarded() = default;

protected:
  discarded() = default;
};

/**
 * @brief Wrapper over reference in callback of the hook<br>
 * Can be used to access underlying address of the reference without any changes in hook signature
 * @tparam T type of the reference
 */
template <typename T>
struct reference {
  using type = T;

  explicit reference(T* address)
    : address(address) {
  }

  reference(T& ref)
    : address(&ref) {
  }

  operator T&() const noexcept {
    return *address;
  }

  T& get() const noexcept {
    return *address;
  }

  /**
   * @brief Sets the underlying address of the reference
   * @param address new address
   */
  void set_address(std::uintptr_t address) {
    this->address = reinterpret_cast<T*>(address);
  }

  /**
   * @brief Sets the underlying address of the reference
   * @param address new address
   */
  void set_address(T* address) {
    this->address = address;
  }

private:
  T* address{};
};

template <typename FuncSig, template<typename> typename Traits = hook_traits>
class hook;

template <typename FuncSig, template<typename U> typename Traits = hook_traits, typename Discarded = void, typename
          Range = range<>>
struct hook_interface;
}
#endif // #ifndef KTHOOK_X86_FORWARD_DECL_HPP_
