#ifndef KTHOOK_ARCH_FWD_DECL_HPP_
#define KTHOOK_ARCH_FWD_DECL_HPP_

namespace kthook {
/**
 * @brief
 * Used to indicate that function takes args only in range @p Start - @p End
 *
 * Ranges can be combined via operator+
 *
 * Example usage:
 * @code
 * using callback_type = void(int, float, double, char, short, long);
 *
 * void myfunction(discarded& d, float, short, long);
 * void foo(callback_type);
 *
 * foo(keep<1> + keep<4, 5> + &myfunction); // ok
 * @endcode
 * @tparam Start Start of range 
 * @tparam End End of range
 */
template <std::size_t Start, std::size_t End = Start + 1>
constexpr auto keep = traits::make_index_range<Start, End>{};

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

template <typename FuncSig>
struct hook_traits;

template <typename FuncSig, template<typename> typename Traits = hook_traits>
class hook;

template <typename FuncSig, template<typename U> typename Traits = hook_traits, typename Discarded = void, typename
          Range = traits::range<>>
struct hook_interface;
}

#endif // KTHOOK_ARCH_FWD_DECL_HPP_