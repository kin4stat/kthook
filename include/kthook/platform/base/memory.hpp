#ifndef KTHOOK_PLATFORM_BASE_MEMORY_HPP_
#define KTHOOK_PLATFORM_BASE_MEMORY_HPP_

namespace kthook::platform {
enum class MemoryProt {
  PROTECT_RW,
  PROTECT_RWE,
  PROTECT_RE,
};

/**
 * @brief Can be used to obtain relative address
 * @param dest destination address
 * @param src source address
 * @param oplen length of the whole instruction, which is using relative address encoding
 * @return relative address, from src to dest
 */
inline std::uintptr_t get_relative_address(std::uintptr_t dest, std::uintptr_t src, std::size_t oplen = 5) {
  return dest - src - oplen;
}

/**
 * @brief Can be used to restore absolute address from relative address
 * @param RIP address of the instruction, which is using relative address encoding
 * @param rel relative address(instruction operand)
 * @param oplen length of the whole instruction, which is using relative address encoding
 * @return absolute address
 */
inline std::uintptr_t restore_absolute_address(std::uintptr_t RIP, std::uintptr_t rel, std::size_t oplen = 5) {
  return RIP + static_cast<std::int32_t>(rel) + oplen;
}
}

#endif // KTHOOK_PLATFORM_BASE_MEMORY_HPP_