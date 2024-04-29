#ifndef KTHOOK_CPU_CTX_X86_64_HPP_
#define KTHOOK_CPU_CTX_X86_64_HPP_

#pragma push_macro("M128")
#ifdef _MSC_VER
#include <xmmintrin.h>
#define M128 __m128
#else
#define M128 __float128
#endif

namespace kthook {
/**
 * @brief General purpose CPU registers
 *
 * r pre/postfix means 64 bit sized register
 *
 * e pre/postfix means lower 32 bits of register
 *
 * x pre/postfix means lower 16 bits of register
 *
 * h pre/postfix means higher 8 bits of lower 16 bit part of register
 *
 * l pre/postfix means lower 8 bits of register
 */
enum class REG : unsigned {
  rax = 0b0111'1111,
  eax = 0b0111'0111,
  ax = 0b0111'0011,
  ah = 0b0111'0010,
  al = 0b0111'0001,

  rbx = 0b0100'1111,
  ebx = 0b0100'0111,
  bx = 0b0100'0011,
  bh = 0b0100'0010,
  bl = 0b0100'0001,

  rcx = 0b0110'1111,
  ecx = 0b0110'0111,
  cx = 0b0110'0011,
  ch = 0b0110'0010,
  cl = 0b0110'0001,

  rdx = 0b0101'1111,
  edx = 0b0101'0111,
  dx = 0b0101'0011,
  dh = 0b0101'0010,
  dl = 0b0101'0001,

  rsp = 0b0011'1111,
  esp = 0b0011'0111,
  sp = 0b0011'0011,
  sph = 0b0011'0010,
  spl = 0b0011'0001,

  rbp = 0b0010'1111,
  ebp = 0b0010'0111,
  bp = 0b0010'0011,
  bph = 0b0010'0010,
  bpl = 0b0010'0001,

  rsi = 0b0001'1111,
  esi = 0b0001'0111,
  si = 0b0001'0011,
  sih = 0b0001'0010,
  sil = 0b0001'0001,

  rdi = 0b0000'1111,
  edi = 0b0000'0111,
  di = 0b0000'0011,
  dih = 0b0000'0010,
  dil = 0b0000'0001,

#ifdef KTHOOK64
  r8 = 0b1000'1111,
  e8 = 0b1000'0111,
  x8 = 0b1000'0011,
  h8 = 0b1000'0010,
  l8 = 0b1000'0001,

  r9 = 0b1001'1111,
  e9 = 0b1001'0111,
  x9 = 0b1001'0011,
  h9 = 0b1001'0010,
  l9 = 0b1001'0001,

  r10 = 0b1010'1111,
  e10 = 0b1010'0111,
  x10 = 0b1010'0011,
  h10 = 0b1010'0010,
  l10 = 0b1010'0001,

  r11 = 0b1011'1111,
  e11 = 0b1011'0111,
  x11 = 0b1011'0011,
  h11 = 0b1011'0010,
  l11 = 0b1011'0001,

  r12 = 0b1100'1111,
  e12 = 0b1100'0111,
  x12 = 0b1100'0011,
  h12 = 0b1100'0010,
  l12 = 0b1100'0001,

  r13 = 0b1101'1111,
  e13 = 0b1101'0111,
  x13 = 0b1101'0011,
  h13 = 0b1101'0010,
  l13 = 0b1101'0001,

  r14 = 0b1110'1111,
  e14 = 0b1110'0111,
  x14 = 0b1110'0011,
  h14 = 0b1110'0010,
  l14 = 0b1110'0001,

  r15 = 0b1111'1111,
  e15 = 0b1111'0111,
  x15 = 0b1111'0011,
  h15 = 0b1111'0010,
  l15 = 0b1111'0001,
#endif
};

/**
 * @brief CPU segment registers
 */
enum class SEGMENT : unsigned {
  GS = 0,
  ES = 1,
  CS = 2,
  FS = 3,
  DS = 4,
  SS = 5,
};

/**
 * @brief SSE registers
 */
enum XMM: unsigned {
  XMM0,
  XMM1,
  XMM2,
  XMM3,
  XMM4,
  XMM5,
  XMM6,
  XMM7,
#ifdef KTHOOK_64
  XMM8,
  XMM9,
  XMM10,
  XMM11,
  XMM12,
  XMM13,
  XMM14,
  XMM15,
#endif
};

/**
 * @brief x87 fpu registers
 */
enum ST: unsigned {
  ST0,
  ST1,
  ST2,
  ST3,
  ST4,
  ST5,
  ST6,
  ST7
};

/**
 * @brief MMX instruction set registers
 */
enum MM: unsigned {
  MM0,
  MM1,
  MM2,
  MM3,
  MM4,
  MM5,
  MM6,
  MM7
};

namespace detail {
#ifdef KTHOOK64
inline constexpr auto REG_COUNT = 16;
#else
inline constexpr auto REG_COUNT = 8;
#endif

inline constexpr auto SEGMENT_COUNT = 6;

template <std::uint8_t R>
struct impl_get_reg_type;

template <>
struct impl_get_reg_type<0b1111> {
  using type = std::uintptr_t;
};

template <>
struct impl_get_reg_type<0b0111> {
  using type = std::uint32_t;
};

template <>
struct impl_get_reg_type<0b0011> {
  using type = std::uint16_t;
};

template <>
struct impl_get_reg_type<0b0010> {
  using type = std::uint8_t;
};

template <>
struct impl_get_reg_type<0b0001> {
  using type = std::uint8_t;
};

template <REG R>
struct get_reg_type {
  using type = typename impl_get_reg_type<static_cast<std::uint8_t>(R) & 0b1111>::type;
};
} // namespace detail

#pragma pack(push, 1)
/**
 * @brief Interface for general purpose cpu registers
 */
struct cpu_ctx_int {
private:
  std::array<std::uintptr_t, detail::REG_COUNT> regs{};
public:
  /**
   * @brief Getter for register value
   * @tparam R register
   * @return value of the register
   */
  template <REG R>
  [[nodiscard]] typename detail::get_reg_type<R>::type reg() const noexcept {
    typename detail::get_reg_type<R>::type result{0};

    const auto r_type = static_cast<unsigned>(R) & 0b1111;
    const auto r_num = (static_cast<unsigned>(R) >> 4) & 0b1111;
    if constexpr (r_type & 0b1000) {
      result |= regs[r_num];
    } else if constexpr (r_type & 0b0100) {
      result |= regs[r_num] & 0xFFFFFFFF;
    } else if constexpr (r_type & 0b0011) {
      result |= regs[r_num] & 0xFFFF;
    } else if constexpr (r_type & 0b0010) {
      result |= regs[r_num] & 0xFF00;
    } else if constexpr (r_type & 0b0001) {
      result |= regs[r_num] & 0xFF;
    }

    return result;
  }

  /**
   * @brief Setter for register value
   * @tparam R register
   * @param v value to set
   */
  template <REG R>
  void set_reg(typename detail::get_reg_type<R>::type v) noexcept {
    const auto r_type = static_cast<unsigned>(R) & 0b1111;
    const auto r_num = (static_cast<unsigned>(R) >> 4) & 0b1111;
    if constexpr (r_type & 0b1000) {
      regs[r_num] = v;
    } else if constexpr (r_type & 0b0100) {
      regs[r_num] = v & 0xFFFFFFFF;
    } else if constexpr (r_type & 0b0011) {
      regs[r_num] = v & 0xFFFF;
    } else if constexpr (r_type & 0b0010) {
      regs[r_num] = v & 0xFF00;
    } else if constexpr (r_type & 0b0001) {
      regs[r_num] = v & 0xFF;
    }
  }
};

/**
 * @brief Interface for CPU EFLAGS
 */
struct cpu_ctx_flags {
public:
  std::uintptr_t CF : 1; // Carry flag

private:
  std::uintptr_t reserved1 : 1;

public:
  std::uintptr_t PF : 1; // Parity flag

private:
  std::uintptr_t reserved2 : 1;

public:
  std::uintptr_t AF : 1; // Auxiliary flag

private:
  std::uintptr_t reserved3 : 1;

public:
  std::uintptr_t ZF : 1;   // Zero flag
  std::uintptr_t SF : 1;   // Sign flag
  std::uintptr_t TF : 1;   // Trap flag
  std::uintptr_t IF : 1;   // Interrupt enable flag
  std::uintptr_t DF : 1;   // Direction flag
  std::uintptr_t OF : 1;   // Overflow flag
  std::uintptr_t IOPL : 2; // I/O privilege level
  std::uintptr_t NT : 1;   // 	Nested task flag

private:
  std::uintptr_t reserved4 : 1;

public:
  std::uintptr_t RF : 1;  // Resume flag
  std::uintptr_t VM : 1;  // Virtual 8086 mode flag
  std::uintptr_t AC : 1;  // Alignment check
  std::uintptr_t VIF : 1; // Virtual interrupt flag
  std::uintptr_t VIP : 1; // Virtual interrupt pending
  std::uintptr_t ID : 1;  // Able to use CPUID instruction

private:
  std::uintptr_t reserved5 : 10;
};

/**
 * @brief Interface for CPU Segment registers
 */
struct cpu_ctx_segment_regs {
public:
  using container = std::array<std::uint16_t, detail::SEGMENT_COUNT>;

  container segment_regs{};
public:
  /**
   * @brief Getter for segment registers
   * @tparam R register
   * @return value of segment register
   */
  template <SEGMENT R>
  [[nodiscard]] container::value_type reg() const noexcept {
    return segment_regs[static_cast<unsigned>(R)];
  }

  /**
   * @brief Setter for segment register
   * @tparam R register
   * @param v value to set
   */
  template <REG R>
  void set_reg(container::value_type v) noexcept {
    segment_regs[static_cast<unsigned>(R)] = v;
  }
};

struct fp_reg {
  double value;
  std::uint64_t reserved;
};

/**
 * @brief Interface for x87 fpu state
 */
struct cpu_ctx_x87 {
public:
  std::uint16_t FCW{};
  std::uint16_t FSW{};
  std::uint8_t FTW{};
  std::uint8_t _reserved1{};
  std::uint16_t FOP{};
#ifdef KTHOOK32
  std::uint32_t FIP{};
  std::uint16_t FCS{};
  std::uint16_t _reserved2{};

  std::uint32_t FDP{};
  std::uint16_t FDS{};
  std::uint16_t _reserved3{};
#else
  std::uint64_t FIP{};
  std::uint64_t FDP{};
#endif
  std::uint32_t MXCSR{};
  std::uint32_t MXCSR_MASK{};

private:
  std::array<fp_reg, 8> ST_regs{};

  std::array<M128, 16> XMM_regs{};

  std::array<M128, 3> _reserved4{};
  std::array<M128, 3> _available1{};

public:
  /**
   * @brief Getter for MMX registers
   * @tparam R register
   * @return value of MMX register
   */
  template <MM R>
  [[nodiscard]] double reg() const noexcept {
    return ST_regs[static_cast<unsigned>(R)].value;
  }

  /**
   * @brief Setter for MMX registers
   * @tparam R register
   * @param v value to set
   */
  template <MM R>
  void set_reg(double v) noexcept {
    ST_regs[static_cast<unsigned>(R)].value = v;
  }

  /**
   * @brief Getter for ST registers(x87 fpu instruction set)
   * @tparam R register
   * @return value of ST register
   */
  template <ST R>
  [[nodiscard]] double reg() const noexcept {
    return ST_regs[static_cast<unsigned>(R)].value;
  }

  /**
   * @brief Setter for ST registers(x87 fpu instruction set)
   * @tparam R register
   * @param v value to set
   */
  template <ST R>
  void set_reg(double v) noexcept {
    ST_regs[static_cast<unsigned>(R)].value = v;
  }

  /**
   * @brief Getter for XMM registers(SSE instruction set)
   * @tparam R register
   * @return value of XMM register
   */
  template <XMM R>
  [[nodiscard]] M128 reg() const noexcept {
    return XMM_regs[static_cast<unsigned>(R)];
  }

  /**
   * @brief Setter for XMM registers(SSE instruction set)
   * @tparam R register
   * @param v value to set
   */
  template <XMM R>
  void set_reg(M128 v) noexcept {
    XMM_regs[static_cast<unsigned>(R)] = v;
  }
};
#pragma pack(pop)
}

#pragma pop_macro("M128")
#endif // #ifndef KTHOOK_CPU_CTX_X86_64_HPP_
