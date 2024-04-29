#ifndef KTHOOK_DETAIL_X86_64_HPP_
#define KTHOOK_DETAIL_X86_64_HPP_

#ifdef KTHOOK_32
#define hde_disasm(code, hs) hde32_disasm(code, hs)
#else
#define hde_disasm(code, hs) hde64_disasm(code, hs)
#endif

namespace kthook::detail {
#ifdef KTHOOK_32
using hde = hde32s;
#else
using hde = hde64s;
#endif

inline thread_local void* hook_ctx{};

inline void CCDECL save_ctx(void* ptr) {
  hook_ctx = ptr;
}

template <typename T>
inline T* CCDECL get_ctx() {
  return static_cast<T*>(hook_ctx);
}

template <bool Enable, typename T>
struct dependent_stack_holder {
};

template <typename T>
struct dependent_stack_holder<true, T> {
  std::stack<T> ctx_storage_stack;
};

#pragma pack(push, 1)
struct hook_patch {
  std::uint8_t opcode;
  std::uint32_t operand;
};
#pragma pack(pop)

struct cpu_opcode {
  cpu_opcode(std::uint8_t op1, std::uint8_t op2, std::uint8_t modrm, std::uint8_t size)
    : op1(op1),
      op2(op2),
      modrm(modrm),
      size(size) {
  }

  std::uint8_t op1;
  std::uint8_t op2;
  std::uint8_t modrm;

  std::uint8_t size;

  [[nodiscard]] bool is_call() const {
    return op1 == 0xE8;
  }

  [[nodiscard]] bool is_relative_jmp() const {
    return (op1 & 0xFD) == 0xE9;
  }

  [[nodiscard]] bool is_cond_relative_jmp() const {
    return ((op1 & 0xF0) == 0x70) || // one byte jump
           ((op1 & 0xFC) == 0xE0) || // LOOPNZ/LOOPZ/LOOP/JECXZ
           ((op2 & 0xF0) == 0x80);
  }

  [[nodiscard]] bool is_ret() const {
    return (op1 & 0xFE) == 0xC2;
  }

  [[nodiscard]] bool is_rip_addressing() const {
    return (modrm & 0xC7) == 0x05;
  }
};

// https://github.com/TsudaKageyu/minhook/blob/master/src/trampoline.h
#pragma pack(push, 1)
struct JCC_ABS {
  std::uint8_t opcode; // 7* 0E:         J** +16
  std::uint8_t dummy0;
  std::uint8_t dummy1; // FF25 00000000: JMP [+6]
  std::uint8_t dummy2;
  std::uint32_t dummy3;
  std::uint64_t address; // Absolute destination address
};

struct CALL_ABS {
  std::uint8_t opcode0; // FF15 00000002: CALL [+6]
  std::uint8_t opcode1;
  std::uint32_t dummy0;
  std::uint8_t dummy1; // EB 08:         JMP +10
  std::uint8_t dummy2;
  std::uint64_t address; // Absolute destination address
};

struct JMP_ABS {
  std::uint8_t opcode0; // FF25 00000000: JMP [+6]
  std::uint8_t opcode1;
  std::uint32_t dummy;
  std::uint64_t address; // Absolute destination address
};

typedef struct {
  std::uint8_t opcode;   // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
  std::uint32_t operand; // Relative destination address
} JMP_REL, CALL_REL;

struct JCC_REL {
  std::uint8_t opcode0; // 0F8* xxxxxxxx: J** +6+xxxxxxxx
  std::uint8_t opcode1;
  std::uint32_t operand; // Relative destination address
};
#pragma pack(pop)

inline std::vector<cpu_opcode> collect_function_info(std::uintptr_t hook_address, std::size_t required_size) {
#ifdef KTHOOK32
  using call_t = CALL_ABS;
  using jcc_t = JCC_ABS;
  using jmp_t = JMP_ABS;
#else
  using call_t = CALL_REL;
  using jcc_t = JCC_REL;
  using jmp_t = JMP_REL;
#endif

  std::vector<cpu_opcode> result;

  std::uintptr_t current_address = hook_address;
  std::uintptr_t max_jmp_ref = 0;
  bool finished = false;

  while (!finished) {
    hde hs;
    hde_disasm(reinterpret_cast<void*>(current_address), &hs);
    if (hs.flags & F_ERROR) return {};
    result.emplace_back(hs.opcode, hs.opcode2, hs.modrm, hs.len);

    if (current_address - hook_address >= required_size) {
      break;
    }
    // Relative Call
    else if (hs.opcode == 0xE8) {
    }
    // Relative jmp
    else if ((hs.opcode & 0xFD) == 0xE9) {
      std::uintptr_t jmp_destination = current_address + hs.len;

      if (hs.opcode == 0xEB) // is short jump
        jmp_destination += static_cast<std::int8_t>(hs.imm.imm8);
      else
        jmp_destination += static_cast<std::int32_t>(hs.imm.imm32);

      if (hook_address <= jmp_destination && jmp_destination < (hook_address + sizeof(JMP_REL))) {
        if (max_jmp_ref < jmp_destination) max_jmp_ref = jmp_destination;
      } else {
        // Exit the function if it is not in the branch.
        finished = (hook_address >= max_jmp_ref);
      }
    }
    // Conditional relative jmp
    else if (((hs.opcode & 0xF0) == 0x70) || // one byte jump
             ((hs.opcode & 0xFC) == 0xE0) || // LOOPNZ/LOOPZ/LOOP/JECXZ
             ((hs.opcode2 & 0xF0) == 0x80)) {
      // two byte jump

      std::uintptr_t jmp_destination = current_address + hs.len;

      if ((hs.opcode & 0xF0) == 0x70 || // Jcc
          (hs.opcode & 0xFC) == 0xE0)   // LOOPNZ/LOOPZ/LOOP/JECXZ
        jmp_destination += static_cast<std::int8_t>(hs.imm.imm8);
      else
        jmp_destination += static_cast<std::int32_t>(hs.imm.imm32);

      // Simply copy an internal jump.
      if (hook_address <= jmp_destination && jmp_destination < (hook_address + sizeof(JMP_REL))) {
        if (max_jmp_ref < jmp_destination) max_jmp_ref = jmp_destination;
      } else if ((hs.opcode & 0xFC) == 0xE0) {
        // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
        return {};
      }
    }
    // RET
    else if ((hs.opcode & 0xFE) == 0xC2) {
      finished = (current_address >= max_jmp_ref);
    }

    current_address += hs.len;
  }
  return result;
}

struct hook_info {
  union {
    std::uintptr_t hook_address;
    void* hook_address_ptr;
  };

  std::unique_ptr<unsigned char[]> original_code;

  hook_info(std::uintptr_t a, std::unique_ptr<unsigned char[]>&& c)
    : hook_address(a),
      original_code(std::move(c)) {
  }

  hook_info(std::uintptr_t a)
    : hook_address(a),
      original_code(nullptr) {
  }
};

template <typename T>
struct discarded_holder {
  T& value;
};

template <>
struct discarded_holder<void> {
};
}

// namespace kthook

#endif // #ifndef KTHOOK_DETAIL_X86_64_HPP_
