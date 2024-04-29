#ifndef KTHOOK_DISASM_X86_STRUCTS_HPP_
#define KTHOOK_DISASM_X86_STRUCTS_HPP_

namespace kthook::disasm {
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
struct hook_patch {
  std::uint8_t opcode;
  std::uint32_t operand;
};
#pragma pack(pop)
}

#endif // KTHOOK_DISASM_X86_STRUCTS_HPP_