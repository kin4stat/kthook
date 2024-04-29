#ifndef KTHOOK_DISASM_X86_STRUCTS_HPP_
#define KTHOOK_DISASM_X86_STRUCTS_HPP_

namespace kthook::disasm {
#pragma pack(push, 1)
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