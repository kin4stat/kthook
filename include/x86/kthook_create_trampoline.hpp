#ifndef KTHOOK_CREATE_TRAMPOLINE_HPP_
#define KTHOOK_CREATE_TRAMPOLINE_HPP_

namespace kthook::detail {
inline bool create_trampoline(std::uintptr_t hook_address,
                              const std::unique_ptr<Xbyak::CodeGenerator>& trampoline_gen,
                              std::size_t used_bytes_count) {
    CALL_REL call = {
        0xE8,      // E8 xxxxxxxx: CALL +5+xxxxxxxx
        0x00000000 // Relative destination address
    };
    JMP_REL jmp = {
        0xE9,      // E9 xxxxxxxx: JMP +5+xxxxxxxx
        0x00000000 // Relative destination address
    };
    JCC_REL jcc = {
        0x0F, 0x80, // 0F8* xxxxxxxx: J** +6+xxxxxxxx
        0x00000000  // Relative destination address
    };

    std::size_t trampoline_size = 0;
    std::uintptr_t current_address = hook_address;
    std::uintptr_t max_jmp_ref = 0;
    bool finished = false;

    while (!finished) {
      hde hs;
      std::size_t op_copy_size = hde_disasm(reinterpret_cast<void*>(current_address), &hs);
      if (hs.flags & F_ERROR) return false;
      auto op_copy_src = reinterpret_cast<void*>(current_address);
      if (current_address - hook_address >= used_bytes_count) {
        // jump to next instruction after patched bytes
        trampoline_gen->jmp(reinterpret_cast<std::uint8_t*>(current_address));
        break;
      }
      // Relative Call
      else if (hs.opcode == 0xE8) {
        if (current_address == hook_address) {
          const std::uintptr_t call_destination =
              utils::restore_absolute_address(current_address, hs.imm.imm32, hs.len);
          jmp.operand = utils::get_relative_address(
              call_destination, reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(jmp));
          op_copy_src = &jmp;
          op_copy_size = sizeof(jmp);
        } else {
          const std::uintptr_t call_destination =
              utils::restore_absolute_address(current_address, hs.imm.imm32, hs.len);
          call.operand = utils::get_relative_address(
              call_destination, reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(jmp));
          op_copy_src = &call;
          op_copy_size = sizeof(call);
        }
      }
      // Relative jmp
      else if ((hs.opcode & 0xFD) == 0xE9) {
        std::uintptr_t jmp_destination = current_address + hs.len;

        if (hs.opcode == 0xEB) // is short jump
          jmp_destination += static_cast<std::int8_t>(hs.imm.imm8);
        else
          jmp_destination += static_cast<std::int32_t>(hs.imm.imm32);

        jmp.operand = utils::get_relative_address(
            jmp_destination, reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(jmp));
        op_copy_src = &jmp;
        op_copy_size = sizeof(jmp);

        // Exit the function if it is not in the branch.
        finished = (hook_address >= max_jmp_ref);
      }
      // Conditional relative jmp
      else if (((hs.opcode & 0xF0) == 0x70) || // one byte jump
               ((hs.opcode & 0xFC) == 0xE0) || // LOOPNZ/LOOPZ/LOOP/JECXZ
               ((hs.opcode2 & 0xF0) == 0x80)) {
        // two byte jump

        std::uintptr_t jmp_destination = current_address + hs.len;

        if ((hs.opcode & 0xF0) == 0x70     // Jcc
            || (hs.opcode & 0xFC) == 0xE0) // LOOPNZ/LOOPZ/LOOP/JECXZ
          jmp_destination += static_cast<std::int8_t>(hs.imm.imm8);
        else
          jmp_destination += static_cast<std::int32_t>(hs.imm.imm32);

        if ((hs.opcode & 0xFC) == 0xE0) {
          // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
          return false;
        } else {
          std::uint8_t cond = ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
          jcc.opcode1 = 0x80 | cond;
          jcc.operand = utils::get_relative_address(
              jmp_destination, reinterpret_cast<std::uintptr_t>(trampoline_gen->getCurr()), sizeof(jcc));
          op_copy_src = &jcc;
          op_copy_size = sizeof(jcc);
        }
      }

      trampoline_gen->db(reinterpret_cast<std::uint8_t*>(op_copy_src), op_copy_size);

      trampoline_size += op_copy_size;
      current_address += hs.len;
    }
    if (current_address - hook_address < used_bytes_count) return false;
    return true;
  }
} // namespace kthook::detail

#endif // #ifndef KTHOOK_CREATE_TRAMPOLINE_HPP_
