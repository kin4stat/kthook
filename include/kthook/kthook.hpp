#ifndef KTHOOK_HPP_
#define KTHOOK_HPP_

#if defined(_WIN64) || defined(__MINGW64__) || (defined(__CYGWIN__) && defined(__x86_64__))
# define KTHOOK_64_WIN
#elif defined(__x86_64__)
# define KTHOOK_64_GCC
#endif

#if !defined(KTHOOK_64) && !defined(KTHOOK_32)
# if defined(KTHOOK_64_GCC) || defined(KTHOOK_64_WIN)
#   define KTHOOK_64
# else
#   define KTHOOK_32
# endif
#endif

#if defined(_WIN32)

# define KTHOOK_WIN
# ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# include <tlhelp32.h>

#elif defined(__linux__)

# define KTHOOK_LINUX
# include <filesystem>
# include <charconv>
# include <fstream>
# include <sys/mman.h>
# include <unistd.h>
# include <signal.h>

#elif defined(__apple__)

# define KTHOOK_APPLE
# include <mach/mach.h>
#endif

#if defined(KTHOOK_32)
#include "xbyak/xbyak.h"
#include "hde/hde32.h"
#elif defined(KTHOOK_64)
#include "xbyak/xbyak.h"
#include "hde/hde64.h"
#endif

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <tuple>
#include <vector>
#include <type_traits>
#include <numeric>
#include <stack>

#include "disasm/disasm.hpp"
#include "disasm/structs.hpp"

#include "arch/cconv.hpp"


#include "traits/base.hpp"
#include "traits/range.hpp"
#include "traits/signature.hpp"
#include "traits/type_holder.hpp"
#include "arch/fwd_decl.hpp"
#include "traits/discarded_values.hpp"

#include "base/ctx.hpp"
#include "base/error_codes.hpp"
#include "base/utils.hpp"

#include "platform/thread.hpp"
#include "platform/memory.hpp"

#include "xbyak_wrap/jmp_allocator.hpp"

#include "arch/ctx.hpp"
#include "arch/function_traits.hpp"
#include "arch/hook_info.hpp"
#include "arch/make_trampoline.hpp"
#include "arch/relay.hpp"
#include "arch/hook_traits.hpp"

#include "arch/hook_interface.hpp"
#include "interface.hpp"

//#include "arch/kthook_impl.hpp"

#include "concepts/concepts.hpp"

#include "impl/inline_x86_32_impl_base.hpp"
#include "impl/inline_x86_32_impl_safe.hpp"
#include "impl/inline_x86_32_impl_unsafe.hpp"
#include "impl/hook_impl.hpp"

#endif // KTHOOK_HPP_