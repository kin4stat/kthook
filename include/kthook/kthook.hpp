#ifndef KTHOOK_HPP_
#define KTHOOK_HPP_

#if defined(_WIN64) || defined(__MINGW64__) || (defined(__CYGWIN__) && defined(__x86_64__))
#define KTHOOK_64_WIN
#elif defined(__x86_64__)
#define KTHOOK_64_GCC
#endif
#if !defined(KTHOOK_64) && !defined(KTHOOK_32)
#if defined(KTHOOK_64_GCC) || defined(KTHOOK_64_WIN)
#define KTHOOK_64
#else
#define KTHOOK_32
#endif
#endif

#if defined(KTHOOK_64) || defined(KTHOOK_32)
#include "xbyak/xbyak.h"
#endif

#include "ktsignal/ktsignal.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#endif

#include <optional>
#include <functional>
#include <type_traits>
#include <memory>
#include <tuple>
#include <array>
#include <cstdint>
#include <cstddef>
#include <cstring>

#if defined(KTHOOK_64)
#include "hde/hde64.h"
#include "x86_64/kthook_x86_64_detail.hpp"
#include "x64/kthook_detail.hpp"
#include "x64/kthook_impl.hpp"
#elif defined(KTHOOK_32)
#include "hde/hde32.h"
#include "x86_64/kthook_x86_64_detail.hpp"
#include "x86/kthook_detail.hpp"
#include "x86/kthook_impl.hpp"
#endif


#endif