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
#include <tlhelp32.h>
#else
#include <filesystem>
#include <charconv>
#include <fstream>
#include <sys/mman.h>
#ifdef __linux__
#include <unistd.h>
#include <signal.h>
#endif
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

#if defined(KTHOOK_64)
// clang-format off
#include "hde/hde64.h"
#include "x86_64/kthook_x86_64_detail.hpp"
#include "x64/kthook_detail.hpp"
#include "x64/kthook_impl.hpp"
// clang-format on

#elif defined(KTHOOK_32)
// clang-format off
#include "hde/hde32.h"
#include "x86_64/kthook_x86_64_detail.hpp"
#include "x86/kthook_detail.hpp"
#include "x86/kthook_impl.hpp"
// clang-format on
#endif

#endif
