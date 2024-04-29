#ifndef KTHOOK_PLATFORM_MEMORY_HPP_
#define KTHOOK_PLATFORM_MEMORY_HPP_

#include "base/memory.hpp"

#if defined(KTHOOK_WIN)
#include "win/memory.hpp"
#elif defined(KTHOOK_LINUX)
#include "linux/memory.hpp"
#elif defined(KTHOOK_APPLE)
#include "macos/memory.hpp"
#endif

#endif  // KTHOOK_PLATFORM_MEMORY_HPP_
