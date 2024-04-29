#ifndef KTHOOK_PLATFORM_THREAD_HPP_
#define KTHOOK_PLATFORM_THREAD_HPP_

#if defined(KTHOOK_WIN)
#include "win/thread.hpp"
#elif defined(KTHOOK_LINUX)
#include "linux/thread.hpp"
#elif defined(KTHOOK_APPLE)
#include "macos/thread.hpp"
#endif

#endif  // KTHOOK_PLATFORM_MEMORY_HPP_
