#ifndef KTHOOK_PLATFORM_WIN_THREAD_HPP_
#define KTHOOK_PLATFORM_WIN_THREAD_HPP_

namespace kthook::platform {
struct frozen_threads {
  std::vector<DWORD> thread_ids;
};

/**
 * @brief Suspends all threads except current thread
 * @param threads intermediate storage
 * @return was the operation successful
 */
inline bool freeze_threads(frozen_threads& threads) {
  auto enumerate_threads = [](frozen_threads& threads) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    auto self_tid = GetCurrentThreadId();
    auto self_pid = GetCurrentProcessId();
    auto offset = FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD);

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te)) {
      do {
        if (te.dwSize >= offset && te.th32OwnerProcessID == self_pid && te.th32ThreadID != self_tid) {
          threads.thread_ids.push_back(te.th32ThreadID);
        }
        te.dwSize = sizeof(THREADENTRY32);
      } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    return true;
  };

  if (!enumerate_threads(threads)) {
    return false;
  }
  for (auto tid : threads.thread_ids) {
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT, FALSE, tid);
    if (hThread != NULL) {
      SuspendThread(hThread);
      CloseHandle(hThread);
    }
  }
  return true;
}

/**
 * @brief Resumes all threads previously suspended
 * @param threads parameter passed to freeze_threads
 * @return was the operation successful
 */
inline bool unfreeze_threads(frozen_threads& threads) {
  for (auto tid : threads.thread_ids) {
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT, FALSE, tid);
    if (hThread != NULL) {
      ResumeThread(hThread);
      CloseHandle(hThread);
    }
  }
  return true;
}
}

#endif // KTHOOK_PLATFORM_WIN_THREAD_HPP_