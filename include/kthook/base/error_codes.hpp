#ifndef KTHOOK_BASE_ERROR_CODES_HPP_
#define KTHOOK_BASE_ERROR_CODES_HPP_

namespace kthook {
enum class error_code_t {
  kOk = 0,
  kNotInstalled,
  kAlreadyInstalled,
  kHookAddressNotValid,
  kHookLocationNotExecutable,
  kTrampolineCreationError,
  kHookInstallationFailure,
  kHookRemoveFailure,
  kMemoryProtectionFailure,
  kThreadFreezeError,
};
}
#endif // #ifndef KTHOOK_BASE_ERROR_CODES_HPP_