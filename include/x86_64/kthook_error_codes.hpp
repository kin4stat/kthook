#ifndef KTHOOK_X86_64_ERROR_CODES_HPP_
#define KTHOOK_X86_64_ERROR_CODES_HPP_

enum class kthook_error_code_t {
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

#endif // #ifndef KTHOOK_X86_64_ERROR_CODES_HPP_