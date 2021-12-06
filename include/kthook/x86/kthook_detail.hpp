#ifndef KTHOOK_DETAIL_HPP_
#define KTHOOK_DETAIL_HPP_

#ifdef __GNUC__
#define CCDECL __attribute__((cdecl))
#define CFASTCALL __attribute__((fastcall))
#define CSTDCALL __attribute__((stdcall))
#define CTHISCALL __attribute__((thiscall))
#else
#define CCDECL __cdecl
#define CFASTCALL __fastcall
#define CSTDCALL __stdcall
#define CTHISCALL __thiscall
#endif // __GNUC__

#define hde_disasm(code, hs) hde32_disasm(code, hs)

namespace kthook {
	namespace detail {
		using hde = hde32s;
		
		namespace traits {

			enum class cconv {
				ccdecl,
				cfastcall,
				cthiscall,
				cstdcall,
			};

			template <typename T, typename Enable = void>
			struct convert_ref {
				using type = T;
			};

			template <typename T>
			struct convert_ref<T, std::enable_if_t<std::is_reference_v<T>>> {
				using type = std::add_pointer_t<std::remove_cv_t<std::remove_reference_t<T>>>;
				/*using non_ref = std::remove_reference_t<T>;
				using ptr_type = std::add_pointer_t<std::remove_cv_t<non_ref>>;
				using const_ptr_type = std::conditional_t<std::is_const_v<non_ref>, std::add_const_t<ptr_type>, ptr_type>;
				using type = std::conditional_t<std::is_volatile_v<non_ref>, std::add_volatile_t<const_ptr_type>, const_ptr_type>;*/
			};

			template <typename T>
			using convert_ref_t = typename convert_ref<T>::type;

			template<typename Tuple>
			struct convert_refs;

			template<typename... Ts>
			struct convert_refs<std::tuple<Ts...>> {
				using type = std::tuple<convert_ref_t<Ts>...>;
			};

			template <cconv Conv, typename Ret, typename Tuple>
			struct function_connect_ptr;
			template <typename Ret, typename... Args>
			struct function_connect_ptr<cconv::ccdecl, Ret, std::tuple<Args...>> {
				using type = Ret(CCDECL*)(Args...);
			};
#ifdef _WIN32
			template <typename Ret, typename... Args>
			struct function_connect_ptr<cconv::cstdcall, Ret, std::tuple<Args...>> {
				using type = Ret(CSTDCALL*)(Args...);
			};
			template <typename Ret, typename... Args>
			struct function_connect_ptr<cconv::cthiscall, Ret, std::tuple<Args...>> {
				using type = Ret(CTHISCALL*)(Args...);
			};
			template <typename Ret, typename... Args>
			struct function_connect_ptr<cconv::cfastcall, Ret, std::tuple<Args...>> {
				using type = Ret(CFASTCALL*)(Args...);
			};
#endif

			template <class R, class Tuple>
			struct function_connect;
			template <class R, class... Types>
			struct function_connect<R, std::tuple<Types...>> {
				using type = R(Types...);
			};


			template <typename Pointer>
			struct function_traits;

			template <typename Ret, typename Class, typename... Args>
			struct function_traits<Ret(Class::*)(Args...)> {
				static constexpr auto args_count = sizeof...(Args);
				static constexpr auto function_convention = cconv::cthiscall;
				using args = std::tuple<Class*, Args...>;
				using return_type = Ret;
			};

			template <typename Ret, typename... Args>
			struct function_traits<Ret(CCDECL*)(Args...)> {
				static constexpr auto args_count = sizeof...(Args);
				static constexpr auto convention = cconv::ccdecl;
				using args = std::tuple<Args...>;
				using return_type = Ret;
			};
			template <typename Ret, typename... Args>
			struct function_traits<Ret(Args...)> {
				static constexpr auto args_count = sizeof...(Args);
				static constexpr auto convention = cconv::cstdcall;
				using args = std::tuple<Args...>;
				using return_type = Ret;
			};
#ifdef _WIN32
			template <typename Ret, typename... Args>
			struct function_traits<Ret(CTHISCALL*)(Args...)> {
				static constexpr auto args_count = sizeof...(Args);
				static constexpr auto convention = cconv::cthiscall;
				using args = std::tuple<Args...>;
				using return_type = Ret;
			};

			template <typename Ret, typename... Args>
			struct function_traits<Ret(CSTDCALL*)(Args...)> {
				static constexpr auto args_count = sizeof...(Args);
				static constexpr auto convention = cconv::cstdcall;
				using args = std::tuple<Args...>;
				using return_type = Ret;
			};

			template <typename Ret, typename... Args>
			struct function_traits<Ret(CFASTCALL*)(Args...)> {
				static constexpr auto args_count = sizeof...(Args);
				static constexpr auto convention = cconv::cfastcall;
				using args = std::tuple<Args...>;
				using return_type = Ret;
			};
#endif
			template<typename T, typename Tuple>
			struct tuple_cat;

			template<typename T, typename... Ts>
			struct tuple_cat<T, std::tuple<Ts...>> {
				using type = std::tuple<T, Ts...>;
			};

			template <cconv Conv, typename Ret, typename... Args>
			using function_connect_ptr_t = typename function_connect_ptr<Conv, Ret, Args...>::type;

			template <class R, class... Types>
			using function_connect_t = typename function_connect<R, Types...>::type;

			template<typename T, typename... Ts>
			using tuple_cat_t = typename tuple_cat<T, Ts...>::type;

			template <class... Types>
			using convert_refs_t = typename convert_refs<Types...>::type;
		}

		template <typename HookPtrType, typename SourceType, typename Ret, typename... Args>
		inline Ret common_signal_relay(HookPtrType* this_hook, Args&... args) {
			if constexpr (std::is_void_v<Ret>) {
				auto before_iterate = this_hook->before.emit_iterate(*this_hook, args...);
				bool dont_skip_original = true;
				for (auto return_value : before_iterate) {
					dont_skip_original &= return_value;
				}
				if (dont_skip_original) {
					this_hook->get_trampoline()(args...);
					this_hook->after.emit(*this_hook, args...);
				}
				return;
			}
			else {
				auto before_iterate = this_hook->before.emit_iterate(*this_hook, args...);
				bool dont_skip_original = true;
				Ret value{};
				for (std::optional<Ret> return_value : before_iterate) {
					bool has_value = return_value.has_value();
					dont_skip_original &= !has_value;
					if (has_value) {
						value = return_value.value();
					}
				}
				if (dont_skip_original) {
					value = std::move(this_hook->get_trampoline()(args...));
					this_hook->after.emit(*this_hook, value, args...);
				}
				return value;
			}
		}

		template <typename HookPtrType, traits::cconv Convention, typename Ret, typename... Args>
		struct signal_relay_generator;

		template <typename HookPtrType, typename Ret, typename... Args>
		struct signal_relay_generator<HookPtrType, traits::cconv::ccdecl, Ret, std::tuple<Args...>> {
			static Ret CCDECL relay(HookPtrType* this_hook, std::uintptr_t retaddr, Args... args) {
				using source_t = Ret(CCDECL*)(Args...);
				return common_signal_relay<HookPtrType, source_t, Ret, Args...>(this_hook, args...);
			}
		};

#ifdef _WIN32
		template <typename HookPtrType, typename Ret, typename... Args>
		struct signal_relay_generator<HookPtrType, traits::cconv::cstdcall, Ret, std::tuple<Args...>> {
			static Ret CSTDCALL relay(HookPtrType* this_hook, Args... args) {
				using source_t = Ret(CSTDCALL*)(Args...);
				return common_signal_relay<HookPtrType, source_t, Ret, Args...>(this_hook, args...);
			}
		};

		template <typename HookPtrType, typename Ret, typename... Args>
		struct signal_relay_generator<HookPtrType, traits::cconv::cthiscall, Ret, std::tuple<Args...>> {
			static Ret CSTDCALL relay(HookPtrType* this_hook, Args... args) {
				using source_t = Ret(CTHISCALL*)(Args...);
				return common_signal_relay<HookPtrType, source_t, Ret, Args...>(this_hook, args...);
			}
		};

		template <typename HookPtrType, typename Ret, typename... Args>
		struct signal_relay_generator<HookPtrType, traits::cconv::cfastcall, Ret, std::tuple<Args...>> {
			// fastcall uses registers for first two integral/pointer types (left->right)
			// so we can use this trick to get outr hook object from stack
			struct fastcall_trick {
				HookPtrType* ptr;
			};

			static Ret CFASTCALL relay(fastcall_trick esp4, Args... args) {
				using source_t = Ret(CFASTCALL*)(Args...);
				return common_signal_relay<HookPtrType, source_t, Ret, Args...>(esp4.ptr, args...);
			}
		};
#endif
		template <typename Callback, typename HookPtrType, typename Ret, typename... Args>
		inline Ret common_relay(Callback& cb, HookPtrType* this_hook, Args&... args) {
			return cb(*this_hook, args...);
		}

		template <typename HookPtrType, traits::cconv Convention, typename Ret, typename Tuple>
		struct relay_generator;

		template <typename HookPtrType, typename Ret, typename... Args>
		struct relay_generator<HookPtrType, traits::cconv::ccdecl, Ret, std::tuple<Args...>> {
			static Ret CCDECL relay(HookPtrType* this_hook, std::uintptr_t retaddr, Args... args) {
				return common_relay<decltype(this_hook->callback), HookPtrType, Ret, Args...>(this_hook->callback, this_hook, args...);
			}
		};

#ifdef _WIN32
		template <typename HookPtrType, typename Ret, typename... Args>
		struct relay_generator<HookPtrType, traits::cconv::cstdcall, Ret, std::tuple<Args...>> {
			static Ret CSTDCALL relay(HookPtrType* this_hook, Args... args) {
				return common_relay<decltype(this_hook->callback), HookPtrType, Ret, Args...>(this_hook->callback, this_hook, args...);
			}
		};

		template <typename HookPtrType, typename Ret, typename... Args>
		struct relay_generator<HookPtrType, traits::cconv::cthiscall, Ret, std::tuple<Args...>> {
			static Ret CSTDCALL relay(HookPtrType* this_hook, Args... args) {
				return common_relay<decltype(this_hook->callback), HookPtrType, Ret, Args...>(this_hook->callback, this_hook, args...);
			}
		};

		template <typename HookPtrType, typename Ret, typename... Args>
		struct relay_generator<HookPtrType, traits::cconv::cfastcall, Ret, std::tuple<Args...>> {
			// fastcall uses registers for first two integral/pointer types (left->right)
			// so we can use this trick to get outr hook object from stack
			struct fastcall_trick {
				HookPtrType* ptr;
			};

			static Ret CFASTCALL relay(fastcall_trick esp4, Args... args) {
				auto this_hook = esp4.ptr;
				return common_relay<decltype(this_hook->callback), HookPtrType, Ret, Args...>(this_hook->callback, this_hook, args...);
			}
		};
#endif

		// https://github.com/TsudaKageyu/minhook/blob/master/src/trampoline.h
#pragma pack(push, 1)
		struct JCC_ABS
		{
			std::uint8_t  opcode;      // 7* 0E:         J** +16
			std::uint8_t  dummy0;
			std::uint8_t  dummy1;      // FF25 00000000: JMP [+6]
			std::uint8_t  dummy2;
			std::uint32_t dummy3;
			std::uint64_t address;     // Absolute destination address
		};

		struct CALL_ABS
		{
			std::uint8_t  opcode0;     // FF15 00000002: CALL [+6]
			std::uint8_t  opcode1;
			std::uint32_t dummy0;
			std::uint8_t  dummy1;      // EB 08:         JMP +10
			std::uint8_t  dummy2;
			std::uint64_t address;     // Absolute destination address
		};

		struct JMP_ABS
		{
			std::uint8_t  opcode0;     // FF25 00000000: JMP [+6]
			std::uint8_t  opcode1;
			std::uint32_t dummy;
			std::uint64_t address;     // Absolute destination address
		};
		typedef struct
		{
			std::uint8_t  opcode;      // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
			std::uint32_t operand;     // Relative destination address
		} JMP_REL, CALL_REL;

		struct JCC_REL
		{
			std::uint8_t  opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
			std::uint8_t  opcode1;
			std::uint32_t operand;     // Relative destination address
		};
#pragma pack(pop)

		inline std::size_t detect_hook_size(std::uintptr_t addr) {
			size_t size = 0;
			while (size < 5) {
				hde op;
				hde_disasm(reinterpret_cast<void*>(addr), &op);
				size += op.len;
				addr += op.len;
			}
			return size;
		}

		inline std::uintptr_t get_relative_address(std::uintptr_t dest, std::uintptr_t src, std::size_t oplen = 5) { return dest - src - oplen; }
		inline std::uintptr_t restore_absolute_address(std::uintptr_t RIP, std::uintptr_t rel, std::size_t oplen = 5) { return RIP + rel + oplen; }

		inline bool flush_intruction_cache(const void* ptr, std::size_t size) {
#ifdef _WIN32
			return FlushInstructionCache(GetCurrentProcess(), ptr, size) != 0;
#else
			return cacheflush(ptr, size, ICACHE) == 0;
#endif
		}

		inline bool check_is_executable(const void* addr) {
#ifdef _WIN32
			MEMORY_BASIC_INFORMATION buffer;
			VirtualQuery(addr, &buffer, sizeof(buffer));
			return buffer.Protect == PAGE_EXECUTE || buffer.Protect == PAGE_EXECUTE_READ || PAGE_EXECUTE_READWRITE;
#else
			return true;
#endif
		}

		enum class MemoryProt {
			PROTECT_RW,
			PROTECT_RWE,
			PROTECT_RE,
		};
		inline bool set_memory_prot(const void* addr, std::size_t size, MemoryProt protectMode) {
#if defined(_WIN32)
			const DWORD c_rw = PAGE_READWRITE;
			const DWORD c_rwe = PAGE_EXECUTE_READWRITE;
			const DWORD c_re = PAGE_EXECUTE_READ;
			DWORD mode;
#else
			const int c_rw = PROT_READ | PROT_WRITE;
			const int c_rwe = PROT_READ | PROT_WRITE | PROT_EXEC;
			const int c_re = PROT_READ | PROT_EXEC;
			int mode;
#endif
			switch (protectMode) {
			case MemoryProt::PROTECT_RW: mode = c_rw; break;
			case MemoryProt::PROTECT_RWE: mode = c_rwe; break;
			case MemoryProt::PROTECT_RE: mode = c_re; break;
			default:
				return false;
			}
#if defined(_WIN32)
			DWORD oldProtect;
			return VirtualProtect(const_cast<void*>(addr), size, mode, &oldProtect) != 0;
#elif defined(__GNUC__)
			size_t pageSize = sysconf(_SC_PAGESIZE);
			size_t iaddr = reinterpret_cast<size_t>(addr);
			size_t roundAddr = iaddr & ~(pageSize - static_cast<size_t>(1));
			return mprotect(reinterpret_cast<void*>(roundAddr), size + (iaddr - roundAddr), mode) == 0;
#else
			return true;
#endif
		}
	}
}

#endif