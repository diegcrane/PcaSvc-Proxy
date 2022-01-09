
#include "../hdr.hpp"

namespace sdk::memory
{
	extern __forceinline auto get_p_env() -> _PEB*;

	extern __forceinline auto get_ntdll() -> unsigned __int64;

	extern __forceinline auto get_library_base(const char* mod_name) -> unsigned __int64;

	extern __forceinline auto get_proc_address(unsigned __int64 mod, const char* exp_name) -> unsigned __int64;
}

namespace sdk::memory
{
	extern __forceinline auto nt_open_process(
		void** handle,
		unsigned long access,
		unsigned long pid
	) -> long;

	extern __forceinline auto nt_query_virtual_memory(
		void* handle,
		void* address,
		unsigned char mode,
		void* mbi,
		unsigned __int64 size,
		unsigned __int64* bytes_read
	) -> long;

	extern __forceinline auto nt_read_virtual_memory(
		void* handle,
		void* address,
		void* buffer,
		unsigned __int64 size,
		unsigned __int64* bytes_read
	) -> long;

	extern __forceinline auto nt_write_virtual_memory(
		void* handle,
		void* address,
		void* buffer,
		unsigned __int64 size,
		unsigned __int64* bytes_written
	) -> long;

	extern __forceinline auto nt_create_thread_ex(
		void** thread,
		unsigned long access,
		void* attribs,
		void* process,
		void* routine,
		void* args,
		unsigned long create_flags,
		unsigned __int64 zero_bits,
		unsigned __int64 stack_size,
		unsigned __int64 stack,
		void* attribs_list
	) -> long;

	extern __forceinline auto nt_allocate_virtual_memory(
		void* handle,
		void** address,
		unsigned __int64* zero_bits,
		unsigned __int64* size,
		unsigned __int64 type,
		unsigned __int64 protection
	) -> long;

	extern __forceinline auto nt_free_virtual_memory(
		void* handle,
		void** address,
		unsigned __int64* size,
		unsigned __int64 type
	) -> long;

	extern __forceinline auto nt_protect_virtual_memory(
		void* handle,
		void* address,
		unsigned __int64 size,
		unsigned long new_protection,
		unsigned long* old_protection
	) -> long;
}

namespace sdk::memory
{
	extern __forceinline auto grant_all_privileges() -> bool
	{
		void* token = nullptr;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_READ | TOKEN_ADJUST_PRIVILEGES, &token) || token == nullptr)
		{
			return false;
		}

		auto privs = new _TOKEN_PRIVILEGES[100];

		static auto del_and_ret = [&](bool ret_val) -> bool
		{
			delete[] privs;

			return ret_val;
		};

		unsigned long size = 0;

		if (GetTokenInformation(token,
			_TOKEN_INFORMATION_CLASS::TokenPrivileges, privs, 100 * sizeof(_TOKEN_PRIVILEGES), &size))
		{
			for (unsigned long x = 0; x < privs->PrivilegeCount; ++x)
			{
				privs->Privileges[x].Attributes = SE_PRIVILEGE_ENABLED;
			}

			if (!AdjustTokenPrivileges(token, false, privs, size * sizeof(_TOKEN_PRIVILEGES), nullptr, nullptr))
			{
				return del_and_ret(false);
			}
		}
		else
		{
			return del_and_ret(false);
		}

		return del_and_ret(true);
	}

	extern __forceinline auto get_process_id(const char* exe_name, const char* cls_name, const char* win_name, const char* ser_name) -> unsigned long
	{
		unsigned long process_id = 0;

		if (exe_name != nullptr)
		{
			auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			if (snap != INVALID_HANDLE_VALUE)
			{
				tagPROCESSENTRY32 entry
				{
					sizeof(tagPROCESSENTRY32)
				};

				for (auto init = Process32First(snap, &entry); init && Process32Next(snap, &entry);)
				{
					if (std::string(entry.szExeFile).find(exe_name) != std::string::npos)
					{
						process_id = entry.th32ProcessID;
					}
				}
			
				CloseHandle(snap);
			}
		}

		if (cls_name != nullptr)
		{
			GetWindowThreadProcessId(FindWindowA(cls_name, nullptr), &process_id);
		}

		if (win_name != nullptr)
		{
			GetWindowThreadProcessId(FindWindowA(nullptr, win_name), &process_id);
		}

		if (ser_name != nullptr)
		{
			auto manager = OpenSCManagerA(nullptr, nullptr, 0);

			if (manager == nullptr)
				return 0;

			auto service = OpenServiceA(manager, ser_name, SERVICE_QUERY_STATUS);

			if (service == nullptr)
			{
				CloseServiceHandle(manager);
				return 0;
			}

			_SERVICE_STATUS_PROCESS service_status;

			unsigned long bytes_read = 0;

			auto res = QueryServiceStatusEx(
				service, SC_STATUS_PROCESS_INFO, (unsigned char*)&service_status, sizeof(service_status), &bytes_read);

			CloseServiceHandle(service);
			CloseServiceHandle(manager);

			if (service_status.dwProcessId != 0)
			{
				process_id = service_status.dwProcessId;
			}
		}

		return process_id;
	}

	extern __forceinline auto find_remote_handle(void* handle, unsigned long pid) -> void*
	{
		void* remote_handle = nullptr;

		for (unsigned __int64 address = 0x34; remote_handle == nullptr && address < 0x1fff; address += 4)
		{
			void* temp = nullptr;

			if (DuplicateHandle(handle, (void*)address, (void*)-1, &temp, 0, 0, DUPLICATE_SAME_ACCESS))
			{
				if (GetProcessId(temp) == pid)
				{
					remote_handle = (void*)address;
				}
			}

			CloseHandle(temp);
		}

		return remote_handle;
	}
}