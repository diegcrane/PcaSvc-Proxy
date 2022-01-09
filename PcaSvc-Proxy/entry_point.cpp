
#include "proxy/proxy.hpp"

#define SOURCE "PcaSvc"
#define TARGET "Genshin Impact"

auto main() -> __int32
{
	auto source_pid = sdk::memory::get_process_id(nullptr, nullptr, nullptr, SOURCE);

	if (source_pid == 0)
	{
		std::cout << "source process not running" << std::cin.get();
		return 0;
	}

	auto target_pid = sdk::memory::get_process_id(nullptr, nullptr, TARGET, nullptr);

	if (target_pid == 0)
	{
		std::cout << "target process not running" << std::cin.get();
		return 0;
	}

	if (proxy::init(source_pid, target_pid) /*testing the proxy with Genshin Impact, protected with Mhyprot*/)
	{
		void* handle = nullptr;

		sdk::memory::nt_open_process(&handle, PROCESS_QUERY_INFORMATION, target_pid);

		_MEMORY_BASIC_INFORMATION mbi;

		for (unsigned __int64 x = 0; sdk::memory::nt_query_virtual_memory(handle, (void*)x, 0, &mbi, sizeof(mbi), nullptr) == 0; x += mbi.RegionSize)
		{
			if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS && !(mbi.Protect & PAGE_GUARD))
			{
				std::string buffer(mbi.RegionSize, 0);

				proxy::rvm((void*)x, &buffer[0], mbi.RegionSize);

				std::cout << buffer.substr(0, 5) << std::endl;
			}
		}

		CloseHandle(handle);
	}

	proxy::exit();

	return std::cin.get() != 0xffffffff;
}