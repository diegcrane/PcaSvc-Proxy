
#include "proxy.hpp"

auto proxy::remote_data::generate_default() -> proxy::remote_data
{
	static auto ntdll = sdk::memory::get_library_base("ntdll.dll");

	static auto del = (void*)sdk::memory::get_proc_address(ntdll,
		"NtDelayExecution");

	static auto rvm = (void*)sdk::memory::get_proc_address(ntdll,
		"NtReadVirtualMemory");

	static auto wvm = (void*)sdk::memory::get_proc_address(ntdll,
		"NtWriteVirtualMemory");

	proxy::remote_data rd = { (void*)del, (void*)rvm, (void*)wvm };

	rd._del.QuadPart = -1;

	rd.buffer_rvm = proxy::remote_region_rvm;
	rd.buffer_wvm = proxy::remote_region_wvm;

	return rd;
}

auto proxy::handler() -> unsigned __int64
{
	for (;;)
	{
		auto current_req = (proxy::remote_data*)((unsigned __int64)proxy::handler + IPC_OFFSET);

		if (current_req->host_req == 1)
		{
			((long(_stdcall*)(void*, void*, void*, unsigned __int64, unsigned __int64*))current_req->rvm)
				(current_req->target_handle, current_req->region, current_req->buffer_rvm, current_req->size, nullptr);

			current_req->host_req = 0;
		
			continue /*ignore sleep if a request has been done*/;
		}

		if (current_req->host_req == 2)
		{
			((long(_stdcall*)(void*, void*, void*, unsigned __int64, unsigned __int64*))current_req->wvm)
				(current_req->target_handle, current_req->region, current_req->buffer_wvm, current_req->size, nullptr);

			current_req->host_req = 0;

			continue /*ignore sleep if a request has been done*/;
		}

		if (current_req->host_req == 3)
		{
			break;
		}

		((void(_stdcall*)(bool, LARGE_INTEGER*))current_req->del)(0, &current_req->_del);
	}

	return 0xffffffffffffffff;
}

auto proxy::init(unsigned long source_pid, unsigned long target_pid) -> bool
{
	if (!sdk::memory::grant_all_privileges(/*grant SeDebugPrivilege in order to get a PROCESS_ALL_ACCESS handle to PcaSvc*/))
	{
		return false;
	}

	sdk::memory::nt_open_process(&proxy::handle_source, PROCESS_ALL_ACCESS, source_pid);

	if (proxy::handle_source == nullptr)
	{
		return false;
	}

	proxy::handle_0 = sdk::memory::find_remote_handle(
		proxy::handle_source,
		GetCurrentProcessId()
	);

	if (proxy::handle_0 == nullptr)
	{
		return false;
	}

	proxy::handle_1 = sdk::memory::find_remote_handle(
		proxy::handle_source,
		target_pid
	);

	if (proxy::handle_1 == nullptr)
	{
		return false;
	}

	auto x = sdk::memory::nt_allocate_virtual_memory(proxy::handle_source, &proxy::remote_region, nullptr, &proxy::size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	auto y = sdk::memory::nt_allocate_virtual_memory(proxy::handle_source,
		&proxy::remote_region_rvm, nullptr, &proxy::size_rvm, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	auto z = sdk::memory::nt_allocate_virtual_memory(proxy::handle_source,
		&proxy::remote_region_wvm, nullptr, &proxy::size_wvm, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (x != 0 || y != 0 || z != 0)
	{
		return false;
	}

	sdk::memory::nt_write_virtual_memory(proxy::handle_source, proxy::remote_region, proxy::handler, IPC_OFFSET, nullptr);

	auto data = proxy::remote_data::generate_default();

	data.host_req = 1;

	sdk::memory::nt_write_virtual_memory(
		proxy::handle_source, (void*)((unsigned __int64)proxy::remote_region + IPC_OFFSET), &data, sizeof(data), nullptr);

	sdk::memory::nt_create_thread_ex(
		&proxy::remote_thread, THREAD_ALL_ACCESS, nullptr, proxy::handle_source, (LPTHREAD_START_ROUTINE)proxy::remote_region, nullptr, 0, 0, 0, 0, nullptr);

	return proxy::remote_thread != nullptr;
}

auto proxy::exit() -> void
{
	if (proxy::remote_thread != nullptr)
	{
		auto data = proxy::remote_data::generate_default();

		data.host_req = 3;

		sdk::memory::nt_write_virtual_memory(
			proxy::handle_source, (void*)((unsigned __int64)proxy::remote_region + IPC_OFFSET), &data, sizeof(data), nullptr);

		WaitForSingleObject(proxy::remote_thread, INFINITE);
	}

	if (proxy::remote_region != nullptr)
	{
		sdk::memory::nt_free_virtual_memory(proxy::handle_source, &proxy::remote_region, &proxy::size, MEM_RELEASE);
	}

	if (proxy::remote_region_rvm != nullptr)
	{
		sdk::memory::nt_free_virtual_memory(proxy::handle_source, &proxy::remote_region_rvm, &proxy::size_rvm, MEM_RELEASE);
	}

	if (proxy::remote_region_wvm != nullptr)
	{
		sdk::memory::nt_free_virtual_memory(proxy::handle_source, &proxy::remote_region_wvm, &proxy::size_wvm, MEM_RELEASE);
	}

	if (proxy::handle_source != nullptr)
	{
		CloseHandle(proxy::handle_source);
	}
}

auto proxy::rvm(void* address, void* buffer, unsigned __int64 size) -> void
{
	auto data = proxy::remote_data::generate_default();

	data.source_handle = proxy::handle_0;
	data.target_handle = proxy::handle_1;

	data.region = address;
	data.buffer = buffer;
	data.size = min(size, proxy::size_rvm);

	data.host_req = 1;

	sdk::memory::nt_write_virtual_memory(
		proxy::handle_source, (void*)((unsigned __int64)proxy::remote_region + IPC_OFFSET), &data, sizeof(data), nullptr);

	for (; data.host_req != 0; sdk::memory::nt_read_virtual_memory(
		proxy::handle_source, (void*)((unsigned __int64)proxy::remote_region + IPC_OFFSET), &data, sizeof(data), nullptr));

	sdk::memory::nt_read_virtual_memory(proxy::handle_source, proxy::remote_region_rvm, buffer, data.size, nullptr);

	sdk::memory::nt_write_virtual_memory(proxy::handle_source, proxy::remote_region_rvm, &proxy::nuller[0], proxy::size_rvm, nullptr);
}

auto proxy::wvm(void* address, void* buffer, unsigned __int64 size) -> void
{
	auto data = proxy::remote_data::generate_default();

	data.source_handle = proxy::handle_0;
	data.target_handle = proxy::handle_1;

	data.region = address;
	data.buffer = buffer;
	data.size = min(size, proxy::size_wvm);

	data.host_req = 2;

	sdk::memory::nt_write_virtual_memory(proxy::handle_source, proxy::remote_region_wvm, buffer, data.size, nullptr);

	sdk::memory::nt_write_virtual_memory(
		proxy::handle_source, (void*)((unsigned __int64)proxy::remote_region + IPC_OFFSET), &data, sizeof(data), nullptr);

	for (; data.host_req != 0; sdk::memory::nt_read_virtual_memory(
		proxy::handle_source, (void*)((unsigned __int64)proxy::remote_region + IPC_OFFSET), &data, sizeof(data), nullptr));

	sdk::memory::nt_write_virtual_memory(proxy::handle_source, proxy::remote_region_wvm, &proxy::nuller[0], proxy::size_wvm, nullptr);
}