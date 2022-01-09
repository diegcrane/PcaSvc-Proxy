
#include "../../helper/sdk/sdk.hpp"

#define IPC_OFFSET 0x400

namespace proxy
{
	inline void* handle_source = nullptr;
	inline void* handle_0 = nullptr;
	inline void* handle_1 = nullptr;

	inline unsigned __int64 size = 0x800;

	inline void* remote_region = nullptr;
	inline void* remote_thread = nullptr;
}

namespace proxy
{
	inline void* remote_region_rvm = nullptr;
	inline void* remote_region_wvm = nullptr;

	inline unsigned __int64 size_rvm = 0x6400000;
	inline unsigned __int64 size_wvm = 0x6400000;

	inline std::vector<unsigned char> nuller(0x6400000, 0);
}

namespace proxy
{
	struct remote_data
	{
		void* del = nullptr;
		void* rvm = nullptr;
		void* wvm = nullptr;
		
		_LARGE_INTEGER _del;

		void* buffer_rvm = nullptr;
		void* buffer_wvm = nullptr;

		void* source_handle = nullptr;
		void* target_handle = nullptr;
	
		void* region = nullptr;
		void* buffer = nullptr;

		unsigned __int64 size = 0;

		void* bytes_data = nullptr;

		unsigned __int32 host_req = 0;

		static auto generate_default() -> proxy::remote_data;
	};
}

namespace proxy
{
	extern auto handler() -> unsigned __int64;
}

namespace proxy
{
	extern auto init(unsigned long source_pid, unsigned long target_pid) -> bool;
	extern auto exit() -> void;
}

namespace proxy
{
	extern auto rvm(void* address, void* buffer, unsigned __int64 size) -> void;
	extern auto wvm(void* address, void* buffer, unsigned __int64 size) -> void;
}