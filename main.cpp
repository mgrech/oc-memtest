// Copyright 2019 Markus Grech
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <immintrin.h>

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using usize = std::uintptr_t;

std::mutex output_mutex;
std::atomic_bool stop{false};

constexpr usize KB = 1024;
constexpr usize MB = KB * KB;
constexpr usize GB = KB * MB;

constexpr usize BLOCK_ALIGN = KB;
constexpr usize BLOCK_SIZE = 16 * MB;

constexpr std::array PATTERNS =
{
	0b0000'0000, 0b1111'1111,
	0b0101'0101, 0b1010'1010,
	0b1100'1100, 0x0011'0011,
};

struct progress
{
	std::atomic<usize> block_count{0};
	std::atomic<usize> error_count{0};
};

struct memory_error
{
	void const* addr;
	u8 expected, actual;
};

void memory_scramble(__m256i* memory, usize size, __m256i pattern)
{
	for(usize i = 0; i != size / sizeof *memory; ++i)
	{
		auto addr = memory + i;
		_mm256_store_si256(addr, _mm256_xor_si256(_mm256_load_si256(addr), pattern));
	}
}

void memory_scramble(u8* memory, usize size, u8 value0, u8 value1)
{
	u16 pattern = value0 | (value1 << 8);
	memory_scramble((__m256i*)memory, size, _mm256_set1_epi16(pattern));
}

std::vector<memory_error> memory_validate(u8 const* memory, usize size, u8 value0, u8 value1)
{
	std::vector<memory_error> errors;

	for(usize i = 0; i != size / 2; ++i)
	{
		auto base = memory + 2 * i;

		if(base[0] != value0)
			errors.push_back({base, value0, base[0]});

		if(base[1] != value1)
			errors.push_back({base + 1, value1, base[1]});
	}

	return errors;
}

void print_test_status(usize size, usize iters, progress& prog)
{
	auto block_goal = iters * size / BLOCK_SIZE;
	auto fmt = "\r                                                    \r%.2f%% complete, %zu errors";
	std::printf(fmt, (double)prog.block_count * 100 / block_goal, prog.error_count.load());
}

void print_memory_errors(std::vector<memory_error> const& errors, usize size, usize iters, usize iter, progress& prog)
{
	std::lock_guard<std::mutex> _(output_mutex);

	for(auto error : errors)
	{
		auto fmt = "\riteration %zu: error at address [%p]: expected=[%s], actual=[%s]\n";
		auto expected_str = std::bitset<8>(error.expected).to_string();
		auto actual_str = std::bitset<8>(error.actual).to_string();
		std::printf(fmt, iter, error.addr, expected_str.c_str(), actual_str.c_str());
		print_test_status(size, iters, prog);
	}
}

void optimization_barrier()
{
	// optimization barrier, nothing to do with synchronization
	// prevents the compiler from moving reads and writes across,
	// forcing everything to be written into memory before and re-read from memory after
	// volatile on the memory would work too, but prevents optimizations and doesn't work with simd intrinsics
	std::atomic_thread_fence(std::memory_order_seq_cst);
}

void memory_test_iteration(u8* memory, usize size, usize iters, usize iter, progress& prog)
{
	std::memset(memory, 0, size);

	for(usize block = 0; block != size / BLOCK_SIZE && !stop; ++block)
	{
		auto block_memory = memory + block * BLOCK_SIZE;

		for(usize i = 0; i != PATTERNS.size() - 1; ++i)
		{
			optimization_barrier();
			memory_scramble(block_memory, BLOCK_SIZE, PATTERNS[i], PATTERNS[i + 1]);
		}

		optimization_barrier();
	}

	if(stop)
		return;

	u8 value0 = 0, value1 = 0;

	for(usize i = 0; i != PATTERNS.size() - 1; ++i)
	{
		value0 ^= PATTERNS[i];
		value1 ^= PATTERNS[i + 1];
	}

	for(usize block = 0; block != size / BLOCK_SIZE && !stop; ++block)
	{
		auto block_memory = memory + block * BLOCK_SIZE;
		auto errors = memory_validate(block_memory, BLOCK_SIZE, value0, value1);

		print_memory_errors(errors, size, iters, iter, prog);
		prog.error_count += errors.size();
		++prog.block_count;
	}
}

void memory_test(u8* memory, usize size, usize iters)
{
	auto hwthreads = std::max(1u, std::thread::hardware_concurrency());
	auto tsize = size / hwthreads / BLOCK_ALIGN * BLOCK_ALIGN;

	std::printf("using %d threads with %zu MiB assigned each\n", (int)hwthreads, tsize / MB);

	std::vector<std::thread> workers;
	progress prog;

	for(usize ti = 0; ti != hwthreads; ++ti)
	{
		workers.emplace_back([&, ti]
		{
			auto tmemory = memory + ti * tsize;

			for(usize i = 0; i != iters && !stop; ++i)
				memory_test_iteration(tmemory, tsize, iters, i, prog);
		});

		auto handle = workers.back().native_handle();
		SetThreadAffinityMask(handle, 1ull << ti);
	}

	auto block_goal = iters * size / BLOCK_SIZE;

	while(prog.block_count != block_goal && !stop)
	{
		std::this_thread::sleep_for(std::chrono::seconds(1));

		std::lock_guard<std::mutex> _(output_mutex);
		print_test_status(size, iters, prog);
	}

	for(auto& worker : workers)
		worker.join();

	if(stop)
		std::printf("\ntest cancelled\n");
}

std::string last_error_string()
{
	auto error = GetLastError();

	if(error == 0)
		return {};

	LPSTR buffer = nullptr;
	DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	auto lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
	auto size = FormatMessageA(flags, nullptr, error, lang, (LPSTR)&buffer, 0, nullptr);

	std::string message(buffer, size);
	LocalFree(buffer);
	return message;
}

bool obtain_lockmemory_privilege()
{
	HANDLE token;

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
	{
		std::fprintf(stderr, "OpenProcessToken failed: %s\n", last_error_string().c_str());
		return false;
	}

	TOKEN_PRIVILEGES priv = {};
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if(!LookupPrivilegeValueA(nullptr, "SeLockMemoryPrivilege", &priv.Privileges[0].Luid))
	{
		std::fprintf(stderr, "LookupPrivilegeValue failed: %s\n", last_error_string().c_str());
		CloseHandle(token);
		return false;
	}

	if(!AdjustTokenPrivileges(token, false, &priv, 0, nullptr, nullptr))
	{
		std::fprintf(stderr, "AdjustTokenPrivileges failed: %s\n", last_error_string().c_str());
		CloseHandle(token);
		return false;
	}

	CloseHandle(token);
	return true;
}

u8* memory_allocate(usize size, bool physical)
{
	if(!physical)
	{
		auto memory = (u8*)VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if(!memory)
			std::fprintf(stderr, "failed to allocate memory: %s\n", last_error_string().c_str());

		return memory;
	}

	SYSTEM_INFO info = {};
	GetSystemInfo(&info);

	ULONG_PTR page_count = size / info.dwPageSize;
	std::vector<ULONG_PTR> pages(page_count);

	if(!AllocateUserPhysicalPages(GetCurrentProcess(), &page_count, pages.data()))
	{
		std::fprintf(stderr, "failed to allocate physical pages: %s\n", last_error_string().c_str());
		return nullptr;
	}

	if(page_count != size / info.dwPageSize)
	{
		std::fprintf(stderr, "not enough free memory\n");

		if(!FreeUserPhysicalPages(GetCurrentProcess(), &page_count, pages.data()))
			std::fprintf(stderr, "FreeUserPhysicalPages failed\n");

		return nullptr;
	}

	auto memory = (u8*)VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_PHYSICAL, PAGE_READWRITE);

	if(!memory)
	{
		std::fprintf(stderr, "failed to allocate virtual pages: %s\n", last_error_string().c_str());
		FreeUserPhysicalPages(GetCurrentProcess(), &page_count, pages.data());
		return nullptr;
	}

	if(!MapUserPhysicalPages(memory, page_count, pages.data()))
	{
		std::fprintf(stderr, "failed to map physical pages: %s\n", last_error_string().c_str());
		return nullptr;
	}

	return memory;
}

void signal_handler(int)
{
	stop = true;
}

int main(int argc, char** argv)
{
	if(argc != 3)
	{
		std::fprintf(stderr, "usage: %s <memory> <iterations>\n", argv[0]);
		std::fprintf(stderr, "memory      -- amount of memory to test, in GiB\n");
		std::fprintf(stderr, "iterations  -- number of passes over the memory\n");
		return 1;
	}

	auto lockperms = obtain_lockmemory_privilege();

	if(!lockperms)
		std::fprintf(stderr, "warning: could not obtain privileges to lock memory\n");

	auto size = std::strtoull(argv[1], nullptr, 10) * GB;
	auto iters = std::strtoull(argv[2], nullptr, 10);

	auto memory = memory_allocate(size, lockperms);

	if(!memory)
		return 1;

	std::signal(SIGINT,  signal_handler);
	std::signal(SIGTERM, signal_handler);
	memory_test(memory, size, iters);
}
