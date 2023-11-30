#ifndef __COROUTINE_INCLUDE_H__
#define __COROUTINE_INCLUDE_H__

#include <coroutine>

namespace cort {

struct task {
	struct promise_type {
		task get_return_object() { return {}; }
		std::suspend_never initial_suspend() { return {}; }
		std::suspend_never final_suspend() noexcept { return {}; }
		void return_void() {}
		void unhandled_exception() {}
	};
	struct awaitable {
		bool await_ready() { return false; }
		void await_resume() {}
		void await_suspend() {}
	};
};

struct awaiter {
	std::coroutine_handle<> *handle;
	constexpr bool await_ready() const noexcept { return false; }
	void await_suspend(std::coroutine_handle<> h) { *handle = h; }
	constexpr void await_resume() const noexcept {}
};

} /* end of namespace cort */

#endif /* end of __COROUTINE_INCLUDE_H__ */
