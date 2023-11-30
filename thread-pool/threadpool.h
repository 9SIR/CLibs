#ifndef __THREAD_POOL_HEADER__
#define __THREAD_POOL_HEADER__

#include <string>

namespace thread {
template<typename T, typename S>
class pool
{
private:
	const unsigned int poolSize; /* thread pool size */
	unsigned int curThreadNum;   /* current thread number running in pool */
	/*
	 * task struct for the threads to executing
	 */
	struct task {
		T *argv; /* arguments input for the thread */
		const int (*func)(void *); /* the function that tells the thread how to execute */
		S *result; /* results after the func executed output */
	};

public:
	explicit pool();
	pool(pool &p) = delete;

	/**
	 * create a thread by thread name and milliseconds timeout for free waitting task
	 * threadName: thread name fro creating
	 * timeout: milliseconds timeout for free waitting task
	 * return: thread ID for successful, 0 for creating failed
	 */
	virtual const unsigned int createThread(
		const std::string &threadName, const unsigned int timeout);
};

} /* namespace thread */

#endif /* __THREAD_POOL_HEADER__ */
