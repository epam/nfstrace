//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: TCP-service.
// Copyright (c) 2013-2014 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef TCP_SERVICE_H
#define TCP_SERVICE_H

#include <net/tcp_endpoint.h>
#include <vector>
#include <queue>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <atomic>

namespace NST
{
namespace net
{

//! TCP-service
/*!
 * Abstract task for TCP-service
 */
class AbstractTcpService
{
public:
	AbstractTcpService() = delete;
	//! Constructs TCP-service and starts it
	/*!
	 * \param port Port to listen on
	 * \param workersAmount Amount of workers in thread-pool
	 * \param Listen backlog - see listen(2)
	 */
	AbstractTcpService(int port, std::size_t workersAmount, int backlog = 15);
	//! Stops TCP-service and destructs it
	virtual ~AbstractTcpService();

	//! Returns TRUE if service is in running state
	inline bool isRunning() const
	{
		return _isRunning.load();
	}
	//! Fills 'struct timespec' value using clock timeout
	inline static void fillDuration(struct timespec& ts)
	{
		ts.tv_sec = ClockTimeoutMs / 1000;
		ts.tv_nsec = ClockTimeoutMs % 1000 * 1000000;
	}
protected:
	//! Asbtract TCP-service task
	class AbstractTask
	{
	public:
		//! Constructs TCP-service task
		/*!
		 * \param socket Socket for I/O
		 */
		AbstractTask(int socket);
		AbstractTask() = delete;
		//! Descructs TCP-service task and closes I/O socket
		virtual ~AbstractTask();

		//! Returns a socket for I/O
		inline int socket() const
		{
			return _socket;
		}
	
		//! Task execution pure virtual method to override
		virtual void execute() = 0;
	private:
		int _socket;
	};

	virtual AbstractTask * createTask(int socket) = 0;
private:
	typedef std::vector<std::thread *> ThreadPool;

	static const int ClockTimeoutMs = 100;
	static const std::size_t ReadBufferSize = 1024;
	static const std::size_t WriteBufferSize = 4096;
	static const std::size_t HeaderPartSize = 1024;
	static const int MaxTasksQueueSize = 128;

	void runWorker();
	void runListener();

	std::atomic_bool _isRunning;
	ThreadPool _threadPool;
	std::unique_ptr<std::thread> _listenerThread;
	int _serverSocket;
	std::queue<AbstractTask *> _tasksQueue;
	std::mutex _tasksQueueMutex;
	std::condition_variable _tasksQueueCond;
};

} // namespace net
} // namespace NST

#endif // TCP_ENPOINT_H

