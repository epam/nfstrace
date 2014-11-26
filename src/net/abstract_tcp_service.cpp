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

#include <net/abstract_tcp_service.h>
#include <functional>
#include <system_error>

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

namespace NST
{
namespace net
{

AbstractTcpService::AbstractTcpService(int port, std::size_t workersAmount, int backlog) :
	_isRunning(true),
	_threadPool(workersAmount),
	_listenerThread(),
	_serverSocket(0),
	_tasksQueue(),
	_tasksQueueMutex(),
	_tasksQueueCond()
{
	// Setting up server TCP-socket
	_serverSocket = socket(PF_INET, SOCK_STREAM, 0);
	if (_serverSocket < 0) {
		throw std::system_error(errno, std::system_category(), "Opening server socket error");
	}
	// Setting SO_REUSEADDR to true
	int reuseAddr = 1;
	if (setsockopt(_serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuseAddr, sizeof(reuseAddr)) < 0) {
		throw std::system_error(errno, std::system_category(), "Setting SO_REUSEADDR socket option error");
	}
	// Binding server socket to endpoint
	TcpEndpoint endpoint(TcpEndpoint::WildcardAddress, port);
	if (bind(_serverSocket, endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen) != 0) {
		throw std::system_error(errno, std::system_category(), "Binding server socket error");
	}
	// Converting socket to listening state
	if (listen(_serverSocket, backlog) != 0) {
		throw std::system_error(errno, std::system_category(), "Converting socket to listening state error");
	}
	// Creating threads for thread-pool
	for (std::size_t i = 0; i < _threadPool.size(); ++i) {
		_threadPool[i] = new std::thread(std::bind(&AbstractTcpService::runWorker, this));
	}
	_listenerThread.reset(new std::thread(std::bind(&AbstractTcpService::runListener, this)));
}

AbstractTcpService::~AbstractTcpService()
{
	_isRunning = false;
	{
		// Waking up all awaiting threads
		std::unique_lock<std::mutex> lock(_tasksQueueMutex);
		_tasksQueueCond.notify_all();
	}
	// Joining to thread-pool threads and disposing them
	for (std::size_t i = 0; i < _threadPool.size(); ++i) {
		_threadPool[i]->join();
		delete _threadPool[i];
	}
	_threadPool.clear();
	_listenerThread->join();
	close(_serverSocket);
	// Disposing tasks which are still in queue
	while (!_tasksQueue.empty()) {
		delete _tasksQueue.front();
		_tasksQueue.pop();
	}
}

void AbstractTcpService::runWorker()
{
	while (_isRunning.load()) {
		std::unique_ptr<AbstractTask> pendingTask;
		{
			std::unique_lock<std::mutex> lock(_tasksQueueMutex);
			if (!_tasksQueue.empty()) {
				pendingTask.reset(_tasksQueue.front());
				_tasksQueue.pop();
			} else {
				_tasksQueueCond.wait(lock);
				if (!_tasksQueue.empty()) {
					pendingTask.reset(_tasksQueue.front());
					_tasksQueue.pop();
				}
			}
		}
		if (pendingTask.get() != nullptr) {
			pendingTask->execute();
		}
	}
}

void AbstractTcpService::runListener()
{
	while (_isRunning.load()) {
		// Accepting incoming connection on socket
		struct timespec acceptDuration;
		fillDuration(acceptDuration);
		fd_set descriptorsSet;
		FD_ZERO(&descriptorsSet);
		FD_SET(_serverSocket, &descriptorsSet);
		int descriptorsCount = pselect(_serverSocket + 1, &descriptorsSet, NULL, NULL, &acceptDuration, NULL);
		if (descriptorsCount == 0) {
			// Timeout expired
			continue;
		} else if (descriptorsCount < 0) {
			std::system_error(errno, std::system_category(), "Awaiting for incoming connection on server socket error");
		}
		// Extracting and returning pending connection
		int pendingSocketDescriptor = accept(_serverSocket, NULL, NULL);
		if (pendingSocketDescriptor < 0) {
			throw std::runtime_error("Accepting incoming connection on server socket error");
		}
		// Create and enqueue task
		std::unique_ptr<AbstractTask> newTask(createTask(pendingSocketDescriptor));
		{
			std::unique_lock<std::mutex> lock(_tasksQueueMutex);
			if (_tasksQueue.size() < MaxTasksQueueSize) {
				_tasksQueue.push(newTask.get());
				newTask.release();
				_tasksQueueCond.notify_one();
			} else {
				// TODO: To log overload event
				// Just close pending socket on overload
				close(pendingSocketDescriptor);
			}
		}
	}
}

//------------------------------------------------------------------------------

AbstractTcpService::AbstractTask::AbstractTask(int socket) :
	_socket(socket)
{}

AbstractTcpService::AbstractTask::~AbstractTask()
{
	close(_socket);
}

} // namespace net
} // namespace NST
