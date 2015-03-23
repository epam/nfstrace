//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: Abstract TCP-service class declaration
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
//------------------------------------------------------------------------------
#ifndef ABSTRACT_TCP_SERVICE_H
#define ABSTRACT_TCP_SERVICE_H
//------------------------------------------------------------------------------
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "ip_endpoint.h"
//------------------------------------------------------------------------------
//! TCP-service
/*!
 * Abstract task for TCP-service
 */
class AbstractTcpService
{
public:
    static constexpr int DefaultBacklog = 15;

    AbstractTcpService() = delete;
    //! Constructs TCP-service
    /*!
     * \param workersAmount Amount of workers in thread-pool
     * \param port Port to bind to
     * \param host Hostname/IP-address to listen
     * \param backlog Listen backlog - see listen(2)
     */
    AbstractTcpService(std::size_t workersAmount, int port, const std::string& host = IpEndpoint::WildcardAddress,
                       int backlog = DefaultBacklog);
    //! Destructs stopped TCP-service
    /*!
     * \note Destruction of non-stopped TCP-service causes undefined behaviour
     */
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

    //! Starts TCP-service
    virtual void start();
    //! Stops TCP-service
    virtual void stop();
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
        //! Destructs TCP-service task and closes I/O socket
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

    virtual AbstractTask* createTask(int socket) = 0;
private:
    using ThreadPool = std::vector<std::thread>;

    static constexpr int ClockTimeoutMs = 100;
    static constexpr std::size_t ReadBufferSize = 1024;
    static constexpr std::size_t WriteBufferSize = 4096;
    static constexpr std::size_t HeaderPartSize = 1024;
    static constexpr int MaxTasksQueueSize = 128;

    void runWorker();
    void runListener();

    const int _port;
    const std::string _host;
    const int _backlog;
    std::atomic_bool _isRunning;
    ThreadPool _threadPool;
    std::thread _listenerThread;
    int _serverSocket;
    std::queue<AbstractTask*> _tasksQueue;
    std::mutex _tasksQueueMutex;
    std::condition_variable _tasksQueueCond;
};
//------------------------------------------------------------------------------
#endif//ABSTRACT_TCP_SERVICE_H
//------------------------------------------------------------------------------
