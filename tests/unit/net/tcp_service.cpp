//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: TCP-service tests
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <chrono>
#include <thread>
#include <net/abstract_tcp_service.h>
#include <sys/socket.h>

#define AWAIT_FOR_SERVICE_STARTUP_MS 250
#define TRANSMISSION_TIMEOUT_MS 10000
#define LISTEN_HOST TcpEndpoint::LoopbackAddress
#define LISTEN_PORT 8888
#define WORKERS_AMOUNT 100
#define RECEIVE_BUFFER_SIZE 4096

using namespace NST::net;

static const char* TestRequest = "GET";
static const char* TestResponse = "{copy:32,remove:46,getattr:154}";

static std::atomic_int taskExecuteCallsCount;

class TestTcpService : public AbstractTcpService
{
public:
    TestTcpService() :
        AbstractTcpService(WORKERS_AMOUNT, LISTEN_PORT, LISTEN_HOST)
    {}
private:
    class Task : public AbstractTask
    {
    public:
        Task(TestTcpService& service, int socket) :
            AbstractTask(socket),
            _service(service)
        {}
        Task() = delete;

        void execute() override final
        {
            ++taskExecuteCallsCount;
            // Receiving request
            struct timespec readTimeout;
            readTimeout.tv_sec = TRANSMISSION_TIMEOUT_MS / 1000;
            readTimeout.tv_nsec = TRANSMISSION_TIMEOUT_MS % 1000 * 1000000;
            fd_set readDescriptiorsSet;
            FD_ZERO(&readDescriptiorsSet);
            FD_SET(socket(), &readDescriptiorsSet);
            int readDescriptorsCount = pselect(socket() + 1, &readDescriptiorsSet, NULL, NULL, &readTimeout, NULL);
            ASSERT_GT(readDescriptorsCount, 0);
            ASSERT_TRUE(FD_ISSET(socket(), &readDescriptiorsSet));
            char receiveBuffer[RECEIVE_BUFFER_SIZE];
            ssize_t bytesReceived = recv(socket(), receiveBuffer, sizeof(receiveBuffer), 0);
            EXPECT_EQ(TestRequest, std::string(receiveBuffer, bytesReceived));
            // Sending response
            struct timespec writeTimeout;
            writeTimeout.tv_sec = TRANSMISSION_TIMEOUT_MS / 1000;
            writeTimeout.tv_nsec = TRANSMISSION_TIMEOUT_MS % 1000 * 1000000;
            fd_set writeDescriptiorsSet;
            FD_ZERO(&writeDescriptiorsSet);
            FD_SET(socket(), &writeDescriptiorsSet);
            int writeDescriptorsCount = pselect(socket() + 1, NULL, &writeDescriptiorsSet, NULL, &writeTimeout, NULL);
            ASSERT_GT(writeDescriptorsCount, 0);
            ASSERT_TRUE(FD_ISSET(socket(), &writeDescriptiorsSet));
            ssize_t bytesSent = send(socket(), TestResponse, strlen(TestResponse), MSG_NOSIGNAL);
            EXPECT_EQ(strlen(TestResponse), bytesSent);
        }
    private:
        TestTcpService& _service;
    };

    AbstractTask* createTask(int socket) override final
    {
        return new Task(*this, socket);
    }
};

TEST(TestTcpService, constructDestruct)
{
    EXPECT_NO_THROW(TestTcpService service);
}

TEST(TestTcpService, requestResponse)
{
    taskExecuteCallsCount = 0;
    TestTcpService service;
    std::this_thread::sleep_for(std::chrono::milliseconds(AWAIT_FOR_SERVICE_STARTUP_MS));
    int s = socket(PF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    TcpEndpoint endpoint(LISTEN_HOST, LISTEN_PORT);
    ASSERT_EQ(0, connect(s, endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen));
    ssize_t bytesSent = send(s, TestRequest, strlen(TestRequest), MSG_NOSIGNAL);
    EXPECT_EQ(strlen(TestRequest), bytesSent);
    char receiveBuffer[RECEIVE_BUFFER_SIZE];
    ssize_t bytesReceived = recv(s, receiveBuffer, sizeof(receiveBuffer), 0);
    EXPECT_EQ(TestResponse, std::string(receiveBuffer, bytesReceived));
    EXPECT_EQ(0, close(s));
    EXPECT_EQ(1, taskExecuteCallsCount.load());
}

TEST(TestTcpService, multipleRequestResponse)
{
    taskExecuteCallsCount = 0;
    TestTcpService service;
    std::this_thread::sleep_for(std::chrono::milliseconds(AWAIT_FOR_SERVICE_STARTUP_MS));
    std::vector<int> sockets(WORKERS_AMOUNT);
    for (auto & s : sockets)
    {
        s = socket(PF_INET, SOCK_STREAM, 0);
        ASSERT_GE(s, 0);
    }
    TcpEndpoint endpoint(LISTEN_HOST, LISTEN_PORT);
    for (auto & s : sockets)
    {
        ASSERT_EQ(0, connect(s, endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen));
    }
    for (auto & s : sockets)
    {
        ssize_t bytesSent = send(s, TestRequest, strlen(TestRequest), MSG_NOSIGNAL);
        EXPECT_EQ(strlen(TestRequest), bytesSent);
    }
    char receiveBuffer[RECEIVE_BUFFER_SIZE];
    for (auto & s : sockets)
    {
        ssize_t bytesReceived = recv(s, receiveBuffer, sizeof(receiveBuffer), 0);
        EXPECT_EQ(TestResponse, std::string(receiveBuffer, bytesReceived));
    }
    for (auto & s : sockets)
    {
        EXPECT_EQ(0, close(s));
    }
    EXPECT_EQ(sockets.size(), taskExecuteCallsCount.load());
}

// TODO
/*TEST(TestTcpService, overload)
{
}*/
