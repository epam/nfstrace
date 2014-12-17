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
//------------------------------------------------------------------------------
#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/socket.h>

#include "net/abstract_tcp_service.h"
//------------------------------------------------------------------------------
using namespace NST::net;

static constexpr std::size_t AwaitForServiceStartupMs = 250U;
static constexpr std::size_t TransmissionTimeoutMs = 10000U;
static constexpr const char* ListenHost = TcpEndpoint::LoopbackAddress;
static constexpr int ListenPort = 8888;
static constexpr std::size_t WorkersAmount = 100U;
static constexpr std::size_t ReceiveBufferSize = 4096U;
static constexpr const char* TestRequest = "GET";
static constexpr const char* TestResponse = "{copy:32,remove:46,getattr:154}";

static std::atomic_int taskExecuteCallsCount;

class TestTcpService : public AbstractTcpService
{
public:
    TestTcpService() :
        AbstractTcpService{WorkersAmount, ListenPort, ListenHost}
    {}
private:
    class Task : public AbstractTask
    {
    public:
        Task(TestTcpService& service, int socket) :
            AbstractTask{socket},
            _service(service)
        {}
        Task() = delete;

        void execute() override final
        {
            ++taskExecuteCallsCount;
            // Receiving request
            struct timespec readTimeout;
            readTimeout.tv_sec = TransmissionTimeoutMs / 1000;
            readTimeout.tv_nsec = TransmissionTimeoutMs % 1000 * 1000000;
            fd_set readDescriptiorsSet;
            FD_ZERO(&readDescriptiorsSet);
            FD_SET(socket(), &readDescriptiorsSet);
            int readDescriptorsCount = pselect(socket() + 1, &readDescriptiorsSet, NULL, NULL, &readTimeout, NULL);
            ASSERT_GT(readDescriptorsCount, 0);
            ASSERT_TRUE(FD_ISSET(socket(), &readDescriptiorsSet));
            char receiveBuffer[ReceiveBufferSize];
            ssize_t bytesReceived = recv(socket(), receiveBuffer, sizeof(receiveBuffer), 0);
            EXPECT_EQ(TestRequest, std::string(receiveBuffer, bytesReceived));
            // Sending response
            struct timespec writeTimeout;
            writeTimeout.tv_sec = TransmissionTimeoutMs / 1000;
            writeTimeout.tv_nsec = TransmissionTimeoutMs % 1000 * 1000000;
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
        return new Task{*this, socket};
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
    std::this_thread::sleep_for(std::chrono::milliseconds{AwaitForServiceStartupMs});
    int s = socket(PF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    TcpEndpoint endpoint{ListenHost, ListenPort};
    ASSERT_EQ(0, connect(s, endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen));
    ssize_t bytesSent = send(s, TestRequest, strlen(TestRequest), MSG_NOSIGNAL);
    EXPECT_EQ(strlen(TestRequest), bytesSent);
    char receiveBuffer[ReceiveBufferSize];
    ssize_t bytesReceived = recv(s, receiveBuffer, sizeof(receiveBuffer), 0);
    EXPECT_EQ(TestResponse, std::string(receiveBuffer, bytesReceived));
    EXPECT_EQ(0, close(s));
    EXPECT_EQ(1, taskExecuteCallsCount.load());
}

TEST(TestTcpService, multipleRequestResponse)
{
    taskExecuteCallsCount = 0;
    TestTcpService service;
    std::this_thread::sleep_for(std::chrono::milliseconds{AwaitForServiceStartupMs});
    std::vector<int> sockets(WorkersAmount);
    for (auto & s : sockets)
    {
        s = socket(PF_INET, SOCK_STREAM, 0);
        ASSERT_GE(s, 0);
    }
    TcpEndpoint endpoint{ListenHost, ListenPort};
    for (auto & s : sockets)
    {
        ASSERT_EQ(0, connect(s, endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen));
    }
    for (auto & s : sockets)
    {
        ssize_t bytesSent = send(s, TestRequest, strlen(TestRequest), MSG_NOSIGNAL);
        EXPECT_EQ(strlen(TestRequest), bytesSent);
    }
    char receiveBuffer[ReceiveBufferSize];
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
