//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: TCP-service tests.
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
#include <net/abstract_tcp_service.h>

#define LISTEN_HOST TcpEndpoint::LoopbackAddress
#define LISTEN_PORT 8888
#define WORKERS_AMOUNT 100
#define RECEIVE_BUFFER_SIZE 1024

using namespace NST::net;

static const char * TestRequest = "GET";
static const char * TestResponse = "{copy:32,remove:46,getattr:154}";

static std::atomic_int taskExecuteCallsCount;

class TestTcpService : public AbstractTcpService
{
public:
	TestTcpService() = delete;
	TestTcpService(int port, std::size_t workersAmount, int backlog = 15) :
		AbstractTcpService(port, workersAmount, backlog)
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

		virtual void execute() override
		{
			++taskExecuteCallsCount;
			char receiveBuffer[RECEIVE_BUFFER_SIZE];
			ssize_t bytesReceived = recv(socket(), receiveBuffer, sizeof(receiveBuffer), 0);
			EXPECT_EQ(TestRequest, std::string(receiveBuffer, bytesReceived));
			ssize_t bytesSent = send(socket(), TestResponse, strlen(TestResponse), MSG_NOSIGNAL);
			EXPECT_EQ(strlen(TestResponse), bytesSent);
		}
	private:
		TestTcpService& _service;
	};

	virtual AbstractTask * createTask(int socket)
	{
		return new Task(*this, socket);
	}
};

TEST(TcpService, constructDestruct)
{
	EXPECT_NO_THROW(TestTcpService service(LISTEN_PORT, WORKERS_AMOUNT));
}

TEST(TcpService, requestResponse)
{
	taskExecuteCallsCount = 0;
	TestTcpService service(LISTEN_PORT, WORKERS_AMOUNT);
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
	TestTcpService service(LISTEN_PORT, WORKERS_AMOUNT);
	std::vector<int> sockets(WORKERS_AMOUNT);
	for (auto i = 0U; i < sockets.size(); ++i) {
		sockets[i] = socket(PF_INET, SOCK_STREAM, 0);
		ASSERT_GE(sockets[i], 0);
	}
	TcpEndpoint endpoint(LISTEN_HOST, LISTEN_PORT);
	for (auto i = 0U; i < sockets.size(); ++i) {
		ASSERT_EQ(0, connect(sockets[i], endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen));
	}
	for (auto i = 0U; i < sockets.size(); ++i) {
		ssize_t bytesSent = send(sockets[i], TestRequest, strlen(TestRequest), MSG_NOSIGNAL);
		EXPECT_EQ(strlen(TestRequest), bytesSent);
	}
	char receiveBuffer[RECEIVE_BUFFER_SIZE];
	for (auto i = 0U; i < sockets.size(); ++i) {
		ssize_t bytesReceived = recv(sockets[i], receiveBuffer, sizeof(receiveBuffer), 0);
		EXPECT_EQ(TestResponse, std::string(receiveBuffer, bytesReceived));
	}
	for (auto i = 0U; i < sockets.size(); ++i) {
		EXPECT_EQ(0, close(sockets[i]));
	}
	EXPECT_EQ(sockets.size(), taskExecuteCallsCount.load());
}

// TODO
/*TEST(TestTcpService, overload)
{
}*/
