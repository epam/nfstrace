//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: JSON analyzer TCP-service declaration
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
#ifndef JSON_TCP_SERVICE_H
#define JSON_TCP_SERVICE_H
//------------------------------------------------------------------------------
#include "abstract_tcp_service.h"
//------------------------------------------------------------------------------
class JsonTcpService : public AbstractTcpService
{
public:
    JsonTcpService() = delete;
    JsonTcpService(class JsonAnalyzer& analyzer, std::size_t workersAmount, int port, const std::string& host,
                   std::size_t maxServingDurationMs, int backlog);
private:
    class Task : public AbstractTask
    {
    public:
        Task(JsonTcpService& service, int socket);
        Task() = delete;

        void execute() override final;
    private:
        JsonTcpService& _service;
    };

    AbstractTask* createTask(int socket) override final;

    JsonAnalyzer& _analyzer;
    std::size_t _maxServingDurationMs;
};
//------------------------------------------------------------------------------
#endif//JSON_TCP_SERVICE_H
//------------------------------------------------------------------------------
