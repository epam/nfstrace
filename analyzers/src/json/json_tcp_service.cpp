//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: JSON analyzer TCP-service definition
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

#include <json.h>

#include "json_analyzer.h"
#include "json_tcp_service.h"
#include "utils/log.h"
//------------------------------------------------------------------------------

JsonTcpService::JsonTcpService(JsonAnalyzer& analyzer, std::size_t workersAmount, int port, const std::string& host,
                               std::size_t maxServingDurationMs, int backlog) :
    AbstractTcpService(workersAmount, port, host, backlog),
    _analyzer(analyzer),
    _maxServingDurationMs(maxServingDurationMs)
{}

AbstractTcpService::AbstractTask* JsonTcpService::createTask(int socket)
{
    return new Task(*this, socket);
}

//------------------------------------------------------------------------------

JsonTcpService::Task::Task(JsonTcpService& service, int socket) :
    AbstractTask(socket),
    _service(service)
{}

void JsonTcpService::Task::execute()
{
    std::chrono::system_clock::time_point servingStarted = std::chrono::system_clock::now();
    // Composing JSON with statistics
    struct json_object* root = json_object_new_object();
    struct json_object* nfsV3Stat = json_object_new_object();
    json_object_object_add(nfsV3Stat, "null", json_object_new_int64(_service._analyzer.getNfsV3Stat().nullOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "getattr", json_object_new_int64(_service._analyzer.getNfsV3Stat().getattrOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "setattr", json_object_new_int64(_service._analyzer.getNfsV3Stat().setattrOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "lookup", json_object_new_int64(_service._analyzer.getNfsV3Stat().lookupOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "access", json_object_new_int64(_service._analyzer.getNfsV3Stat().accessOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "readlink", json_object_new_int64(_service._analyzer.getNfsV3Stat().readlinkOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "read", json_object_new_int64(_service._analyzer.getNfsV3Stat().readOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "write", json_object_new_int64(_service._analyzer.getNfsV3Stat().writeOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "create", json_object_new_int64(_service._analyzer.getNfsV3Stat().createOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "mkdir", json_object_new_int64(_service._analyzer.getNfsV3Stat().mkdirOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "symlink", json_object_new_int64(_service._analyzer.getNfsV3Stat().symlinkOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "mkdnod", json_object_new_int64(_service._analyzer.getNfsV3Stat().mknodOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "remove", json_object_new_int64(_service._analyzer.getNfsV3Stat().removeOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "rmdir", json_object_new_int64(_service._analyzer.getNfsV3Stat().rmdirOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "rename", json_object_new_int64(_service._analyzer.getNfsV3Stat().renameOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "link", json_object_new_int64(_service._analyzer.getNfsV3Stat().linkOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "readdir", json_object_new_int64(_service._analyzer.getNfsV3Stat().readdirOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "readdirplus", json_object_new_int64(_service._analyzer.getNfsV3Stat().readdirplusOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "fsstat", json_object_new_int64(_service._analyzer.getNfsV3Stat().fsstatOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "fsinfo", json_object_new_int64(_service._analyzer.getNfsV3Stat().fsinfoOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "pathconf", json_object_new_int64(_service._analyzer.getNfsV3Stat().pathconfOpsAmount.load()));
    json_object_object_add(nfsV3Stat, "commit", json_object_new_int64(_service._analyzer.getNfsV3Stat().commitOpsAmount.load()));
    json_object_object_add(root, "nfs_v3", nfsV3Stat);
    struct json_object* nfsV4Stat = json_object_new_object();
    json_object_object_add(nfsV4Stat, "null", json_object_new_int64(_service._analyzer.getNfsV4Stat().nullOpsAmount.load()));
    json_object_object_add(nfsV4Stat, "compound", json_object_new_int64(_service._analyzer.getNfsV4Stat().compoundOpsAmount.load()));
    json_object_object_add(root, "nfs_v4", nfsV4Stat);
    std::string json(json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    json_object_put(root);

    // Sending JSON to the client
    std::size_t totalBytesSent = 0U;
    while (totalBytesSent < json.length())
    {
        if (!_service.isRunning())
        {
            LOG("WARNING: Service shutdown detected - terminating task execution");
            return;
        }
        if (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - servingStarted).count() >
                static_cast<std::chrono::milliseconds::rep>(_service._maxServingDurationMs))
        {
            // TODO: Use general logging
            LOG("WARNING: A client is too slow - terminating task execution");
            return;
        }
        struct timespec writeDuration;
        AbstractTcpService::fillDuration(writeDuration);
        fd_set writeDescriptorsSet;
        FD_ZERO(&writeDescriptorsSet);
        FD_SET(socket(), &writeDescriptorsSet);
        int descriptorsCount = pselect(socket() + 1, NULL, &writeDescriptorsSet, NULL, &writeDuration, NULL);
        if (descriptorsCount < 0)
        {
            throw std::system_error(errno, std::system_category(), "Error awaiting for sending data availability on socket");
        }
        else if (descriptorsCount == 0)
        {
            // Timeout expired
            continue;
        }
        ssize_t bytesSent = send(socket(), json.data() + totalBytesSent, json.length() - totalBytesSent, MSG_NOSIGNAL);
        if (bytesSent < 0)
        {
            std::system_error e(errno, std::system_category(), "Sending data to client error");
            LOG("WARNING: %s", e.what());
            return;
        }
        else if (bytesSent == 0)
        {
            LOG("WARNING: Connection has been aborted by client while sending data");
            return;
        }
        totalBytesSent += bytesSent;
    }
}
//------------------------------------------------------------------------------
