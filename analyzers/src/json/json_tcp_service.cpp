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
    AbstractTcpService{workersAmount, port, host, backlog},
    _analyzer(analyzer),
    _maxServingDurationMs{maxServingDurationMs}
{}

AbstractTcpService::AbstractTask* JsonTcpService::createTask(int socket)
{
    return new Task(*this, socket);
}

//------------------------------------------------------------------------------

JsonTcpService::Task::Task(JsonTcpService& service, int socket) :
    AbstractTask{socket},
    _service(service)
{}

void JsonTcpService::Task::execute()
{
    std::chrono::system_clock::time_point servingStarted = std::chrono::system_clock::now();
    // Composing JSON with statistics
    struct json_object* root = json_object_new_object();
    struct json_object* nfsV3Stat = json_object_new_object();
    // NFS3 procedures:
    json_object_object_add(nfsV3Stat, "null", json_object_new_int64(_service._analyzer.getNfsV3Stat().nullProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "getattr", json_object_new_int64(_service._analyzer.getNfsV3Stat().getattrProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "setattr", json_object_new_int64(_service._analyzer.getNfsV3Stat().setattrProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "lookup", json_object_new_int64(_service._analyzer.getNfsV3Stat().lookupProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "access", json_object_new_int64(_service._analyzer.getNfsV3Stat().accessProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "readlink", json_object_new_int64(_service._analyzer.getNfsV3Stat().readlinkProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "read", json_object_new_int64(_service._analyzer.getNfsV3Stat().readProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "write", json_object_new_int64(_service._analyzer.getNfsV3Stat().writeProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "create", json_object_new_int64(_service._analyzer.getNfsV3Stat().createProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "mkdir", json_object_new_int64(_service._analyzer.getNfsV3Stat().mkdirProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "symlink", json_object_new_int64(_service._analyzer.getNfsV3Stat().symlinkProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "mkdnod", json_object_new_int64(_service._analyzer.getNfsV3Stat().mknodProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "remove", json_object_new_int64(_service._analyzer.getNfsV3Stat().removeProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "rmdir", json_object_new_int64(_service._analyzer.getNfsV3Stat().rmdirProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "rename", json_object_new_int64(_service._analyzer.getNfsV3Stat().renameProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "link", json_object_new_int64(_service._analyzer.getNfsV3Stat().linkProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "readdir", json_object_new_int64(_service._analyzer.getNfsV3Stat().readdirProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "readdirplus", json_object_new_int64(_service._analyzer.getNfsV3Stat().readdirplusProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "fsstat", json_object_new_int64(_service._analyzer.getNfsV3Stat().fsstatProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "fsinfo", json_object_new_int64(_service._analyzer.getNfsV3Stat().fsinfoProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "pathconf", json_object_new_int64(_service._analyzer.getNfsV3Stat().pathconfProcsAmount.load()));
    json_object_object_add(nfsV3Stat, "commit", json_object_new_int64(_service._analyzer.getNfsV3Stat().commitProcsAmount.load()));
    json_object_object_add(root, "nfs_v3", nfsV3Stat);
    struct json_object* nfsV40Stat = json_object_new_object();
    // NFS4.0 procedures:
    json_object_object_add(nfsV40Stat, "null", json_object_new_int64(_service._analyzer.getNfsV40Stat().nullProcsAmount.load()));
    json_object_object_add(nfsV40Stat, "compound", json_object_new_int64(_service._analyzer.getNfsV40Stat().compoundProcsAmount.load()));
    // NFS4.0 operations:
    json_object_object_add(nfsV40Stat, "access", json_object_new_int64(_service._analyzer.getNfsV40Stat().accessOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "close", json_object_new_int64(_service._analyzer.getNfsV40Stat().closeOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "commit", json_object_new_int64(_service._analyzer.getNfsV40Stat().commitOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "create", json_object_new_int64(_service._analyzer.getNfsV40Stat().createOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "delegpurge", json_object_new_int64(_service._analyzer.getNfsV40Stat().delegpurgeOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "delegreturn", json_object_new_int64(_service._analyzer.getNfsV40Stat().delegreturnOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "getattr", json_object_new_int64(_service._analyzer.getNfsV40Stat().getattrOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "getfh", json_object_new_int64(_service._analyzer.getNfsV40Stat().getfhOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "link", json_object_new_int64(_service._analyzer.getNfsV40Stat().linkOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "lock", json_object_new_int64(_service._analyzer.getNfsV40Stat().lockOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "lockt", json_object_new_int64(_service._analyzer.getNfsV40Stat().locktOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "locku", json_object_new_int64(_service._analyzer.getNfsV40Stat().lockuOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "lookup", json_object_new_int64(_service._analyzer.getNfsV40Stat().lookupOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "lookupp", json_object_new_int64(_service._analyzer.getNfsV40Stat().lookuppOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "nverify", json_object_new_int64(_service._analyzer.getNfsV40Stat().nverifyOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "open", json_object_new_int64(_service._analyzer.getNfsV40Stat().openOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "openattr", json_object_new_int64(_service._analyzer.getNfsV40Stat().openattrOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "open_confirm", json_object_new_int64(_service._analyzer.getNfsV40Stat().open_confirmOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "open_downgrade", json_object_new_int64(_service._analyzer.getNfsV40Stat().open_downgradeOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "putfh", json_object_new_int64(_service._analyzer.getNfsV40Stat().putfhOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "putpubfh", json_object_new_int64(_service._analyzer.getNfsV40Stat().putpubfhOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "putrootfh", json_object_new_int64(_service._analyzer.getNfsV40Stat().putrootfhOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "read", json_object_new_int64(_service._analyzer.getNfsV40Stat().readOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "readdir", json_object_new_int64(_service._analyzer.getNfsV40Stat().readdirOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "readlink", json_object_new_int64(_service._analyzer.getNfsV40Stat().readlinkOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "remove", json_object_new_int64(_service._analyzer.getNfsV40Stat().removeOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "rename", json_object_new_int64(_service._analyzer.getNfsV40Stat().renameOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "renew", json_object_new_int64(_service._analyzer.getNfsV40Stat().renewOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "restorefh", json_object_new_int64(_service._analyzer.getNfsV40Stat().restorefhOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "savefh", json_object_new_int64(_service._analyzer.getNfsV40Stat().savefhOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "secinfo", json_object_new_int64(_service._analyzer.getNfsV40Stat().secinfoOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "setattr", json_object_new_int64(_service._analyzer.getNfsV40Stat().setattrOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "setclientid", json_object_new_int64(_service._analyzer.getNfsV40Stat().setclientidOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "setclientid_confirm", json_object_new_int64(_service._analyzer.getNfsV40Stat().setclientid_confirmOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "verify", json_object_new_int64(_service._analyzer.getNfsV40Stat().verifyOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "write", json_object_new_int64(_service._analyzer.getNfsV40Stat().writeOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "release_lockowner", json_object_new_int64(_service._analyzer.getNfsV40Stat().release_lockownerOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "get_dir_delegation", json_object_new_int64(_service._analyzer.getNfsV40Stat().get_dir_delegationOpsAmount.load()));
    json_object_object_add(nfsV40Stat, "illegal", json_object_new_int64(_service._analyzer.getNfsV40Stat().illegalOpsAmount.load()));
    json_object_object_add(root, "nfs_v40", nfsV40Stat);
    struct json_object* nfsV41Stat = json_object_new_object();
    // NFS4.1 procedures:
    json_object_object_add(nfsV41Stat, "null", json_object_new_int64(_service._analyzer.getNfsV41Stat().nullProcsAmount.load()));
    json_object_object_add(nfsV41Stat, "compound", json_object_new_int64(_service._analyzer.getNfsV41Stat().compoundProcsAmount.load()));
    // NFS4.1 operations:
    json_object_object_add(nfsV41Stat, "access", json_object_new_int64(_service._analyzer.getNfsV41Stat().accessOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "close", json_object_new_int64(_service._analyzer.getNfsV41Stat().closeOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "commit", json_object_new_int64(_service._analyzer.getNfsV41Stat().commitOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "create", json_object_new_int64(_service._analyzer.getNfsV41Stat().createOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "delegpurge", json_object_new_int64(_service._analyzer.getNfsV41Stat().delegpurgeOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "delegreturn", json_object_new_int64(_service._analyzer.getNfsV41Stat().delegreturnOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "getattr", json_object_new_int64(_service._analyzer.getNfsV41Stat().getattrOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "getfh", json_object_new_int64(_service._analyzer.getNfsV41Stat().getfhOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "link", json_object_new_int64(_service._analyzer.getNfsV41Stat().linkOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "lock", json_object_new_int64(_service._analyzer.getNfsV41Stat().lockOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "lockt", json_object_new_int64(_service._analyzer.getNfsV41Stat().locktOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "locku", json_object_new_int64(_service._analyzer.getNfsV41Stat().lockuOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "lookup", json_object_new_int64(_service._analyzer.getNfsV41Stat().lookupOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "lookupp", json_object_new_int64(_service._analyzer.getNfsV41Stat().lookuppOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "nverify", json_object_new_int64(_service._analyzer.getNfsV41Stat().nverifyOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "open", json_object_new_int64(_service._analyzer.getNfsV41Stat().openOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "openattr", json_object_new_int64(_service._analyzer.getNfsV41Stat().openattrOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "open_confirm", json_object_new_int64(_service._analyzer.getNfsV41Stat().open_confirmOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "open_downgrade", json_object_new_int64(_service._analyzer.getNfsV41Stat().open_downgradeOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "putfh", json_object_new_int64(_service._analyzer.getNfsV41Stat().putfhOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "putpubfh", json_object_new_int64(_service._analyzer.getNfsV41Stat().putpubfhOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "putrootfh", json_object_new_int64(_service._analyzer.getNfsV41Stat().putrootfhOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "read", json_object_new_int64(_service._analyzer.getNfsV41Stat().readOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "readdir", json_object_new_int64(_service._analyzer.getNfsV41Stat().readdirOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "readlink", json_object_new_int64(_service._analyzer.getNfsV41Stat().readlinkOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "remove", json_object_new_int64(_service._analyzer.getNfsV41Stat().removeOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "rename", json_object_new_int64(_service._analyzer.getNfsV41Stat().renameOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "renew", json_object_new_int64(_service._analyzer.getNfsV41Stat().renewOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "restorefh", json_object_new_int64(_service._analyzer.getNfsV41Stat().restorefhOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "savefh", json_object_new_int64(_service._analyzer.getNfsV41Stat().savefhOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "secinfo", json_object_new_int64(_service._analyzer.getNfsV41Stat().secinfoOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "setattr", json_object_new_int64(_service._analyzer.getNfsV41Stat().setattrOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "setclientid", json_object_new_int64(_service._analyzer.getNfsV41Stat().setclientidOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "setclientid_confirm", json_object_new_int64(_service._analyzer.getNfsV41Stat().setclientid_confirmOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "verify", json_object_new_int64(_service._analyzer.getNfsV41Stat().verifyOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "write", json_object_new_int64(_service._analyzer.getNfsV41Stat().writeOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "release_lockowner", json_object_new_int64(_service._analyzer.getNfsV41Stat().release_lockownerOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "backchannel_ctl", json_object_new_int64(_service._analyzer.getNfsV41Stat().backchannel_ctlOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "bind_conn_to_session", json_object_new_int64(_service._analyzer.getNfsV41Stat().bind_conn_to_sessionOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "exchange_id", json_object_new_int64(_service._analyzer.getNfsV41Stat().exchange_idOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "create_session", json_object_new_int64(_service._analyzer.getNfsV41Stat().create_sessionOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "destroy_session", json_object_new_int64(_service._analyzer.getNfsV41Stat().destroy_sessionOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "free_stateid", json_object_new_int64(_service._analyzer.getNfsV41Stat().free_stateidOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "get_dir_delegation", json_object_new_int64(_service._analyzer.getNfsV41Stat().get_dir_delegationOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "getdeviceinfo", json_object_new_int64(_service._analyzer.getNfsV41Stat().getdeviceinfoOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "getdevicelist", json_object_new_int64(_service._analyzer.getNfsV41Stat().getdevicelistOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "layoutcommit", json_object_new_int64(_service._analyzer.getNfsV41Stat().layoutcommitOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "layoutget", json_object_new_int64(_service._analyzer.getNfsV41Stat().layoutgetOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "layoutreturn", json_object_new_int64(_service._analyzer.getNfsV41Stat().layoutreturnOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "secinfo_no_name", json_object_new_int64(_service._analyzer.getNfsV41Stat().secinfo_no_nameOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "sequence", json_object_new_int64(_service._analyzer.getNfsV41Stat().sequenceOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "set_ssv", json_object_new_int64(_service._analyzer.getNfsV41Stat().set_ssvOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "test_stateid", json_object_new_int64(_service._analyzer.getNfsV41Stat().test_stateidOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "want_delegation", json_object_new_int64(_service._analyzer.getNfsV41Stat().want_delegationOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "destroy_clientid", json_object_new_int64(_service._analyzer.getNfsV41Stat().destroy_clientidOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "reclaim_complete", json_object_new_int64(_service._analyzer.getNfsV41Stat().reclaim_completeOpsAmount.load()));
    json_object_object_add(nfsV41Stat, "illegal", json_object_new_int64(_service._analyzer.getNfsV41Stat().illegalOpsAmount.load()));
    json_object_object_add(root, "nfs_v41", nfsV41Stat);
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
            throw std::system_error{errno, std::system_category(), "Error awaiting for sending data availability on socket"};
        }
        else if (descriptorsCount == 0)
        {
            // Timeout expired
            continue;
        }
        ssize_t bytesSent = send(socket(), json.data() + totalBytesSent, json.length() - totalBytesSent, MSG_NOSIGNAL);
        if (bytesSent < 0)
        {
            std::system_error e{errno, std::system_category(), "Sending data to client error"};
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
