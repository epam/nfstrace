//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of filtrated NFSv3 Procedures.
// Copyright (c) 2013 EPAM Systems
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
#include "analysis/nfs_parser_thread.h"
#include "protocols/nfs3/nfs_procedure.h"
#include "protocols/nfs3/nfs_utils.h"
#include "protocols/rpc/rpc_header.h"
#include "protocols/xdr/xdr_decoder.h"
#include "utils/log.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::NFS3;
using namespace NST::protocols::rpc;
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

NFSParserThread::NFSParserThread(FilteredDataQueue& q, Analyzers& a, RunningStatus& s)
: status   (s)
, analyzers(a)
, queue    (q)
, running  {ATOMIC_FLAG_INIT} // false
{
}
NFSParserThread::~NFSParserThread()
{
    if (parsing.joinable()) stop();
}

void NFSParserThread::start()
{
    if(running.test_and_set()) return;
    parsing = std::thread(&NFSParserThread::thread, this);
}

void NFSParserThread::stop()
{
    running.clear();
    parsing.join();
}

inline void NFSParserThread::thread()
{
    try
    {
        while(running.test_and_set())
        {
            // process all available items from queue
            process_queue();

            // then sleep this thread
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        process_queue(); // flush data from queue
    }
    catch(...)
    {
        status.push_current_exception();
    }
}

inline void NFSParserThread::process_queue()
{
    while(true)
    {
        // take all items from the queue
        FilteredDataQueue::List list{queue};
        if(!list)
        {
            return; // list from queue is empty, break infinity loop
        }

        do
        {
            parse_data(list.get_current());
        }
        while(list);
    }
}

void NFSParserThread::parse_data(FilteredDataQueue::Ptr&& ptr)
{
    // TODO: refactor and generalize this code
    if(ptr->dlen < sizeof(MessageHeader)) return;
    auto msg = reinterpret_cast<const MessageHeader*>(ptr->data);
    switch(msg->type())
    {
    case MsgType::CALL:
    {
        if(ptr->dlen < sizeof(CallHeader)) return;
        auto call = static_cast<const CallHeader*>(msg);

        if(RPCValidator::check(call) && Validator::check(call))
        {
            RPCSession* session = sessions.get_session(ptr->session, ptr->direction, MsgType::CALL);
            if(session)
            {
                session->save_nfs_call_data(call->xid(), std::move(ptr));
            }
        }
    }
    break;
    case MsgType::REPLY:
    {
        if(ptr->dlen < sizeof(ReplyHeader)) return;
        auto reply = static_cast<const ReplyHeader*>(msg);

        if(!RPCValidator::check(reply)) return;

        RPCSession* session = sessions.get_session(ptr->session, ptr->direction, MsgType::REPLY);
        if(session)
        {
            FilteredDataQueue::Ptr&& call_data = session->get_nfs_call_data(reply->xid());
            if(call_data)
            {
                analyze_nfs_operation(std::move(call_data), std::move(ptr), session);
            }
        }
    }
    }
}

void NFSParserThread::analyze_nfs_operation( FilteredDataQueue::Ptr&& call,
                                             FilteredDataQueue::Ptr&& reply,
                                             RPCSession* session)
{
    auto header = reinterpret_cast<const CallHeader*>(call->data);
    const uint32_t procedure = header->proc();
    try
    {
        XDRDecoder c{std::move(call) };
        XDRDecoder r{std::move(reply)};
        const Session* s = session->get_session();

        switch(procedure)
        {
        case ProcEnum::NFS_NULL:    return analyzers(&IAnalyzer::nfsv3rpcgen::null,       NFSPROC3RPCGEN_NULL       {c, r, s});
        case ProcEnum::GETATTR:     return analyzers(&IAnalyzer::nfsv3rpcgen::getattr3,   NFSPROC3RPCGEN_GETATTR    {c, r, s});
        case ProcEnum::SETATTR:     return analyzers(&IAnalyzer::nfsv3rpcgen::setattr3,   NFSPROC3RPCGEN_SETATTR    {c, r, s});
        case ProcEnum::LOOKUP:      return analyzers(&IAnalyzer::nfsv3rpcgen::lookup3,    NFSPROC3RPCGEN_LOOKUP     {c, r, s});
        case ProcEnum::ACCESS:      return analyzers(&IAnalyzer::nfsv3rpcgen::access3,    NFSPROC3RPCGEN_ACCESS     {c, r, s});
        case ProcEnum::READLINK:    return analyzers(&IAnalyzer::nfsv3rpcgen::readlink3,  NFSPROC3RPCGEN_READLINK   {c, r, s});
        case ProcEnum::READ:        return analyzers(&IAnalyzer::nfsv3rpcgen::read3,      NFSPROC3RPCGEN_READ       {c, r, s});
        case ProcEnum::WRITE:       return analyzers(&IAnalyzer::nfsv3rpcgen::write3,     NFSPROC3RPCGEN_WRITE      {c, r, s});
        case ProcEnum::CREATE:      return analyzers(&IAnalyzer::nfsv3rpcgen::create3,    NFSPROC3RPCGEN_CREATE     {c, r, s});
        case ProcEnum::MKDIR:       return analyzers(&IAnalyzer::nfsv3rpcgen::mkdir3,     NFSPROC3RPCGEN_MKDIR      {c, r, s});
        case ProcEnum::SYMLINK:     return analyzers(&IAnalyzer::nfsv3rpcgen::symlink3,   NFSPROC3RPCGEN_SYMLINK    {c, r, s});
        case ProcEnum::MKNOD:       return analyzers(&IAnalyzer::nfsv3rpcgen::mknod3,     NFSPROC3RPCGEN_MKNOD      {c, r, s});
        case ProcEnum::REMOVE:      return analyzers(&IAnalyzer::nfsv3rpcgen::remove3,    NFSPROC3RPCGEN_REMOVE     {c, r, s});
        case ProcEnum::RMDIR:       return analyzers(&IAnalyzer::nfsv3rpcgen::rmdir3,     NFSPROC3RPCGEN_RMDIR      {c, r, s});
        case ProcEnum::RENAME:      return analyzers(&IAnalyzer::nfsv3rpcgen::rename3,    NFSPROC3RPCGEN_RENAME     {c, r, s});
        case ProcEnum::LINK:        return analyzers(&IAnalyzer::nfsv3rpcgen::link3,      NFSPROC3RPCGEN_LINK       {c, r, s});
        case ProcEnum::READDIR:     return analyzers(&IAnalyzer::nfsv3rpcgen::readdir3,   NFSPROC3RPCGEN_READDIR    {c, r, s});
        case ProcEnum::READDIRPLUS: return analyzers(&IAnalyzer::nfsv3rpcgen::readdirplus3, NFSPROC3RPCGEN_READDIRPLUS{c, r, s});
        case ProcEnum::FSSTAT:      return analyzers(&IAnalyzer::nfsv3rpcgen::fsstat3,    NFSPROC3RPCGEN_FSSTAT     {c, r, s});
        case ProcEnum::FSINFO:      return analyzers(&IAnalyzer::nfsv3rpcgen::fsinfo3,    NFSPROC3RPCGEN_FSINFO     {c, r, s});
        case ProcEnum::PATHCONF:    return analyzers(&IAnalyzer::nfsv3rpcgen::pathconf3,  NFSPROC3RPCGEN_PATHCONF   {c, r, s});
        case ProcEnum::COMMIT:      return analyzers(&IAnalyzer::nfsv3rpcgen::commit3,    NFSPROC3RPCGEN_COMMIT     {c, r, s});
        }

/*
        RPCReader c{std::move(call) };
        RPCReader r{std::move(reply)};
        const Session* s = session->get_session();

        switch(procedure)
        {
        case ProcEnum::NFS_NULL:    return analyzers(&IAnalyzer::nfsv3handmade::null,       NFSPROC3_NULL       {c, r, s});
        case ProcEnum::GETATTR:     return analyzers(&IAnalyzer::nfsv3handmade::getattr3,   NFSPROC3_GETATTR    {c, r, s});
        case ProcEnum::SETATTR:     return analyzers(&IAnalyzer::nfsv3handmade::setattr3,   NFSPROC3_SETATTR    {c, r, s});
        case ProcEnum::LOOKUP:      return analyzers(&IAnalyzer::nfsv3handmade::lookup3,    NFSPROC3_LOOKUP     {c, r, s});
        case ProcEnum::ACCESS:      return analyzers(&IAnalyzer::nfsv3handmade::access3,    NFSPROC3_ACCESS     {c, r, s});
        case ProcEnum::READLINK:    return analyzers(&IAnalyzer::nfsv3handmade::readlink3,  NFSPROC3_READLINK   {c, r, s});
        case ProcEnum::READ:        return analyzers(&IAnalyzer::nfsv3handmade::read3,      NFSPROC3_READ       {c, r, s});
        case ProcEnum::WRITE:       return analyzers(&IAnalyzer::nfsv3handmade::write3,     NFSPROC3_WRITE      {c, r, s});
        case ProcEnum::CREATE:      return analyzers(&IAnalyzer::nfsv3handmade::create3,    NFSPROC3_CREATE     {c, r, s});
        case ProcEnum::MKDIR:       return analyzers(&IAnalyzer::nfsv3handmade::mkdir3,     NFSPROC3_MKDIR      {c, r, s});
        case ProcEnum::SYMLINK:     return analyzers(&IAnalyzer::nfsv3handmade::symlink3,   NFSPROC3_SYMLINK    {c, r, s});
        case ProcEnum::MKNOD:       return analyzers(&IAnalyzer::nfsv3handmade::mknod3,     NFSPROC3_MKNOD      {c, r, s});
        case ProcEnum::REMOVE:      return analyzers(&IAnalyzer::nfsv3handmade::remove3,    NFSPROC3_REMOVE     {c, r, s});
        case ProcEnum::RMDIR:       return analyzers(&IAnalyzer::nfsv3handmade::rmdir3,     NFSPROC3_RMDIR      {c, r, s});
        case ProcEnum::RENAME:      return analyzers(&IAnalyzer::nfsv3handmade::rename3,    NFSPROC3_RENAME     {c, r, s});
        case ProcEnum::LINK:        return analyzers(&IAnalyzer::nfsv3handmade::link3,      NFSPROC3_LINK       {c, r, s});
        case ProcEnum::READDIR:     return analyzers(&IAnalyzer::nfsv3handmade::readdir3,   NFSPROC3_READDIR    {c, r, s});
        case ProcEnum::READDIRPLUS: return analyzers(&IAnalyzer::nfsv3handmade::readdirplus3, NFSPROC3_READDIRPLUS{c, r, s});
        case ProcEnum::FSSTAT:      return analyzers(&IAnalyzer::nfsv3handmade::fsstat3,    NFSPROC3_FSSTAT     {c, r, s});
        case ProcEnum::FSINFO:      return analyzers(&IAnalyzer::nfsv3handmade::fsinfo3,    NFSPROC3_FSINFO     {c, r, s});
        case ProcEnum::PATHCONF:    return analyzers(&IAnalyzer::nfsv3handmade::pathconf3,  NFSPROC3_PATHCONF   {c, r, s});
        case ProcEnum::COMMIT:      return analyzers(&IAnalyzer::nfsv3handmade::commit3,    NFSPROC3_COMMIT     {c, r, s});
        }
*/
    }
    catch(XDRError& exception)
    {
        LOG("The data of NFS operation %s %s(%u) is too short for parsing", session->str().c_str(), NFSProcedureTitles[procedure], procedure);
    }
    catch(XDRDecoderError& exception)
    {
    }
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
