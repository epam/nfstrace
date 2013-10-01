//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of the raw data filtered NFSv3 Procedures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "../auxiliary/exception.h"
#include "../auxiliary/logger.h"
#include "../filter/rpc/rpc_header.h"
#include "nfs3/nfs_procedure.h"
#include "nfs_parser_thread.h"
#include "rpc/rpc_reader.h"
//------------------------------------------------------------------------------
using namespace NST::analyzer::NFS3;
using namespace NST::analyzer::RPC;
using namespace NST::analyzer::XDR;
using namespace NST::filter::rpc;

using NST::analyzer::RPC::RPCReader;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

NFSParserThread::NFSParserThread(FilteredDataQueue& q,
                                 Analyzers&         a,
                                 RunningStatus&     rs)
                                    :   status(rs)
                                    ,   analyzers(a)
                                    ,   queue(q)
                                    ,   exec(false)
{
}
NFSParserThread::~NFSParserThread()
{
}

void* NFSParserThread::run()
{
    // Allow processing data contained in the queue
    exec = true;
    try
    {
        while(exec)
        {
            process_queue();
        }
        process_queue(); // flush data in queue
    }
    catch(std::exception& exception)
    {
        status.push(exception);
    }
    return NULL;
}

void NFSParserThread::stop()
{
    exec = false;   // Deny processing data
    join();
}

inline void NFSParserThread::process_queue()
{
    // Read all data from the received queue
    FilteredDataQueue::List list(queue);
    if(list)
    {
        do
        {
            FilteredDataQueue::Ptr data = list.get_current();
            parse_data(data);
        }
        while(list);
    }
    else Thread::yield();
}

void NFSParserThread::create_nfs_operation( FilteredDataQueue::Ptr& call,
                                            FilteredDataQueue::Ptr& reply,
                                            RPCSession* session)
{
    const CallHeader* header = reinterpret_cast<const CallHeader*>(call->data);
    const uint32_t procedure = header->proc();
    try
    {
        RPCReader c(call);
        RPCReader r(reply);
        const Session* s = session->get_session();

        switch(procedure)
        {
        case Proc::NFS_NULL:    return analyzers(&IAnalyzer::null,       NFSPROC3_NULL       (c, r, s));
        case Proc::GETATTR:     return analyzers(&IAnalyzer::getattr3,   NFSPROC3_GETATTR    (c, r, s));
        case Proc::SETATTR:     return analyzers(&IAnalyzer::setattr3,   NFSPROC3_SETATTR    (c, r, s));
        case Proc::LOOKUP:      return analyzers(&IAnalyzer::lookup3,    NFSPROC3_LOOKUP     (c, r, s));
        case Proc::ACCESS:      return analyzers(&IAnalyzer::access3,    NFSPROC3_ACCESS     (c, r, s));
        case Proc::READLINK:    return analyzers(&IAnalyzer::readlink3,  NFSPROC3_READLINK   (c, r, s));
        case Proc::READ:        return analyzers(&IAnalyzer::read3,      NFSPROC3_READ       (c, r, s));
        case Proc::WRITE:       return analyzers(&IAnalyzer::write3,     NFSPROC3_WRITE      (c, r, s));
        case Proc::CREATE:      return analyzers(&IAnalyzer::create3,    NFSPROC3_CREATE     (c, r, s));
        case Proc::MKDIR:       return analyzers(&IAnalyzer::mkdir3,     NFSPROC3_MKDIR      (c, r, s));
        case Proc::SYMLINK:     return analyzers(&IAnalyzer::symlink3,   NFSPROC3_SYMLINK    (c, r, s));
        case Proc::MKNOD:       return analyzers(&IAnalyzer::mknod3,     NFSPROC3_MKNOD      (c, r, s));
        case Proc::REMOVE:      return analyzers(&IAnalyzer::remove3,    NFSPROC3_REMOVE     (c, r, s));
        case Proc::RMDIR:       return analyzers(&IAnalyzer::rmdir3,     NFSPROC3_RMDIR      (c, r, s));
        case Proc::RENAME:      return analyzers(&IAnalyzer::rename3,    NFSPROC3_RENAME     (c, r, s));
        case Proc::LINK:        return analyzers(&IAnalyzer::link3,      NFSPROC3_LINK       (c, r, s));
        case Proc::READDIR:     return analyzers(&IAnalyzer::readdir3,   NFSPROC3_READDIR    (c, r, s));
        case Proc::READDIRPLUS: return analyzers(&IAnalyzer::readdirplus3, NFSPROC3_READDIRPLUS(c, r, s));
        case Proc::FSSTAT:      return analyzers(&IAnalyzer::fsstat3,    NFSPROC3_FSSTAT     (c, r, s));
        case Proc::FSINFO:      return analyzers(&IAnalyzer::fsinfo3,    NFSPROC3_FSINFO     (c, r, s));
        case Proc::PATHCONF:    return analyzers(&IAnalyzer::pathconf3,  NFSPROC3_PATHCONF   (c, r, s));
        case Proc::COMMIT:      return analyzers(&IAnalyzer::commit3,    NFSPROC3_COMMIT     (c, r, s));
        case Proc::num:;
        }
    }
    catch(XDRError& exception)
    {
        LOG("The data of NFS operation %s %s(%u) is too short for parsing", session->str().c_str(), Proc::Titles[procedure], procedure);
    }
}

void NFSParserThread::parse_data(FilteredDataQueue::Ptr& ptr)
{
    if(ptr->dlen < sizeof(MessageHeader)) return;
    const MessageHeader* msg = (MessageHeader*)ptr->data;
    switch(msg->type())
    {
    case SUNRPC_CALL:
        {
            if(ptr->dlen < sizeof(CallHeader)) return;

            const CallHeader* call = static_cast<const CallHeader*>(msg);
            if(RPCValidator::check(call) && NFSv3Validator::check(call))
            {
                RPCSession* session = sessions.get_session(ptr->session, RPCSessions::DIRECT);
                if(session)
                {
                    session->save_nfs_call_data(call->xid(), ptr);
                }
            }
        }
        break;
    case SUNRPC_REPLY:
        {
            if(ptr->dlen < sizeof(ReplyHeader)) return;
            const ReplyHeader* reply = static_cast<const ReplyHeader*>(msg);

            RPCSession* session = sessions.get_session(ptr->session, RPCSessions::REVERSE);

            if(session == NULL) return;

            FilteredDataQueue::Ptr call_data = session->get_nfs_call_data(reply->xid());
            if(call_data)
            {
                if(reply->stat() == SUNRPC_MSG_ACCEPTED)
                {
                    // TODO: check msg-length before cast
                    const AcceptedReplyHeader* areply = static_cast<const AcceptedReplyHeader*>(msg);
                    if(areply->astat() == SUNRPC_SUCCESS)
                    {
                        create_nfs_operation(call_data, ptr, session);
                    }
                }
            }
        }
    }
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
