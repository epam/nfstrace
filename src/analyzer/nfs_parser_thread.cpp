//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of the NFS Data.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <memory>

#include "../auxiliary/exception.h"
#include "../auxiliary/logger.h"
#include "../filter/rpc/rpc_header.h"
#include "nfs3/nfs_operation.h"
#include "nfs_parser_thread.h"
//------------------------------------------------------------------------------
using namespace NST::analyzer::NFS3;
using namespace NST::analyzer::XDR;
using namespace NST::filter::rpc;
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

            std::auto_ptr<RPCOperation> operation(parse_data(data));

            if(operation.get())
            {
                //analyzers.call(*operation);
            }
        }
        while(list);
    }
    else pthread_yield();
}

RPCOperation* create_nfs_operation( FilteredDataQueue::Ptr& call,
                                    FilteredDataQueue::Ptr& reply,
                                    RPCSession* session)
{
    const CallHeader* c = reinterpret_cast<const CallHeader*>(call->data);
    const uint32_t proc = c->proc();
    try
    {
        switch(proc)
        {
            /*
        case Proc::NFS_NULL:    return new NFSPROC3_NULL       (call, reply, session);
        case Proc::GETATTR:     return new NFSPROC3_GETATTR    (call, reply, session);
        case Proc::SETATTR:     return new NFSPROC3_SETATTR    (call, reply, session);
        case Proc::LOOKUP:      return new NFSPROC3_LOOKUP     (call, reply, session);
        case Proc::ACCESS:      return new NFSPROC3_ACCESS     (call, reply, session);
        case Proc::READLINK:    return new NFSPROC3_READLINK   (call, reply, session);
        case Proc::READ:        return new NFSPROC3_READ       (call, reply, session);
        case Proc::WRITE:       return new NFSPROC3_WRITE      (call, reply, session);
        case Proc::CREATE:      return new NFSPROC3_CREATE     (call, reply, session);
        case Proc::MKDIR:       return new NFSPROC3_MKDIR      (call, reply, session);
        case Proc::SYMLINK:     return new NFSPROC3_SYMLINK    (call, reply, session);
        case Proc::MKNOD:       return new NFSPROC3_MKNOD      (call, reply, session);
        case Proc::REMOVE:      return new NFSPROC3_REMOVE     (call, reply, session);
        case Proc::RMDIR:       return new NFSPROC3_RMDIR      (call, reply, session);
        case Proc::RENAME:      return new NFSPROC3_RENAME     (call, reply, session);
        case Proc::LINK:        return new NFSPROC3_LINK       (call, reply, session);
        case Proc::READDIR:     return new NFSPROC3_READDIR    (call, reply, session);
        case Proc::READDIRPLUS: return new NFSPROC3_READDIRPLUS(call, reply, session);
        case Proc::FSSTAT:      return new NFSPROC3_FSSTAT     (call, reply, session);
        case Proc::FSINFO:      return new NFSPROC3_FSINFO     (call, reply, session);
        case Proc::PATHCONF:    return new NFSPROC3_PATHCONF   (call, reply, session);
        case Proc::COMMIT:      return new NFSPROC3_COMMIT     (call, reply, session);
        case Proc::num:;
            */
        }
    }
    catch(XDRError& exception)
    {
        LOG("The data of NFS operation %s %s(%u) is too short for parsing", session->str().c_str(), Proc::Titles[proc], proc);
    }
    return NULL;
}

RPCOperation* NFSParserThread::parse_data(FilteredDataQueue::Ptr& ptr)
{
    if(ptr->dlen < sizeof(MessageHeader)) return NULL;
    const MessageHeader* msg = (MessageHeader*)ptr->data;
    switch(msg->type())
    {
    case SUNRPC_CALL:
        {
            if(ptr->dlen < sizeof(CallHeader)) return NULL;

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
            if(ptr->dlen < sizeof(ReplyHeader)) return NULL;
            const ReplyHeader* reply = static_cast<const ReplyHeader*>(msg);

            RPCSession* session = sessions.get_session(ptr->session, RPCSessions::REVERSE);

            if(session == NULL) return NULL;

            FilteredDataQueue::Ptr call_data = session->get_nfs_call_data(reply->xid());
            if(call_data)
            {
                if(reply->stat() == SUNRPC_MSG_ACCEPTED)
                {
                    // TODO: check msg-length before cast
                    const AcceptedReplyHeader* areply = static_cast<const AcceptedReplyHeader*>(msg);
                    if(areply->astat() == SUNRPC_SUCCESS)
                    {
                        return create_nfs_operation(call_data, ptr, session);
                    }
                }
            }
        }
    }
    return NULL;
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
