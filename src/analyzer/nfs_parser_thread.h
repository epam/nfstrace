//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of the NFS Data.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PARSER_THREAD_H
#define NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
#include <memory>

#include "../auxiliary/exception.h"
#include "../auxiliary/thread.h"
#include "../auxiliary/filtered_data.h"
#include "../controller/running_status.h"
#include "../filter/rpc/rpc_header.h"
#include "analyzers.h"
#include "nfs3/nfs_operation.h"
#include "nfs3/nfs_procedures.h"
#include "nfs3/nfs_structs.h"
#include "rpc/rpc_struct.h"
#include "rpc_sessions.h"
#include "xdr/xdr_reader.h"
//------------------------------------------------------------------------------
using namespace NST::analyzer::NFS3; // enum Ops;
using namespace NST::analyzer::XDR;
using namespace NST::filter::rpc;

using NST::auxiliary::FilteredData;
using NST::auxiliary::FilteredDataQueue;
using NST::auxiliary::Exception;
using NST::auxiliary::Thread;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class NFSParserThread : public Thread
{
public:
    NFSParserThread(FilteredDataQueue& nfs_queue,
                    Analyzers& nfs_analyzers,
                    RunningStatus &rs)
                    :   status(rs),
                        analyzers(nfs_analyzers),
                        queue(nfs_queue),
                        exec(false)
    {
    }
    ~NFSParserThread()
    {
    }
    
    virtual void* run()
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

    virtual void stop()
    {
        exec = false;   // Deny processing data
        join();
    }

private:
    inline void process_queue()
    {
        try
        {
            // Read all data from the received queue
            FilteredDataQueue::ElementList list(queue);
            if(list)
            {
                do
                {
                    const FilteredData& data = list.data();
                    std::auto_ptr<NFSOperation> op(create_nfs_operation(data));
                    list.free_current();
                    if(op.get())
                    {
                        analyzers.call(*op);
                    }
                }
                while(list);
            }
            else pthread_yield();
        }
        catch(XDRError& exception)
        {
            status.push(exception);
        }
    }

    NFSOperation* create_nfs_operation(const FilteredData& rpc)
    {
        NFSOperation* op = NULL;
        if(rpc.dlen < sizeof(MessageHeader)) return NULL;
        const MessageHeader* msg = (MessageHeader*)rpc.data;
        switch(msg->type())
        {
        case SUNRPC_CALL:
            {
                if(rpc.dlen < sizeof(CallHeader)) return NULL;
                const CallHeader* call = static_cast<const CallHeader*>(msg);
                if(RPCValidator::check(call) && NFSv3Validator::check(call))
                {
                    std::auto_ptr<RPCCall> c = parse_nfs_call((Proc::Ops)call->proc(), rpc);
                    if(c.get() != NULL)
                    {
                        RPCSession* session = sessions.get_session(rpc.session, RPCSessions::DIRECT);
                        session->insert(c);
                    }
                }
            }
            break;
        case SUNRPC_REPLY:
            {
                if(rpc.dlen < sizeof(ReplyHeader)) return NULL;
                const ReplyHeader* reply = static_cast<const ReplyHeader*>(msg);

                RPCSession* session = sessions.get_session(rpc.session, RPCSessions::REVERSE);
                RPCSession::Iterator i = session->find(reply->xid());
                if(session->is_valid(i))
                {
                    if(reply->stat() == SUNRPC_MSG_ACCEPTED)
                    {
                        // TODO: check msg-length before cast
                        const AcceptedReplyHeader* areply = static_cast<const AcceptedReplyHeader*>(msg);
                        if(areply->astat() == SUNRPC_SUCCESS)
                        {
                            std::auto_ptr<RPCReply> r = parse_rpc_reply((Proc::Ops)i->second->get_proc(), rpc);
                            if(r.get() != NULL)
                            {
                                op = new NFSOperation(i->second, r.release(), session->get_session());
                            }
                        }
                    }
                    session->remove(i);
                }
            }
        }
        return op;
    }

    std::auto_ptr<RPCCall> parse_nfs_call(Proc::Ops ops, const FilteredData& rpc)
    {
        XDRReader reader((uint8_t*)rpc.data, rpc.dlen);
        std::auto_ptr<RPCCall> call;

        switch(ops)
        {
        case Proc::NFS_NULL:    call.reset(new NullArgs       (reader)); break;
        case Proc::GETATTR:     call.reset(new GetAttrArgs    (reader)); break;
        case Proc::SETATTR:     call.reset(new SetAttrArgs    (reader)); break;
        case Proc::LOOKUP:      call.reset(new LookUpArgs     (reader)); break;
        case Proc::ACCESS:      call.reset(new AccessArgs     (reader)); break;
        case Proc::READLINK:    call.reset(new ReadLinkArgs   (reader)); break;
        case Proc::READ:        call.reset(new ReadArgs       (reader)); break;
        case Proc::WRITE:       call.reset(new WriteArgs      (reader)); break;
        case Proc::CREATE:      call.reset(new CreateArgs     (reader)); break;
        case Proc::MKDIR:       call.reset(new MkDirArgs      (reader)); break;
        case Proc::SYMLINK:     call.reset(new SymLinkArgs    (reader)); break;
        case Proc::MKNOD:       call.reset(new MkNodArgs      (reader)); break;
        case Proc::REMOVE:      call.reset(new RemoveArgs     (reader)); break;
        case Proc::RMDIR:       call.reset(new RmDirArgs      (reader)); break;
        case Proc::RENAME:      call.reset(new RenameArgs     (reader)); break;
        case Proc::LINK:        call.reset(new LinkArgs       (reader)); break;
        case Proc::READDIR:     call.reset(new ReadDirArgs    (reader)); break;
        case Proc::READDIRPLUS: call.reset(new ReadDirPlusArgs(reader)); break;
        case Proc::FSSTAT:      call.reset(new FSStatArgs     (reader)); break;
        case Proc::FSINFO:      call.reset(new FSInfoArgs     (reader)); break;
        case Proc::PATHCONF:    call.reset(new PathConfArgs   (reader)); break;
        case Proc::COMMIT:      call.reset(new CommitArgs     (reader)); break;
        default:    break;
        }

        call->set_time(rpc.timestamp);
        return call;
    }
    std::auto_ptr<RPCReply> parse_rpc_reply(Proc::Ops ops, const FilteredData& rpc)
    {
        XDRReader reader((uint8_t*)rpc.data, rpc.dlen);
        std::auto_ptr<RPCReply> reply(new RPCReply(reader));
        reply->set_time(rpc.timestamp);
        return reply;
    }

private:
    RunningStatus& status;
    Analyzers& analyzers;
    FilteredDataQueue& queue;
    RPCSessions sessions;
    volatile bool exec;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
