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
#include "../filter/rpc/rpc_struct.h"
#include "../filter/nfs/nfs_operation.h"
#include "../filter/nfs/nfs_procedures.h"
#include "../filter/nfs/nfs_struct.h"
#include "../filter/xdr/xdr_reader.h"
#include "analyzers.h"
#include "rpc_sessions.h"
//------------------------------------------------------------------------------
using namespace NST::filter::NFS3; // enum Ops;
using namespace NST::filter::XDR;
using namespace NST::filter::RPC;

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
            process();
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
    inline void process()
    {
        while(exec)
        {
            // Read all data from the received queue
            FilteredDataQueue::ElementList list(queue);
            while(list)
            {
                const FilteredData& data = list.data();
                parse_rpc(data);
                //list.free_current();
            }
        }
    }

    void parse_rpc(const FilteredData& rpc)
    {
        if(rpc.dlen < sizeof(MessageHeader)) return;
        const MessageHeader* msg = (MessageHeader*)rpc.data;
        switch(msg->type())
        {
        case SUNRPC_CALL:
            {
                if(rpc.dlen < sizeof(CallHeader)) return;
                const CallHeader* call = static_cast<const CallHeader*>(msg);

                uint32_t rpcvers = call->rpcvers();
                uint32_t prog = call->prog();
                uint32_t vers = call->vers();
                uint32_t proc = call->proc();

                if(rpcvers != 2)    return;
                if(prog != 100003)  return;  // portmap NFS v3 TCP 2049
                if(vers != 3)       return;  // NFS v3
                if(proc < 0 || proc > 21) return;

                std::auto_ptr<RPCCall> c = parse_rpc_call((Proc::Ops)proc, rpc);
                if(c.get() != NULL)
                {
                    RPCSession* session = sessions.get_session(rpc.session, RPCSessions::DIRECT);
                    session->register_call(c, rpc.timestamp);
                }
            }
            break;
        case SUNRPC_REPLY:
            {
                if(rpc.dlen < sizeof(ReplyHeader)) return;
                const ReplyHeader* reply = static_cast<const ReplyHeader*>(msg);
                switch(reply->stat())
                {
                    case SUNRPC_MSG_ACCEPTED:
                    {
                        // TODO: check accepted reply
                        std::auto_ptr<RPCReply> r = parse_rpc_reply(rpc);
                        if(r.get() != NULL)
                        {
                            RPCSession* session = sessions.get_session(rpc.session, RPCSessions::REVERSE);
                            RPCSession::Iterator i = session->confirm_call(r, rpc.timestamp);
                            //assert(i->second);
                            analyzers.call(session->get_session(), *i->second);
                        }
                    }
                    break;
                    case SUNRPC_MSG_DENIED:
                    {
                        // TODO: check rejected reply
                    }
                    break;
                }
            }
            break;
        }
    }

    std::auto_ptr<RPCCall> parse_rpc_call(Proc::Ops ops, const FilteredData& rpc)
    {
        XDRReader reader((uint8_t*)rpc.data, rpc.dlen);
        std::auto_ptr<RPCCall> call;

        switch(ops)
        {
        case Proc::NFS_NULL:    call.reset(new NullArgs       (reader)); break;
        case Proc::GETATTR:     call.reset(new GetAttrArgs    (reader)); break;
        case Proc::SETATTR:     call.reset(new RPCCall        (reader)); break;
        case Proc::LOOKUP:      call.reset(new LookUpArgs     (reader)); break;
        case Proc::ACCESS:      call.reset(new AccessArgs     (reader)); break;
        case Proc::READLINK:    call.reset(new ReadLinkArgs   (reader)); break;
        case Proc::READ:        call.reset(new ReadArgs       (reader)); break;
        case Proc::WRITE:       call.reset(new WriteArgs      (reader)); break;
        case Proc::CREATE:      call.reset(new RPCCall        (reader)); break;
        case Proc::MKDIR:       call.reset(new RPCCall        (reader)); break;
        case Proc::SYMLINK:     call.reset(new RPCCall        (reader)); break;
        case Proc::MKNOD:       call.reset(new RPCCall        (reader)); break;
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

        return call;    
    }
    std::auto_ptr<RPCReply> parse_rpc_reply(const FilteredData& rpc)
    {
        XDRReader reader((uint8_t*)rpc.data, rpc.dlen);
        std::auto_ptr<RPCReply> reply(new RPCReply(reader));
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
