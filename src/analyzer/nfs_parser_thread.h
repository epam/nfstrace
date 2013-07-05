//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of the NFS Data.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PARSER_THREAD_H
#define NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
#include <memory>

#include "../controller/running_status.h"
#include "../filter/rpc/rpc_struct.h"
#include "../filter/nfs/nfs_operation.h"
#include "../filter/nfs/nfs_procedures.h"
#include "../filter/nfs/nfs_struct.h"
#include "../filter/xdr/xdr_reader.h"
#include "../auxiliary/exception.h"
#include "../auxiliary/thread.h"
#include "../auxiliary/queue.h"
#include "analyzers.h"
#include "nfs_data.h"
//------------------------------------------------------------------------------
using namespace NST::filter::NFS3; // enum Ops;
using namespace NST::filter::XDR;
using namespace NST::filter::RPC;

using NST::controller::RunningStatus;
using NST::auxiliary::Exception;
using NST::auxiliary::Thread;
using NST::auxiliary::Queue;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class NFSParserThread : public Thread
{
    typedef Queue<NFSData> NFSQueue;

public:
    NFSParserThread(NFSQueue& nfs_queue, Analyzers& nfs_analyzers, RunningStatus &running_status) : status(running_status), analyzers(nfs_analyzers), queue(nfs_queue), exec(false)
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
            NFSQueue::List list = queue.pop_list();

            // Read all data from the received queue
            while(list)
            {
                const NFSData& data = list.data();
                parse(data);
                list.free_current();
            }
        }
    }

    void parse_rpc_call(Proc::Ops ops, const NFSData& data)
    {
        XDRReader reader((uint8_t*)data.rpc_message, data.rpc_len);
        NFSOperation operation;

        std::auto_ptr<RPCCall> call;

        switch(ops)
        {
        case Proc::NFS_NULL:    call.reset(new NullArgs(reader));        break;
        case Proc::GETATTR:     call.reset(new GetAttrArgs(reader));     break;
        case Proc::SETATTR:     call.reset(new RPCCall(reader));         break;
        case Proc::LOOKUP:      call.reset(new LookUpArgs(reader));      break;
        case Proc::ACCESS:      call.reset(new AccessArgs(reader));      break;
        case Proc::READLINK:    call.reset(new ReadLinkArgs(reader));    break;
        case Proc::READ:        call.reset(new ReadArgs(reader));        break;
        case Proc::WRITE:       call.reset(new WriteArgs(reader));       break;
        case Proc::CREATE:      call.reset(new RPCCall(reader));         break;
        case Proc::MKDIR:       call.reset(new RPCCall(reader));         break;
        case Proc::SYMLINK:     call.reset(new RPCCall(reader));         break;
        case Proc::MKNOD:       call.reset(new RPCCall(reader));         break;
        case Proc::REMOVE:      call.reset(new RemoveArgs(reader));      break;
        case Proc::RMDIR:       call.reset(new RmDirArgs(reader));       break;
        case Proc::RENAME:      call.reset(new RenameArgs(reader));      break;
        case Proc::LINK:        call.reset(new LinkArgs(reader));        break;
        case Proc::READDIR:     call.reset(new ReadDirArgs(reader));     break;
        case Proc::READDIRPLUS: call.reset(new ReadDirPlusArgs(reader)); break;
        case Proc::FSSTAT:      call.reset(new FSStatArgs(reader));      break;
        case Proc::FSINFO:      call.reset(new FSInfoArgs(reader));      break;
        case Proc::PATHCONF:    call.reset(new PathConfArgs(reader));    break;
        case Proc::COMMIT:      call.reset(new CommitArgs(reader));      break;
        default:    return;
        }
        
        if(call.get() != NULL)
        {
            operation.set_call(call);
            analyzers.call(data.session, operation);
        }
    }

    void parse(const NFSData& data)
    {
        if(data.rpc_len < sizeof(MessageHeader)) return;
        const MessageHeader* msg = (MessageHeader*)data.rpc_message;
        switch(msg->type())
        {
        case SUNRPC_CALL:
            {
                if(data.rpc_len < sizeof(CallHeader)) return;
                const CallHeader* call = static_cast<const CallHeader*>(msg);

                uint32_t rpcvers = call->rpcvers();
                uint32_t prog = call->prog();
                uint32_t vers = call->vers();
                uint32_t proc = call->proc();

                if(rpcvers != 2)    return;
                if(prog != 100003)  return;  // portmap NFS v3 TCP 2049
                if(vers != 3)       return;  // NFS v3
                if(proc < 0 || proc > 21) return;

                parse_rpc_call((Proc::Ops)proc, data);
            }
            break;
        case SUNRPC_REPLY:
            {
                if(data.rpc_len < sizeof(ReplyHeader)) return;
                const ReplyHeader* reply = static_cast<const ReplyHeader*>(msg);
                switch(reply->stat())
                {
                    case SUNRPC_MSG_ACCEPTED:
                    {
                        // TODO: check accepted reply
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

private:
    RunningStatus& status;
    Analyzers& analyzers;
    NFSQueue& queue;
    volatile bool exec;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
