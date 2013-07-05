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
        case Proc::NFS_NULL:
            {
                call.reset(new NullArgs(reader));
            }
            break;
        case Proc::NFS_GETATTR:
            {
                std::auto_ptr<GetAttrArgs> args(new GetAttrArgs(reader));
                operation.set_procedure(Proc::NFS_GETATTR);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_SETATTR:
            analyzers.call_setattr(data.session);
            break;
        case Proc::NFS_LOOKUP:
            {
                std::auto_ptr<LookUpArgs> args(new LookUpArgs(reader));
                operation.set_procedure(Proc::NFS_LOOKUP);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_ACCESS:
            {
                std::auto_ptr<AccessArgs> args(new AccessArgs(reader));
                operation.set_procedure(Proc::NFS_ACCESS);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_READLINK:
            {
                std::auto_ptr<ReadLinkArgs> args(new ReadLinkArgs(reader));
                operation.set_procedure(Proc::NFS_READLINK);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_READ:
            {
                std::auto_ptr<ReadArgs> args(new ReadArgs(reader));
                operation.set_procedure(Proc::NFS_READ);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_WRITE:
            {
                std::auto_ptr<WriteArgs> args(new WriteArgs(reader));
                operation.set_procedure(Proc::NFS_WRITE);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_CREATE:
            analyzers.call_create(data.session);
            break;
        case Proc::NFS_MKDIR:
            analyzers.call_mkdir(data.session);
            break;
        case Proc::NFS_SYMLINK:
            analyzers.call_symlink(data.session);
            break;
        case Proc::NFS_MKNOD:
            analyzers.call_mknod(data.session);
            break;
        case Proc::NFS_REMOVE:
            {
                std::auto_ptr<RemoveArgs> args(new RemoveArgs(reader));
                operation.set_procedure(Proc::NFS_GETATTR);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_RMDIR:
            {
                std::auto_ptr<RmDirArgs> args(new RmDirArgs(reader));
                operation.set_procedure(Proc::NFS_RMDIR);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_RENAME:
            {
                std::auto_ptr<RenameArgs> args(new RenameArgs(reader));
                operation.set_procedure(Proc::NFS_RENAME);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_LINK:
            {
                std::auto_ptr<LinkArgs> args(new LinkArgs(reader));
                operation.set_procedure(Proc::NFS_LINK);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_READDIR:
            {
                std::auto_ptr<ReadDirArgs> args(new ReadDirArgs(reader));
                operation.set_procedure(Proc::NFS_READDIR);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_READDIRPLUS:
            {
                std::auto_ptr<ReadDirPlusArgs> args(new ReadDirPlusArgs(reader));
                operation.set_procedure(Proc::NFS_READDIRPLUS);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_FSSTAT:
            {
                std::auto_ptr<FSStatArgs> args(new FSStatArgs(reader));
                operation.set_procedure(Proc::NFS_FSSTAT);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_FSINFO:
            {
                std::auto_ptr<FSInfoArgs> args(new FSInfoArgs(reader));
                operation.set_procedure(Proc::NFS_FSINFO);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_PATHCONF:
            {
                std::auto_ptr<PathConfArgs> args(new PathConfArgs(reader));
                operation.set_procedure(Proc::NFS_PATHCONF);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        case Proc::NFS_COMMIT:
            {
                std::auto_ptr<CommitArgs> args(new CommitArgs(reader));
                operation.set_procedure(Proc::NFS_COMMIT);
                operation.set_call(args.release());
                analyzers.call(data.session, operation);
            }
            break;
        default:
            break;
        }
        
        // TODO: fix all PROC!!!
        if(call.get() != NULL && call->get_proc() == Proc::NFS_NULL)
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
