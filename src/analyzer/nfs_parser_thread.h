//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of the NFS Data.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PARSER_THREAD_H
#define NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
#include "../controller/running_status.h"
#include "../filter/rpc/rpc_struct.h"
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

        switch(ops)
        {
        case Proc::NFS_NULL:
            {
                NullArgs args(reader);
                analyzers.call_null(data.session, args);
            }
            break;
        case Proc::NFS_GETATTR:
            {
                GetAttrArgs args(reader);
                analyzers.call_getattr(data.session, args);
            }
            break;
        case Proc::NFS_SETATTR:
            analyzers.call_setattr(data.session);
            break;
        case Proc::NFS_LOOKUP:
            {
                LookUpArgs args(reader);
                analyzers.call_lookup(data.session, args);
            }
            break;
        case Proc::NFS_ACCESS:
            {
                AccessArgs args(reader);
                analyzers.call_access(data.session, args);
            }
            break;
        case Proc::NFS_READLINK:
            {
                ReadLinkArgs args(reader);
                analyzers.call_readlink(data.session, args);
            }
            break;
        case Proc::NFS_READ:
            {
                ReadArgs ra(reader);
                analyzers.call_read(data.session, ra);
            }
            break;
        case Proc::NFS_WRITE:
            {
                WriteArgs wa(reader);
                analyzers.call_write(data.session, wa);
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
                RemoveArgs args(reader);
                analyzers.call_remove(data.session, args);
            }
            break;
        case Proc::NFS_RMDIR:
            {
                RmDirArgs args(reader);
                analyzers.call_rmdir(data.session, args);
            }
            break;
        case Proc::NFS_RENAME:
            {
                RenameArgs args(reader);
                analyzers.call_rename(data.session, args);
            }
            break;
        case Proc::NFS_LINK:
            {
                LinkArgs args(reader);
                analyzers.call_link(data.session, args);
            }
            break;
        case Proc::NFS_READDIR:
            {
                ReadDirArgs args(reader);
                analyzers.call_readdir(data.session, args);
            }
            break;
        case Proc::NFS_READDIRPLUS:
            {
                ReadDirPlusArgs args(reader);
                analyzers.call_readdirplus(data.session, args);
            }
            break;
        case Proc::NFS_FSSTAT:
            {
                FSStatArgs args(reader);
                analyzers.call_fsstat(data.session, args);
            }
            break;
        case Proc::NFS_FSINFO:
            {
                FSInfoArgs args(reader);
                analyzers.call_fsinfo(data.session, args);
            }
            break;
        case Proc::NFS_PATHCONF:
            {
                PathConfArgs args(reader);
                analyzers.call_pathconf(data.session, args);
            }
            break;
        case Proc::NFS_COMMIT:
            {
                CommitArgs args(reader);
                analyzers.call_commit(data.session, args);
            }
            break;
        default:
            break;
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
