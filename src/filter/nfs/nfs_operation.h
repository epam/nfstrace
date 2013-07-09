//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base structure for nfs-info.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_OPERATION_H
#define NFS_OPERATION_H
//------------------------------------------------------------------------------
#include <cassert>
#include <memory>

#include "../rpc/rpc_struct.h"
#include "nfs_procedures.h"
//------------------------------------------------------------------------------
using namespace NST::filter::RPC;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace NFS3
{

class NFSOperation
{
    typedef Proc::Ops ProcedureType;
public:
    NFSOperation() : call(NULL), reply(NULL)
    {
    }
    ~NFSOperation()
    {
        delete call;
        delete reply;
    }

    inline void set_call(std::auto_ptr<RPCCall>& c, const timeval& time)
    {
        call = c.release();
        assert(call);
        call_time = time;
    }
    inline const RPCCall* get_call() const
    {
        return call;
    }
    inline const timeval& get_call_time() const
    {
        return call_time;
    }
    inline bool is_call() const
    {
        return call != NULL;
    }
    inline void set_reply(std::auto_ptr<RPCReply>& r, const timeval& time)
    {
        reply = r.release();
        assert(reply);
        reply_time = time;
    }
    inline const RPCReply* get_reply() const
    {
        return reply;
    }
    inline const timeval& get_reply_time() const
    {
        return reply_time;
    }
    inline bool is_reply() const
    {
        return reply != NULL;
    }

    inline operator uint32_t() const // Allow us use NFSOperation inside switch-block
    {
        if(!is_call())
            return 0;
        return call->get_proc();
    }

private:
    NFSOperation(const NFSOperation&);
    void operator=(const NFSOperation&);

    RPCCall* call;
    timeval call_time;
    RPCReply* reply;
    timeval reply_time;
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_OPERATION_H
//------------------------------------------------------------------------------
