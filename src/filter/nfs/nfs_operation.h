//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base structure for nfs-info.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_OPERATION_H
#define NFS_OPERATION_H
//------------------------------------------------------------------------------
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

    inline bool set_call(std::auto_ptr<RPCCall>& c)
    {
        call = c.release();
        return call != NULL;
    }

    inline const RPCCall* get_call() const
    {
        return call;
    }
    inline bool is_call() const
    {
        return call != NULL;
    }
    inline bool set_reply(std::auto_ptr<RPCReply>& r)
    {
        reply = r.release();
        return reply != NULL;
    }
    inline const RPCReply* get_reply() const
    {
        return reply;
    }
    inline bool is_reply() const
    {
        return reply != NULL;
    }

    inline operator uint32_t() const // Allow us use NFSOperation inside switch-block
    {
        return call->get_proc();
    }

private:
    NFSOperation(const NFSOperation&);
    void operator=(const NFSOperation&);

    RPCCall* call;
    RPCReply* reply;
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_OPERATION_H
//------------------------------------------------------------------------------
