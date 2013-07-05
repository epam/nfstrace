//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base structure for nfs-info.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_OPERATION_H
#define NFS_OPERATION_H
//------------------------------------------------------------------------------
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

    bool set_call(RPCCall* c)
    {
        if(call) return false;
        call = c;
        return true;
    }
    const RPCCall* get_call() const
    {
        return call;
    }
    bool is_call() const
    {
        return (call) ? true : false;
    }
    bool set_reply(RPCReply* c)
    {
        if(reply) return false;
        reply = c;
        return true;
    }
    const RPCReply* get_reply() const
    {
        return reply;
    }
    bool is_reply() const
    {
        return (reply) ? true : false;
    }

    operator int() const // Allow us use NFSOperation inside switch-block
    {
        return procedure;
    }
    void set_procedure(ProcedureType type)
    {
        procedure = type;
    }

private:
    NFSOperation(const NFSOperation&);
    void operator=(const NFSOperation&);

    ProcedureType procedure;
    RPCCall* call;
    RPCReply* reply;
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_OPERATION_H
//------------------------------------------------------------------------------
