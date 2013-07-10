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
    NFSOperation(std::auto_ptr<RPCCall>& c) : call(c.release()), reply(NULL) 
    {
    }
    ~NFSOperation()
    {
        delete call;
        delete reply;
    }

    inline const RPCCall* get_call() const
    {
        return call;
    }
    inline void set_reply(std::auto_ptr<RPCReply>& r)
    {
        reply = r.release();
        assert(reply);
    }
    inline const RPCReply* get_reply() const
    {
        return reply;
    }
    inline timeval time_diff() const
    {
        timeval diff = {0, 0};
        if(reply) {
            diff.tv_sec = call->get_time().tv_sec - reply->get_time().tv_sec;
            diff.tv_usec = call->get_time().tv_usec - reply->get_time().tv_usec;
        }
        return diff; 
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
