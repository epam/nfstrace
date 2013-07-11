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

#include "../../auxiliary/filtered_data.h"
#include "../rpc/rpc_struct.h"
#include "nfs_procedures.h"
//------------------------------------------------------------------------------
using namespace NST::filter::RPC;

using NST::auxiliary::FilteredData;
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
    typedef FilteredData::Session Session;
public:
    NFSOperation(const RPCCall* c, const RPCReply* r, const Session* s) : call(c), reply(r), session(s)
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
    inline const RPCReply* get_reply() const
    {
        return reply;
    }
    inline const Session* get_session() const
    {
        return session;
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

    const RPCCall* call;
    const RPCReply* reply;
    const Session* session;
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_OPERATION_H
//------------------------------------------------------------------------------
