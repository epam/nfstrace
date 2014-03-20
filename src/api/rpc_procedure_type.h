//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Presentation info about ISO/OSI layers up to RPC protocol.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_PROCEDURE_TYPE_H
#define RPC_PROCEDURE_TYPE_H
//------------------------------------------------------------------------------
#include <sys/time.h>

#include "api/rpc_types.h"
#include "api/session_type.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

struct RPCProcedure
{
    struct RPCCall  call;
    struct RPCReply reply;
    const struct Session* session;
    const struct timeval* ctimestamp;
    const struct timeval* rtimestamp;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_PROCEDURE_TYPE_H
//------------------------------------------------------------------------------
