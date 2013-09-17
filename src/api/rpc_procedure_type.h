//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Presentation info about ISO/OSI layers up to RPC protocol.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_PROCEDURE_TYPE_H
#define RPC_PROCEDURE_TYPE_H
//------------------------------------------------------------------------------
#include "rpc_types.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

struct RPCProcedure
{
    struct RPCCall  call;
    struct RPCReply reply;
    const struct Session* session;
    const struct timeval* ctimestamp;
    const struct timeval* rtimestamp;
};

}
//------------------------------------------------------------------------------
#endif//RPC_PROCEDURE_TYPE_H
//------------------------------------------------------------------------------
