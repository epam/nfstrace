//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Presentation info about ISO/OSI layers up to RPC protocol.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_PROCEDURE_TYPE_H
#define RPC_PROCEDURE_TYPE_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

struct RPCProcedure
{
    const struct Session*  session;
    const struct RPCCall*  call;
    const struct RPCReply* reply;
    const struct timeval*  call_time;
    const struct timeval*  reply_time;
};

}
//------------------------------------------------------------------------------
#endif//RPC_PROCEDURE_TYPE_H
//------------------------------------------------------------------------------
