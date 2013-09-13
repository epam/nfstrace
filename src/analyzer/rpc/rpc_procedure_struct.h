//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Presentation info about ISO/OSI layers up to RPC protocol.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_PROCEDURE_STRUCT_H
#define RPC_PROCEDURE_STRUCT_H
//------------------------------------------------------------------------------
#include <sys/time.h>

#include "../../auxiliary/session.h"
#include "../rpc/rpc_structs.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Session;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace RPC 
{

#include "../../api/rpc_procedure_type.h"

} // namespace RPC 
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_PROCEDURE_STRUCT_H
//------------------------------------------------------------------------------

