//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base analyzer, which implement restoring rpc/nfs structures from plain rpc header.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BASE_ANALYZER_STRUCT_H
#define BASE_ANALYZER_STRUCT_H
//------------------------------------------------------------------------------
#include "../nfs3/nfs_structs.h"        // api/nfs3_types.h
#include "../rpc/rpc_procedure_struct.h"// api/rpc_procedure_type.h
//------------------------------------------------------------------------------
using namespace NST::analyzer::NFS3;

using NST::analyzer::RPC::RPCProcedure;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

#include "../../api/base_analyzer_type.h"

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_ANALYZER_STRUCT_H
//------------------------------------------------------------------------------
