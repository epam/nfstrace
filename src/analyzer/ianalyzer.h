//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base analyzer, which implement restoring rpc/nfs structures from plain rpc header.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef IANALYZER_H
#define IANALYZER_H
//------------------------------------------------------------------------------
#include "../auxiliary/session.h"
using NST::auxiliary::Session;

#include "nfs3/nfs_structs.h"        // api/nfs3_types.h
#include "rpc/rpc_procedure_struct.h"// api/rpc_procedure_type.h
//------------------------------------------------------------------------------
using namespace NST::analyzer::NFS3;

using NST::analyzer::RPC::RPCProcedure;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

#include "../api/ianalyzer_type.h"

typedef const char* (*plugin_usage_func)   (); // return description of expected opts for plugin_create_func()
typedef IAnalyzer*  (*plugin_create_func)  (const char*    opts); // create and return an instance of analyzer
typedef void        (*plugin_destroy_func) (IAnalyzer* instance); // destroy an instance of analyzer

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//IANALYZER_H
//------------------------------------------------------------------------------
