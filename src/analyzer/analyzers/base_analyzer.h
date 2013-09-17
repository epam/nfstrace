//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base analyzer, which implement restoring rpc/nfs structures from plain rpc header.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BASE_ANALYZER_H
#define BASE_ANALYZER_H
//------------------------------------------------------------------------------
#include "../../auxiliary/session.h"
using NST::auxiliary::Session;  // F*****G namespaces!

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

typedef const char* (*plugin_usage_func)   (); // return description of expected opts for plugin_create_func()
typedef void*       (*plugin_create_func)  (const char* opts); // create and return an instance of analyzer
typedef void        (*plugin_destroy_func) (void*   instance); // destroy an instance of analyzer

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_ANALYZER_H
//------------------------------------------------------------------------------
