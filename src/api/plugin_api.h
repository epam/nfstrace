//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Unique Plugin-API interface header.
// Aggregated all definitions for plugins' development
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_API_H
#define PLUGIN_API_H
//------------------------------------------------------------------------------
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <sys/time.h>

#include "api/xdr_types.h"
#include "api/rpc_types.h"
#include "api/rpc_procedure_type.h"
#include "api/nfs3_types.h"
#include "api/session_type.h"
#include "api/ianalyzer_type.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

// THESE CALLS MUST BE IMPLEMENTED BY Pluggable Analysis Module
const char* usage  ();    // return description of expected opts for create(opts)
IAnalyzer*  create (const char*    opts); // create and return an instance of an Analyzer
void        destroy(IAnalyzer* instance); // destroy created instance of an Analyzer

}
//------------------------------------------------------------------------------
#endif //PLUGIN_API_H
//------------------------------------------------------------------------------
