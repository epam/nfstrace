//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin-API describe interface expected by nfstrace.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_API_H
#define PLUGIN_API_H
//------------------------------------------------------------------------------
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <sys/time.h>

#include "xdr_types.h"
#include "rpc_types.h"
#include "rpc_procedure_type.h"
#include "nfs3_types.h"
#include "session_type.h"
#include "base_analyzer_type.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

BaseAnalyzer* create(const char* opts);// create analyzer 
void destroy(BaseAnalyzer* context);   // destroy analyzer 

}

//------------------------------------------------------------------------------
#endif //PLUGIN_API_H
//------------------------------------------------------------------------------
