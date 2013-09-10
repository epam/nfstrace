//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin-API describe interface expected by nfstrace.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_API_H
#define PLUGIN_API_H
//------------------------------------------------------------------------------
#include "rpc_types.h"
#include "nfs3_types.h"
#include "session_type.h"
#include "base_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

BaseAnalyzer2* create(const char* opts);// create analyzer and return filled NST_API structure 
void destroy(BaseAnalyzer2* context);   // destroy analyzer 

}

//------------------------------------------------------------------------------
#endif //PLUGIN_API_H
//------------------------------------------------------------------------------
