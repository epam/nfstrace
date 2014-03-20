//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base analysis, which implement restoring rpc/nfs structures from plain rpc header.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef IANALYZER_H
#define IANALYZER_H
//------------------------------------------------------------------------------
#include "api/ianalyzer_type.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

using namespace NST::API;

typedef const char* (*plugin_usage_func)   (); // return description of expected opts for plugin_create_func()
typedef IAnalyzer*  (*plugin_create_func)  (const char*    opts); // create and return an instance of analysis
typedef void        (*plugin_destroy_func) (IAnalyzer* instance); // destroy an instance of analysis

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//IANALYZER_H
//------------------------------------------------------------------------------
