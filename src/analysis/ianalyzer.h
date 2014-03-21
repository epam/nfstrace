//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base analysis, which implement restoring rpc/nfs structures from plain rpc header.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef IANALYZER_H
#define IANALYZER_H
//------------------------------------------------------------------------------
#include "api/plugin_api.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

// type of pluggable analysis module
using IAnalyzer = NST::API::IAnalyzer;

// functions exported from pluggable analysis module
using plugin_usage_func   = decltype(&usage);   // return description of expected opts for plugin_create_func()
using plugin_create_func  = decltype(&create);  // create and return an instance of module
using plugin_destroy_func = decltype(&destroy); // destroy an instance of module

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//IANALYZER_H
//------------------------------------------------------------------------------
