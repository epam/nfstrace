//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base analysis, which implement restoring rpc/nfs structures from plain rpc header.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef IANALYZER_H
#define IANALYZER_H
//------------------------------------------------------------------------------
#include "api/plugin_api.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

// type of pluggable analysis module
using IAnalyzer = NST::API::IAnalyzer;

// functions exported from pluggable analysis module
using plugin_get_entry_points_func = decltype(&get_entry_points);
using plugin_usage_func            = decltype(&usage);   // return description of expected opts for plugin_create_func()
using plugin_create_func           = decltype(&create);  // create and return an instance of module
using plugin_destroy_func          = decltype(&destroy); // destroy an instance of module
} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//IANALYZER_H
//------------------------------------------------------------------------------
