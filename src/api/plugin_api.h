//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Unique Plugin-API interface header.
// Aggregated all definitions for plugins' development
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_API_H
#define PLUGIN_API_H
//------------------------------------------------------------------------------
#include <iostream>

#include "fh.h"
#include "ianalyzer_type.h"
#include "nfs3_types.h"
//------------------------------------------------------------------------------
using namespace NST::API;
//------------------------------------------------------------------------------
extern "C"
{
// THESE CALLS MUST BE IMPLEMENTED BY Pluggable Analysis Module
const char* usage  ();    // return description of expected opts for create(opts)
IAnalyzer*  create (const char*    opts); // create and return an instance of an Analyzer
void        destroy(IAnalyzer* instance); // destroy created instance of an Analyzer

// These calls implemented by nfstrace
std::ostream& print_nfs3_procedures(std::ostream& out, const ProcEnum::NFSProcedure proc);
std::ostream& print_session(std::ostream& out, const Session& session);
std::ostream& print_nfs_fh3(std::ostream& out, const FH& fh);
}

inline std::ostream& operator<<(std::ostream& out, const Session& session)
{
    return print_session(out, session);
}

inline std::ostream& operator<<(std::ostream& out, const ProcEnum::NFSProcedure proc)
{
    return print_nfs3_procedures(out, proc);
}
//------------------------------------------------------------------------------
#endif //PLUGIN_API_H
//------------------------------------------------------------------------------
