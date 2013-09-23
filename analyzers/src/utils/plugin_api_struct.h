//------------------------------------------------------------------------------
// Author: Dzianis Huznou 
// Description: Entry for all operations under plugin_api.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_API_STRUCT_H
#define PLUGIN_API_STRUCT_H
//------------------------------------------------------------------------------
#include <iostream>

#include <api/plugin_api.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

std::ostream& operator<<(std::ostream& out, const Session& session);
std::ostream& operator<<(std::ostream& out, const ProcEnum::NFSProcedure proc);

//------------------------------------------------------------------------------
#endif //PLUGIN_API_STRUCT_H
//------------------------------------------------------------------------------

