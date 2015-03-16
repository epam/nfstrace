//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Sourcefor CIFSv1 protocol.
// Copyright (c) 2015 EPAM Systems. All Rights Reserved.
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
#include <api/plugin_api.h> // include plugin development definitions
#include "cifsv1_protocol.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
CIFSv1Protocol::CIFSv1Protocol()
: AbstractProtocol {"CIFS v1", static_cast<std::size_t>(SMBv1::SMBv1Commands::CMD_COUNT)}
{
}

CIFSv1Protocol::~CIFSv1Protocol()
{
}

const char* CIFSv1Protocol::printProcedure(std::size_t i)
{
    if ( i >= static_cast<std::size_t>(SMBv1::SMBv1Commands::CMD_COUNT)) { return nullptr; }
    return print_cifs1_procedures(static_cast<SMBv1::SMBv1Commands>(i));
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
