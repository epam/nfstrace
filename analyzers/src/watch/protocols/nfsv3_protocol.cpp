//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source for NFSv3 protocol.
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
#include "nfsv3_protocol.h"
//------------------------------------------------------------------------------
NFSv3Protocol::NFSv3Protocol()
: AbstractProtocol {"NFS v3", ProcEnumNFS3::count}
{
}

NFSv3Protocol::~NFSv3Protocol()
{
}

const char* NFSv3Protocol::printProcedure(std::size_t i)
{
    if ( i > ProcEnumNFS3::count) { return nullptr; }
    return  print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(i));
}
//------------------------------------------------------------------------------
