//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source for NFSv41 protocol.
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

#include "nfsv41_protocol.h"
//------------------------------------------------------------------------------
namespace
{
const int NFSV41_NUMBEROFGROUPS = 2;
const int PROCEDURES_GROUP      = 1;
const int OPERATIONS_GROUP      = 2;
}

NFSv41Protocol::NFSv41Protocol()
    : AbstractProtocol{"NFS v41", ProcEnumNFS41::count}
{
}

NFSv41Protocol::~NFSv41Protocol()
{
}

const char* NFSv41Protocol::printProcedure(std::size_t i)
{
    if(i > ProcEnumNFS41::count)
    {
        return nullptr;
    }
    return print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(i));
}

std::size_t NFSv41Protocol::getGroups()
{
    return NFSV41_NUMBEROFGROUPS;
}

std::size_t NFSv41Protocol::getGroupBegin(std::size_t i)
{
    if(i == PROCEDURES_GROUP)
        return 0;
    else if(i == OPERATIONS_GROUP)
        return ProcEnumNFS4::count_proc;
    else
        return getAmount();
}
//------------------------------------------------------------------------------
