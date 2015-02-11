//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Represents NFS v3 commands
// Copyright (c) 2015 EPAM Systems
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
#include <api/plugin_api.h>

#include "nfsv3commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
const char* NFSv3Commands::command_description(int cmd_code)
{
    return print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(cmd_code));
}

const char* NFSv3Commands::command_name(int cmd_code)
{
    return print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(cmd_code));
}

size_t NFSv3Commands::commands_count()
{
    return ProcEnumNFS3::count;
}


const char* NST::breakdown::NFSv3Commands::protocol_name()
{
    return "NFS v3";
}
