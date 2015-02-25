//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Represents NFS v4.1 commands
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

#include "nfsv41commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
const char* NST::breakdown::NFSv41Commands::command_description(int cmd_code)
{
    return print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(cmd_code));
}

const char* NST::breakdown::NFSv41Commands::command_name(int cmd_code)
{
    return print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(cmd_code));
}

const char* NST::breakdown::NFSv41Commands::protocol_name()
{
    return "NFS v4.1";
}

size_t NST::breakdown::NFSv41Commands::commands_count()
{
    return ProcEnumNFS41::count;
}
