//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Represents NFS v4 commands
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

#include "nfsv4commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
const std::string NST::breakdown::NFSv4Commands::command_description(int cmd_code)
{
    return print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(cmd_code));
}

const std::string NST::breakdown::NFSv4Commands::command_name(int cmd_code)
{
    return print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(cmd_code));
}

size_t NST::breakdown::NFSv4Commands::commands_count()
{
    return ProcEnumNFS4::count;
}
