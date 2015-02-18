//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Represents CIFS v1 commands
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

#include "cifsv1commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
const char* NST::breakdown::SMBv1Commands::command_name(int cmd_code)
{
    return print_cifs1_procedures(static_cast<NST::API::SMBv1::SMBv1Commands>(cmd_code));
}

size_t SMBv1Commands::commands_count()
{
    return static_cast<size_t>(NST::API::SMBv1::SMBv1Commands::CMD_COUNT);
}

const char* NST::breakdown::SMBv1Commands::command_description(int cmd_code)
{
    return print_cifs1_procedures(static_cast<NST::API::SMBv1::SMBv1Commands>(cmd_code));
}

const char* NST::breakdown::SMBv1Commands::protocol_name()
{
    return "CIFS v1";
}
//------------------------------------------------------------------------------
