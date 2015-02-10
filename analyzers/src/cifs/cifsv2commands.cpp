//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Represents CIFS v2 commands
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
#include <map>

#include "cifsv2commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------

const char* NST::breakdown::SMBv2Commands::command_name(int cmd_code)
{
    static std::map<Commands, const char*> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[Commands::NEGOTIATE]         = "NEGOTIATE";
        cmdNames[Commands::SESSION_SETUP]     = "SESSION SETUP";
        cmdNames[Commands::LOGOFF]            = "LOGOFF";
        cmdNames[Commands::TREE_CONNECT]      = "TREE CONNECT";
        cmdNames[Commands::TREE_DISCONNECT]   = "TREE DISCONNECT";
        cmdNames[Commands::CREATE]            = "CREATE";
        cmdNames[Commands::CLOSE]             = "CLOSE";
        cmdNames[Commands::FLUSH]             = "FLUSH";
        cmdNames[Commands::READ]              = "READ";
        cmdNames[Commands::WRITE]             = "WRITE";
        cmdNames[Commands::LOCK]              = "LOCK";
        cmdNames[Commands::IOCTL]             = "IOCTL";
        cmdNames[Commands::CANCEL]            = "CANCEL";
        cmdNames[Commands::ECHO]              = "ECHO";
        cmdNames[Commands::QUERY_DIRECTORY]   = "QUERY DIRECTORY";
        cmdNames[Commands::CHANGE_NOTIFY]     = "CHANGE NOTIFY";
        cmdNames[Commands::QUERY_INFO]        = "QUERY INFO";
        cmdNames[Commands::SET_INFO]          = "SET INFO";
        cmdNames[Commands::OPLOCK_BREAK]      = "OPLOCK BREAK";
    }
    return cmdNames[static_cast<Commands>(cmd_code)];
}

size_t SMBv2Commands::commands_count()
{
    return Commands::CMD_COUNT;
}

const char* NST::breakdown::SMBv2Commands::command_description(int cmd_code)
{
    static std::map<Commands, const char*> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[Commands::NEGOTIATE]         = "NEGOTIATE";
        cmdNames[Commands::SESSION_SETUP]     = "SESSION_SETUP";
        cmdNames[Commands::LOGOFF]            = "LOGOFF";
        cmdNames[Commands::TREE_CONNECT]      = "TREE_CONNECT";
        cmdNames[Commands::TREE_DISCONNECT]   = "TREE_DISCONNECT";
        cmdNames[Commands::CREATE]            = "CREATE";
        cmdNames[Commands::CLOSE]             = "CLOSE";
        cmdNames[Commands::FLUSH]             = "FLUSH";
        cmdNames[Commands::READ]              = "READ";
        cmdNames[Commands::WRITE]             = "WRITE";
        cmdNames[Commands::LOCK]              = "LOCK";
        cmdNames[Commands::IOCTL]             = "IOCTL";
        cmdNames[Commands::CANCEL]            = "CANCEL";
        cmdNames[Commands::ECHO]              = "ECHO";
        cmdNames[Commands::QUERY_DIRECTORY]   = "QUERY_DIRECTORY";
        cmdNames[Commands::CHANGE_NOTIFY]     = "CHANGE_NOTIFY";
        cmdNames[Commands::QUERY_INFO]        = "QUERY_INFO";
        cmdNames[Commands::SET_INFO]          = "SET_INFO";
        cmdNames[Commands::OPLOCK_BREAK]      = "OPLOCK_BREAK";
    }
    return cmdNames[static_cast<Commands>(cmd_code)];
}
//------------------------------------------------------------------------------


const char* NST::breakdown::SMBv2Commands::protocol_name()
{
    return "CIFS v2";
}
