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

#include "cifs2_commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------

const std::string NST::breakdown::SMBv2Commands::command_name(int cmd_code)
{
    static std::map<Commands, std::string> cmdNames;
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

const std::string NST::breakdown::SMBv2Commands::command_description(int cmd_code)
{
    static std::map<Commands, std::string> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[Commands::NEGOTIATE]         = "SMB v2 NEGOTIATE";
        cmdNames[Commands::SESSION_SETUP]     = "SMB v2 SESSION_SETUP";
        cmdNames[Commands::LOGOFF]            = "SMB v2 LOGOFF";
        cmdNames[Commands::TREE_CONNECT]      = "SMB v2 TREE_CONNECT";
        cmdNames[Commands::TREE_DISCONNECT]   = "SMB v2 TREE_DISCONNECT";
        cmdNames[Commands::CREATE]            = "SMB v2 CREATE";
        cmdNames[Commands::CLOSE]             = "SMB v2 CLOSE";
        cmdNames[Commands::FLUSH]             = "SMB v2 FLUSH";
        cmdNames[Commands::READ]              = "SMB v2 READ";
        cmdNames[Commands::WRITE]             = "SMB v2 WRITE";
        cmdNames[Commands::LOCK]              = "SMB v2 LOCK";
        cmdNames[Commands::IOCTL]             = "SMB v2 IOCTL";
        cmdNames[Commands::CANCEL]            = "SMB v2 CANCEL";
        cmdNames[Commands::ECHO]              = "SMB v2 ECHO";
        cmdNames[Commands::QUERY_DIRECTORY]   = "SMB v2 QUERY_DIRECTORY";
        cmdNames[Commands::CHANGE_NOTIFY]     = "SMB v2 CHANGE_NOTIFY";
        cmdNames[Commands::QUERY_INFO]        = "SMB v2 QUERY_INFO";
        cmdNames[Commands::SET_INFO]          = "SMB v2 SET_INFO";
        cmdNames[Commands::OPLOCK_BREAK]      = "SMB v2 OPLOCK_BREAK";
    }
    return cmdNames[static_cast<Commands>(cmd_code)];
}
//------------------------------------------------------------------------------
