//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: CIFS v2 structures.
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

const std::string NST::breakdown::commandName(NST::breakdown::SMBv2Commands cmd_code)
{
    static std::map<SMBv2Commands, std::string> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[SMBv2Commands::NEGOTIATE]         = "NEGOTIATE";
        cmdNames[SMBv2Commands::SESSION_SETUP]     = "SESSION SETUP";
        cmdNames[SMBv2Commands::LOGOFF]            = "LOGOFF";
        cmdNames[SMBv2Commands::TREE_CONNECT]      = "TREE CONNECT";
        cmdNames[SMBv2Commands::TREE_DISCONNECT]   = "TREE DISCONNECT";
        cmdNames[SMBv2Commands::CREATE]            = "CREATE";
        cmdNames[SMBv2Commands::CLOSE]             = "CLOSE";
        cmdNames[SMBv2Commands::FLUSH]             = "FLUSH";
        cmdNames[SMBv2Commands::READ]              = "READ";
        cmdNames[SMBv2Commands::WRITE]             = "WRITE";
        cmdNames[SMBv2Commands::LOCK]              = "LOCK";
        cmdNames[SMBv2Commands::IOCTL]             = "IOCTL";
        cmdNames[SMBv2Commands::CANCEL]            = "CANCEL";
        cmdNames[SMBv2Commands::ECHO]              = "ECHO";
        cmdNames[SMBv2Commands::QUERY_DIRECTORY]   = "QUERY DIRECTORY";
        cmdNames[SMBv2Commands::CHANGE_NOTIFY]     = "CHANGE NOTIFY";
        cmdNames[SMBv2Commands::QUERY_INFO]        = "QUERY INFO";
        cmdNames[SMBv2Commands::SET_INFO]          = "SET INFO";
        cmdNames[SMBv2Commands::OPLOCK_BREAK]      = "OPLOCK BREAK";
    }
    return cmdNames[cmd_code];
}

const std::string NST::breakdown::commandDescription(SMBv2Commands cmd_code)
{
    static std::map<SMBv2Commands, std::string> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[SMBv2Commands::NEGOTIATE]         = "SMB v2 NEGOTIATE";
        cmdNames[SMBv2Commands::SESSION_SETUP]     = "SMB v2 SESSION_SETUP";
        cmdNames[SMBv2Commands::LOGOFF]            = "SMB v2 LOGOFF";
        cmdNames[SMBv2Commands::TREE_CONNECT]      = "SMB v2 TREE_CONNECT";
        cmdNames[SMBv2Commands::TREE_DISCONNECT]   = "SMB v2 TREE_DISCONNECT";
        cmdNames[SMBv2Commands::CREATE]            = "SMB v2 CREATE";
        cmdNames[SMBv2Commands::CLOSE]             = "SMB v2 CLOSE";
        cmdNames[SMBv2Commands::FLUSH]             = "SMB v2 FLUSH";
        cmdNames[SMBv2Commands::READ]              = "SMB v2 READ";
        cmdNames[SMBv2Commands::WRITE]             = "SMB v2 WRITE";
        cmdNames[SMBv2Commands::LOCK]              = "SMB v2 LOCK";
        cmdNames[SMBv2Commands::IOCTL]             = "SMB v2 IOCTL";
        cmdNames[SMBv2Commands::CANCEL]            = "SMB v2 CANCEL";
        cmdNames[SMBv2Commands::ECHO]              = "SMB v2 ECHO";
        cmdNames[SMBv2Commands::QUERY_DIRECTORY]   = "SMB v2 QUERY_DIRECTORY";
        cmdNames[SMBv2Commands::CHANGE_NOTIFY]     = "SMB v2 CHANGE_NOTIFY";
        cmdNames[SMBv2Commands::QUERY_INFO]        = "SMB v2 QUERY_INFO";
        cmdNames[SMBv2Commands::SET_INFO]          = "SMB v2 SET_INFO";
        cmdNames[SMBv2Commands::OPLOCK_BREAK]      = "SMB v2 OPLOCK_BREAK";
    }
    return cmdNames[cmd_code];
}
//------------------------------------------------------------------------------
