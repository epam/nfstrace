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
#ifndef CIFSV2_COMMANDS_H
#define CIFSV2_COMMANDS_H
//------------------------------------------------------------------------------
#include "commandrepresenter.h"
//------------------------------------------------------------------------------
struct SMBv2Commands : CIFSRepresenter::CommandRepresenter
{
    /*!
     * \brief The Commands enum commands codes
     */
    enum Commands
    {
        NEGOTIATE,
        SESSION_SETUP,
        LOGOFF,
        TREE_CONNECT,
        TREE_DISCONNECT,
        CREATE,
        CLOSE,
        FLUSH,
        READ,
        WRITE,
        LOCK,
        IOCTL,
        CANCEL,
        ECHO,
        QUERY_DIRECTORY,
        CHANGE_NOTIFY,
        QUERY_INFO,
        SET_INFO,
        OPLOCK_BREAK,
        CMD_COUNT
    };

    const std::string command_description(int cmd_code) override final;

    const std::string command_name(int cmd_code) override final;

    size_t commands_count();
};
//------------------------------------------------------------------------------
#endif // CIFS2_COMMANDS_H
//------------------------------------------------------------------------------
