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
#ifndef CIFS2_COMMANDS_H
#define CIFS2_COMMANDS_H
//------------------------------------------------------------------------------
#include <string>
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
//------------------------------------------------------------------------------
/*! CIFS v2 commands list
 */
enum class SMBv2Commands
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

/*!
 * \brief commandDescription returns description of the command
 * \param cmd_code command code
 * \return description
 */
const std::string commandDescription(SMBv2Commands cmd_code);

/*!
 * \brief commandName returns name of the command
 * \param cmd_code command code
 * \return name
 */
const std::string commandName(SMBv2Commands cmd_code);

//------------------------------------------------------------------------------
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // CIFS2_COMMANDS_H
//------------------------------------------------------------------------------

