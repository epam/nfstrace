//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Interface for command representers
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
#ifndef COMMANDREPRESENTER_H
#define COMMANDREPRESENTER_H
//------------------------------------------------------------------------------
#include <string>
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
//------------------------------------------------------------------------------
/*!
 * \brief The CommandRepresenter struct represents interface for command representers
 */
struct CommandRepresenter
{
    /*!
     * \brief commandDescription returns description of the command
     * \param cmd_code command code
     * \return description
     */
    virtual const std::string commandDescription(int cmd_code) = 0;

    /*!
     * \brief commandName returns name of the command
     * \param cmd_code command code
     * \return name
     */
    virtual const std::string commandName(int cmd_code) = 0;

    /*!
     * \brief commandsCount returns total count of commands
     * \return count
     */
    virtual size_t commandsCount() = 0;

    virtual ~CommandRepresenter() {}
};
//------------------------------------------------------------------------------
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // COMMANDREPRESENTER_H
//------------------------------------------------------------------------------

