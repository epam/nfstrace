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

/*!
 * \brief The CommandRepresenter struct represents interface for command representers
 * Commands representer should be able to convert commands to string
 */
struct CommandRepresenter
{
    /*!
     * \brief returns description of the command
     * \param cmd_code command code
     * \return description
     */
    virtual const char* command_description(int cmd_code) = 0;

    /*!
     * \brief returns name of the command
     * \param cmd_code command code
     * \return name
     */
    virtual const char* command_name(int cmd_code) = 0;

    /*!
     * \brief returns name of the protocol
     * \return protocol
     */
    virtual const char* protocol_name() = 0;

    /*!
     * \brief commandsCount returns total count of commands
     * \return count
     */
    virtual size_t commands_count() = 0;

    virtual ~CommandRepresenter() {}
};

} // namespace breakdown
} // namespace NST
//------------------------------------------------------------------------------
#endif//COMMANDREPRESENTER_H
//------------------------------------------------------------------------------
