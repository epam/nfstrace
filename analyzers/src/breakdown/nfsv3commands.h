//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Represents NFS v3 commands
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
#ifndef NFSV3COMMANDS_H
#define NFSV3COMMANDS_H
//------------------------------------------------------------------------------
#include "commandrepresenter.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
/*!
 * Represents NFS v3 commands
 * Converts commands to string
 */
class NFSv3Commands : public CommandRepresenter
{
public:
    const char* command_description(int cmd_code) override final;
    const char* command_name(int cmd_code) override final;
    size_t commands_count() override final;
    const char* protocol_name();
};
} // protocols
} // NST
//------------------------------------------------------------------------------
#endif // NFSV3COMMANDS_H
//------------------------------------------------------------------------------
