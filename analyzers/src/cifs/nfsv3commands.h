//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Helpers for parsing CIFS v2 structures.
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
class NFSv3Commands : public CommandRepresenter
{
public:
    const std::string command_description(int cmd_code);
    const std::string command_name(int cmd_code);
    size_t commands_count();
};
} // protocols
} // NST
//------------------------------------------------------------------------------
#endif // NFSV3COMMANDS_H
//------------------------------------------------------------------------------

