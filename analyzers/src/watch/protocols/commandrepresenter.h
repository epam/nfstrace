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
namespace CIFSRepresenter
{
struct CommandRepresenter
{
    virtual const std::string command_description(int cmd_code) = 0;
    virtual const std::string command_name(int cmd_code) = 0;
    virtual size_t commands_count() = 0;
    virtual ~CommandRepresenter() {}
};
} // CIFSRepresenter
//------------------------------------------------------------------------------
#endif // COMMANDREPRESENTER_H
//------------------------------------------------------------------------------
