//------------------------------------------------------------------------------
// Author: Artsem Iliasau 
// Description: Helpers for parsing CIFSv2 structures.
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

#ifndef CIFS2_UTILS_H
#define CIFS2_UTILS_H

#include <iostream>

#include "api/cifs2_commands.h"

namespace NST
{
namespace protocols
{
namespace CIFSv2
{
void print_info_levels(std::ostream& os, const NST::API::SMBv2::InfoTypes infoType, const uint8_t infoClass);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::QueryInfoLevels infoLevels);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::FsInfoLevels infoLevels);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CtlCodes code);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::InfoTypes infoTypes);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareTypes shareTypes);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareFlags shareFlags);
}// namespace CIFSv2    
}// namespace protocols 
}// namespace NST       

#endif//CIFS2_UTILS_H
