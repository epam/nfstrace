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
#include <assert.h>

#include "api/cifs2_commands.h"

namespace NST
{
namespace protocols
{
namespace CIFSv2
{

template<typename E>
inline constexpr auto to_integral(E e) -> typename std::underlying_type<E>::type
{
    return static_cast<typename std::underlying_type<E>::type>(e);
}

void print_info_levels(std::ostream& os, const NST::API::SMBv2::InfoTypes infoType, const uint8_t infoClass);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::QueryInfoLevels infoLevels);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::FsInfoLevels infoLevels);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CtlCodes code);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::InfoTypes infoTypes);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareTypes shareTypes);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareFlags shareFlags);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareCapabilities capabilities);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::OplockLevels value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ImpersonationLevels value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::DesiredAccessFlags value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::FileAttributes value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareAccessFlags value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CreateDisposition value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CreateOptionsFlags value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CreateActions value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::WriteFlags value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SessionFlagsBinding value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SecurityModeShort value);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::Capabilities capabilities);
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SessionFlags value);
}// namespace CIFSv2    
}// namespace protocols 
}// namespace NST       

#endif//CIFS2_UTILS_H
