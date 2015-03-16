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
//------------------------------------------------------------------------------
#ifndef CIFS2_UTILS_H
#define CIFS2_UTILS_H
//------------------------------------------------------------------------------
#include <iosfwd>

#include "api/cifs2_commands.h"
#include "protocols/nfs/nfs_utils.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace CIFSv2
{
namespace SMBv2 = NST::API::SMBv2;

/*! Convert enum type to underlying integer type
 * \param e - instance of enumeration to be converted
 * \return integer representation of enumeration
 */
template<typename E>
inline constexpr auto to_integral(E e) -> typename std::underlying_type<E>::type
{
    return static_cast<typename std::underlying_type<E>::type>(e);
}

std::ostream& operator<<(std::ostream& out, const SMBv2::QueryInfoLevels value);
std::ostream& operator<<(std::ostream& out, const SMBv2::FsInfoLevels value);
std::ostream& operator<<(std::ostream& out, const SMBv2::CtlCodes value);
std::ostream& operator<<(std::ostream& out, const SMBv2::InfoTypes value);
std::ostream& operator<<(std::ostream& out, const SMBv2::ShareTypes value);
std::ostream& operator<<(std::ostream& out, const SMBv2::ShareFlags value);
std::ostream& operator<<(std::ostream& out, const SMBv2::ShareCapabilities value);
std::ostream& operator<<(std::ostream& out, const SMBv2::OplockLevels value);
std::ostream& operator<<(std::ostream& out, const SMBv2::ImpersonationLevels value);
std::ostream& operator<<(std::ostream& out, const SMBv2::DesiredAccessFlags value);
std::ostream& operator<<(std::ostream& out, const SMBv2::FileAttributes value);
std::ostream& operator<<(std::ostream& out, const SMBv2::ShareAccessFlags value);
std::ostream& operator<<(std::ostream& out, const SMBv2::CreateDisposition value);
std::ostream& operator<<(std::ostream& out, const SMBv2::CreateOptionsFlags value);
std::ostream& operator<<(std::ostream& out, const SMBv2::CreateActions value);
std::ostream& operator<<(std::ostream& out, const SMBv2::WriteFlags value);
std::ostream& operator<<(std::ostream& out, const SMBv2::SessionFlagsBinding value);
std::ostream& operator<<(std::ostream& out, const SMBv2::SecurityModeShort value);
std::ostream& operator<<(std::ostream& out, const SMBv2::Capabilities value);
std::ostream& operator<<(std::ostream& out, const SMBv2::SessionFlags value);
std::ostream& operator<<(std::ostream& out, const SMBv2::NTStatus value);
std::ostream& operator<<(std::ostream& out, const SMBv2::AccessMask value);
std::ostream& operator<<(std::ostream& out, const SMBv2::CloseFlags value);
std::ostream& operator<<(std::ostream& out, const SMBv2::SecurityMode value); 

template <typename T>
std::ostream& print_enum(std::ostream& out, const std::string name, T value )
{
    using namespace NST::protocols::NFS;
    out << "  " << name << " = ";
    auto int_value = to_integral(value);
    print_hex(out, int_value);
    out << " (" << value << ")";
    return out;
} 

std::ostream& print_info_levels(std::ostream& os, const NST::API::SMBv2::InfoTypes infoType, const uint8_t infoClass);
}// namespace CIFSv2    
}// namespace protocols 
}// namespace NST       

//------------------------------------------------------------------------------
#endif//CIFS2_UTILS_H
//------------------------------------------------------------------------------
