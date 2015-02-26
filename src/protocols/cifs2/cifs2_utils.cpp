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

#include <bitset>

#include "cifs2_utils.h"

namespace NST
{
namespace protocols
{
namespace CIFSv2
{

void print_info_levels(std::ostream& os, const NST::API::SMBv2::InfoTypes infoType, const uint8_t infoClass)
{
    using namespace NST::API::SMBv2;
    os << "  InfoLevel = ";
    switch(infoType)
    {
        case InfoTypes::FILE:
        os << static_cast<QueryInfoLevels>(infoClass) << "\n";
        break;
        case InfoTypes::FILESYSTEM: 
        os << static_cast<FsInfoLevels>(infoClass) << "\n";
        default:
        //we dont handle other classes 
        ; 
    }
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::FsInfoLevels infoLevels)
{
    using namespace NST::API::SMBv2;
    switch(infoLevels)
    {
    case FsInfoLevels::SMB2_FS_INFO_01: os << "SMB2_FS_INFO_01"; break;
    case FsInfoLevels::SMB2_FS_INFO_02: os << "SMB2_FS_INFO_02"; break;
    case FsInfoLevels::SMB2_FS_INFO_03: os << "SMB2_FS_INFO_03"; break;
    case FsInfoLevels::SMB2_FS_INFO_04: os << "SMB2_FS_INFO_04"; break;
    case FsInfoLevels::SMB2_FS_INFO_05: os << "SMB2_FS_INFO_05"; break;
    case FsInfoLevels::SMB2_FS_INFO_06: os << "SMB2_FS_INFO_06"; break;
    case FsInfoLevels::SMB2_FS_INFO_07: os << "SMB2_FS_INFO_07"; break;
    }
    os << " (0x" << std::hex << static_cast<uint32_t>(infoLevels) << ")" << std::dec; 
    return os;
} 


std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::QueryInfoLevels infoLevels)
{
    using namespace NST::API::SMBv2;
    switch(infoLevels)
    {
    case QueryInfoLevels::DIRECTORY_INFORMATION:             os << "DIRECTORY_INFORMATION"; break;
    case QueryInfoLevels::FULL_DIRECTORY_INFORMATION:        os << "FULL_DIRECTORY_INFORMATION"; break;
    case QueryInfoLevels::BOTH_DIRECTORY_INFORMATION:        os << "BOTH_DIRECTORY_INFORMATION"; break;
    case QueryInfoLevels::BASIC_INFORMATION:                 os << "BASIC_INFORMATION"; break;
    case QueryInfoLevels::STANDARD_INFORMATION:              os << "STANDARD_INFORMATION"; break;
    case QueryInfoLevels::INTERNAL_INFORMATION:              os << "INTERNAL_INFORMATION"; break;
    case QueryInfoLevels::EA_INFORMATION:                    os << "EA_INFORMATION"; break;
    case QueryInfoLevels::ACCESS_INFORMATION:                os << "ACCESS_INFORMATION"; break;
    case QueryInfoLevels::NAME_INFORMATION:                  os << "NAME_INFORMATION"; break;
    case QueryInfoLevels::RENAME_INFORMATION:                os << "RENAME_INFORMATION"; break;
    case QueryInfoLevels::LINK_INFORMATION:                  os << "LINK_INFORMATION"; break;
    case QueryInfoLevels::NAMES_INFORMATION:                 os << "NAMES_INFORMATION"; break;
    case QueryInfoLevels::DISPOSITION_INFORMATION:           os << "DISPOSITION_INFORMATION"; break;
    case QueryInfoLevels::POSITION_INFORMATION:              os << "POSITION_INFORMATION"; break;
    case QueryInfoLevels::FULL_EA_INFORMATION:               os << "FULL_EA_INFORMATION"; break;
    case QueryInfoLevels::MODE_INFORMATION:                  os << "MODE_INFORMATION"; break;
    case QueryInfoLevels::ALIGNMENT_INFORMATION:             os << "ALIGNMENT_INFORMATION"; break;
    case QueryInfoLevels::ALL_INFORMATION:                   os << "ALL_INFORMATION"; break;
    case QueryInfoLevels::ALLOCATION_INFORMATION:            os << "ALLOCATION_INFORMATION"; break;
    case QueryInfoLevels::END_OF_FILE_INFORMATION:           os << "END_OF_FILE_INFORMATION"; break;
    case QueryInfoLevels::ALTERNATE_NAME_INFORMATION:        os << "ALTERNATE_NAME_INFORMATION"; break;
    case QueryInfoLevels::STREAM_INFORMATION:                os << "STREAM_INFORMATION"; break;
    case QueryInfoLevels::PIPE_INFORMATION:                  os << "PIPE_INFORMATION"; break;
    case QueryInfoLevels::PIPE_LOCAL_INFORMATION:            os << "PIPE_LOCAL_INFORMATION"; break;
    case QueryInfoLevels::PIPE_REMOTE_INFORMATION:           os << "PIPE_REMOTE_INFORMATION"; break;
    case QueryInfoLevels::MAILSLOT_QUERY_INFORMATION:        os << "MAILSLOT_QUERY_INFORMATION"; break;
    case QueryInfoLevels::MAILSLOT_SET_INFORMATION:          os << "MAILSLOT_SET_INFORMATION"; break;
    case QueryInfoLevels::COMPRESSION_INFORMATION:           os << "COMPRESSION_INFORMATION"; break;
    case QueryInfoLevels::OBJECT_ID_INFORMATION:             os << "OBJECT_ID_INFORMATION"; break;
    case QueryInfoLevels::MOVE_CLUSTER_INFORMATION:          os << "MOVE_CLUSTER_INFORMATION"; break;
    case QueryInfoLevels::QUOTA_INFORMATION:                 os << "QUOTA_INFORMATION"; break;
    case QueryInfoLevels::REPARSE_POINT_INFORMATION:         os << "REPARSE_POINT_INFORMATION"; break;
    case QueryInfoLevels::NETWORK_OPEN_INFORMATION:          os << "NETWORK_OPEN_INFORMATION"; break;
    case QueryInfoLevels::ATTRIBUTE_TAG_INFORMATION:         os << "ATTRIBUTE_TAG_INFORMATION"; break;
    case QueryInfoLevels::TRACKING_INFORMATION:              os << "TRACKING_INFORMATION"; break;
    case QueryInfoLevels::ID_BOTH_DIRECTORY_INFORMATION:     os << "ID_BOTH_DIRECTORY_INFORMATION"; break;
    case QueryInfoLevels::ID_FULL_DIRECTORY_INFORMATION:     os << "ID_FULL_DIRECTORY_INFORMATION"; break;
    case QueryInfoLevels::VALID_DATA_LENGTH_INFORMATION:     os << "VALID_DATA_LENGTH_INFORMATION"; break;
    case QueryInfoLevels::SHORT_NAME_INFORMATION:            os << "SHORT_NAME_INFORMATION"; break;
    case QueryInfoLevels::SFIO_RESERVE_INFORMATION:          os << "SFIO_RESERVE_INFORMATION"; break;
    case QueryInfoLevels::SFIO_VOLUME_INFORMATION:           os << "SFIO_VOLUME_INFORMATION"; break;
    case QueryInfoLevels::HARD_LINK_INFORMATION:             os << "HARD_LINK_INFORMATION"; break;
    case QueryInfoLevels::NORMALIZED_NAME_INFORMATION:       os << "NORMALIZED_NAME_INFORMATION"; break;
    case QueryInfoLevels::ID_GLOBAL_TX_DIRECTORY_INFORMATION:os << "ID_GLOBAL_TX_DIRECTORY_INFORMATION"; break;
    case QueryInfoLevels::STANDARD_LINK_INFORMATION:         os << "STANDARD_LINK_INFORMATION"; break;
    } 
    os << " (0x" << std::hex << static_cast<uint32_t>(infoLevels) << ")" << std::dec;
    return os;
}
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CtlCodes code)
{
    using namespace NST::API::SMBv2;
    switch(code)
    {
        case CtlCodes::SCTL_DFS_GET_REFERRALS:              os << "SCTL_DFS_GET_REFERRALS"; break;
        case CtlCodes::FSCTL_PIPE_PEEK:                     os << "FSCTL_PIPE_PEEK"; break;
        case CtlCodes::FSCTL_PIPE_WAIT:                     os << "FSCTL_PIPE_WAIT"; break;
        case CtlCodes::FSCTL_PIPE_TRANSCEIVE:               os << "FSCTL_PIPE_TRANSCEIVE"; break;
        case CtlCodes::FSCTL_SRV_COPYCHUNK:                 os << "FSCTL_SRV_COPYCHUNK"; break;
        case CtlCodes::FSCTL_SRV_ENUMERATE_SNAPSHOTS:       os << "FSCTL_SRV_ENUMERATE_SNAPSHOTS"; break;
        case CtlCodes::FSCTL_SRV_REQUEST_RESUME_KEY:        os << "FSCTL_SRV_REQUEST_RESUME_KEY"; break;
        case CtlCodes::FSCTL_SRV_READ_HASH:                 os << "FSCTL_SRV_READ_HASH"; break;
        case CtlCodes::FSCTL_SRV_COPYCHUNK_WRITE:           os << "FSCTL_SRV_COPYCHUNK_WRITE"; break;
        case CtlCodes::FSCTL_LMR_REQUEST_RESILIENCY:        os << "FSCTL_LMR_REQUEST_RESILIENCY"; break;
        case CtlCodes::FSCTL_QUERY_NETWORK_INTERFACE_INFO:  os << "FSCTL_QUERY_NETWORK_INTERFACE_INFO"; break;
        case CtlCodes::FSCTL_SET_REPARSE_POINT:             os << "FSCTL_SET_REPARSE_POINT"; break;
        case CtlCodes::FSCTL_DFS_GET_REFERRALS_EX:          os << "FSCTL_DFS_GET_REFERRALS_EX"; break;
        case CtlCodes::FSCTL_FILE_LEVEL_TRIM:               os << "FSCTL_FILE_LEVEL_TRIM"; break;
        case CtlCodes::FSCTL_VALIDATE_NEGOTIATE_INFO:       os << "FSCTL_VALIDATE_NEGOTIATE_INFO"; break;
    }
    os << "(0x" << std::hex << static_cast<uint32_t>(code) << std::dec << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::InfoTypes infoTypes)
{
    using namespace NST::API::SMBv2;
    switch(infoTypes)
    {
        case InfoTypes::FILE:              os << "SMB2_0_INFO_FILE"; break;
        case InfoTypes::FILESYSTEM:        os << "SMB2_0_INFO_FILESYSTEM"; break;
        case InfoTypes::SECURITY:          os << "SMB2_0_INFO_SECURITY"; break;
        case InfoTypes::QUOTA:             os << "SMB2_0_INFO_QUOTA"; break;
    }
    os << "(0x" << std::hex << static_cast<uint32_t>(infoTypes) << std::dec << ")";
    return os;
}
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareTypes shareTypes)
{
    using namespace NST::API::SMBv2;
    switch(shareTypes)
    {
        case ShareTypes::DISK:        os << "SMB2_SHARE_TYPE_DISK"; break;
        case ShareTypes::PIPE:        os << "SMB2_SHARE_TYPE_PIPE"; break;
        case ShareTypes::PRINT:       os << "SMB2_SHARE_TYPE_PRINT"; break;
    }
    os << "(0x" << std::hex << static_cast<uint32_t>(shareTypes) << std::dec << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareFlags shareFlags)
{
    using namespace NST::API::SMBv2; 
    if(shareFlags & ShareFlags::MANUAL_CACHING)
    {
        os << "\tSMB2_SHAREFLAG_MANUAL_CACHING\n ";
    } 
    if(shareFlags & (ShareFlags::AUTO_CACHING))
    {
        os << "\tSMB2_SHAREFLAG_AUTO_CACHING\n";
    } 
    if(shareFlags & (ShareFlags::VDO_CACHING))
    {
        os << "\tSMB2_SHAREFLAG_VDO_CACHING\n";
    } 
    if(shareFlags & ShareFlags::NO_CACHING)
    {
        os << "\tSMB2_SHAREFLAG_NO_CACHING\n";
    } 
    if(shareFlags & (ShareFlags::DFS))
    {
        os << "\tSMB2_SHAREFLAG_DFS\n";
    } 
    if(shareFlags & ShareFlags::DFS_ROOT)
    {
        os << "\tSMB2_SHAREFLAG_DFS_ROOT\n";
    } 
    if(shareFlags & ShareFlags::RESTRICT_EXCLUSIVE_OPENS)
    {
        os << "\tSMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS\n";
    } 
    if(shareFlags & ShareFlags::FORCE_SHARED_DELETE)
    {
        os << "\tSMB2_SHAREFLAG_FORCE_SHARED_DELETE\n";
    } 
    if(shareFlags | ShareFlags::ALLOW_NAMESPACE_CACHING)
    {
        os << "\tSMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING\n";
    } 
    if(shareFlags | ShareFlags::ACCESS_BASED_DIRECTORY_ENUM)
    {
        os << "\tSMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM\n";
    } 
    if(shareFlags | ShareFlags::FORCE_LEVELII_OPLOCK)
    {
        os << "\tSMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK\n";
    } 
    if(shareFlags | ShareFlags::ENABLE_HASH)
    {
        os << "\tSMB2_SHAREFLAG_ENABLE_HASH_V1\n";
    } 
    if(shareFlags | ShareFlags::ENABLE_HASH_2)
    {
        os << "\tSMB2_SHAREFLAG_ENABLE_HASH_V2\n";
    } 
    if(shareFlags | ShareFlags::ENABLE_ENCRYPT_DATA)
    {
        os << "\tSMB2_SHAREFLAG_ENCRYPT_DATA\n";
    } 
    return os;
} 
} // namespace CIFSv2
} // namespace protocols
} // namespace NST
