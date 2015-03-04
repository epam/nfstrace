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
#include <sstream>

#include "cifs2_utils.h"
#include "protocols/nfs/nfs_utils.h"

namespace NST
{
namespace protocols
{
namespace CIFSv2
{

using namespace NST::protocols::NFS;
using namespace NST::API::SMBv2;

namespace
{
    static const std::string flagDelimiter = " | ";

    inline bool operator&(const NST::API::SMBv2::ShareFlags lhs, const NST::API::SMBv2::ShareFlags rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    }

    inline bool operator&(const NST::API::SMBv2::Capabilities lhs, const NST::API::SMBv2::Capabilities rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    }

    inline bool operator&(const NST::API::SMBv2::DesiredAccessFlags lhs, const NST::API::SMBv2::DesiredAccessFlags rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    }

    inline bool operator&(const NST::API::SMBv2::FileAttributes lhs, const NST::API::SMBv2::FileAttributes rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    }

    inline bool operator&(const NST::API::SMBv2::ShareAccessFlags lhs, const NST::API::SMBv2::ShareAccessFlags rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    }

    inline bool operator&(const NST::API::SMBv2::WriteFlags lhs, const NST::API::SMBv2::WriteFlags rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    }

    inline bool operator&(const NST::API::SMBv2::SecurityModeShort lhs, const NST::API::SMBv2::SecurityModeShort rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    }

    inline bool operator&(const NST::API::SMBv2::ShareCapabilities lhs, const NST::API::SMBv2::ShareCapabilities rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    }

    inline bool operator&(const NST::API::SMBv2::SessionFlags lhs, const NST::API::SMBv2::SessionFlags rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    }

    const char* enumToCharPtr(const NST::API::SMBv2::OplockLevels value)
    {
        switch (value)
        {
            case OplockLevels::NONE:      return "NONE";
            case OplockLevels::II:        return "II";
            case OplockLevels::EXCLUSIVE: return "EXCLUSIVE";
            case OplockLevels::BATCH:     return "BATCH";
            case OplockLevels::LEASE:     return "LEASE";
        }

        assert("enumToCharPtr: Cannot conver input value into string representation.");
        return nullptr;
    }

    const char* enumToCharPtr(const NST::API::SMBv2::ImpersonationLevels value)
    {
        switch (value)
        {
            case ImpersonationLevels::ANONYMOUS:        return "ANONYMOUS";
            case ImpersonationLevels::IDENTIFICATION:   return "IDENTIFICATION";
            case ImpersonationLevels::IMPERSONATION:    return "IMPERSONATION";
            case ImpersonationLevels::DELEGATE:         return "DELEGATE";
        }

        assert("enumToCharPtr: Cannot conver input value into string representation.");
        return nullptr;
    }

    const char* enumToCharPtr(const NST::API::SMBv2::CreateDisposition value)
    {
        switch(value)
        {
            case CreateDisposition::SUPERSEDE:       return "SUPERSEDE";
            case CreateDisposition::OPEN:            return "OPEN";
            case CreateDisposition::CREATE:          return "CREATE";
            case CreateDisposition::OPEN_IF:         return "OPEN_IF";
            case CreateDisposition::OVERWRITE:       return "OVERWRITE";
            case CreateDisposition::OVERWRITE_IF:    return "OVERWRITE_IF";
        }

        assert("enumToCharPtr: Cannot conver input value into string representation.");
        return nullptr;
    }

    const char* enumToCharPtr(const NST::API::SMBv2::CreateActions value)
    {
        switch(value)
        {
            case CreateActions::SUPERSEDED:          return "SUPERSEDED";
            case CreateActions::OPENED:              return "OPENED";
            case CreateActions::CREATED:             return "CREATED";
            case CreateActions::FILE_OVERWRITTEN:    return "FILE_OVERWRITTEN";
        }

        assert("enumToCharPtr: Cannot conver input value into string representation.");
        return nullptr;
    }

    const char* enumToCharPtr(const NST::API::SMBv2::ShareTypes value)
    { 
        using namespace NST::API::SMBv2;
        switch(value)
        {
            case ShareTypes::DISK:        return "SMB2_SHARE_TYPE_DISK";
            case ShareTypes::PIPE:        return "SMB2_SHARE_TYPE_PIPE";
            case ShareTypes::PRINT:       return "SMB2_SHARE_TYPE_PRINT";
        }

        assert("enumToCharPtr: Cannot conver input value into string representation.");
        return nullptr;
    }

    inline std::string ClearFromLastDelimiter(std::string str, std::string delimiter = flagDelimiter)
    {
        if (str.length() == 0) return str;
        return str.erase(str.length() - delimiter.length());
    }

    std::string enumToFlags(const NST::API::SMBv2::DesiredAccessFlags value, std::string delimiter = flagDelimiter)
    {
        std::ostringstream str;
        if (value & DesiredAccessFlags::READ_DATA_LE)
        {
            str << "READ_DATA_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::WRITE_DATA_LE)
        {
            str << "WRITE_DATA_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::APPEND_DATA_LE)
        {
            str << "APPEND_DATA_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::READ_EA_LE)
        {
            str << "READ_EA_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::WRITE_EA_LE)
        {
            str << "WRITE_EA_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::EXECUTE_LE)
        {
            str << "EXECUTE_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::READ_ATTRIBUTES_LE)
        {
            str << "READ_ATTRIBUTES_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::WRITE_ATTRIBUTES_LE)
        {
            str << "WRITE_ATTRIBUTES_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::DELETE_LE)
        {
            str << "DELETE_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::READ_CONTROL_LE)
        {
            str << "READ_CONTROL_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::WRITE_DAC_LE)
        {
            str << "WRITE_DAC_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::WRITE_OWNER_LE)
        {
            str << "WRITE_OWNER_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::SYNCHRONIZE_LE)
        {
            str << "SYNCHRONIZE_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::ACCESS_SYSTEM_SECURITY_LE)
        {
            str << "ACCESS_SYSTEM_SECURITY_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::MAXIMAL_ACCESS_LE)
        {
            str << "MAXIMAL_ACCESS_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::GENERIC_ALL_LE)
        {
            str << "GENERIC_ALL_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::GENERIC_EXECUTE_LE)
        {
            str << "GENERIC_EXECUTE_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::GENERIC_WRITE_LE)
        {
            str << "GENERIC_WRITE_LE" << delimiter;
        }
        if (value & DesiredAccessFlags::GENERIC_READ_LE)
        {
            str << "GENERIC_READ_LE" << delimiter;
        }

        return ClearFromLastDelimiter(str.str());
    }

    std::string enumToFlags(const NST::API::SMBv2::FileAttributes value, std::string delimiter = flagDelimiter)
    {
        std::ostringstream str;

        if (value & FileAttributes::READONLY)
        {
            str << "READONLY" << delimiter;
        }
        if (value & FileAttributes::HIDDEN)
        {
            str << "HIDDEN" << delimiter;
        }
        if (value & FileAttributes::SYSTEM)
        {
            str << "SYSTEM" << delimiter;
        }
        if (value & FileAttributes::DIRECTORY)
        {
            str << "DIRECTORY" << delimiter;
        }
        if (value & FileAttributes::ARCHIVE)
        {
            str << "ARCHIVE" << delimiter;
        }
        if (value & FileAttributes::NORMAL)
        {
            str << "NORMAL" << delimiter;
        }
        if (value & FileAttributes::TEMPORARY)
        {
            str << "TEMPORARY" << delimiter;
        }
        if (value & FileAttributes::SPARSE_FILE)
        {
            str << "SPARSE_FILE" << delimiter;
        }
        if (value & FileAttributes::REPARSE_POINT)
        {
            str << "REPARSE_POINT" << delimiter;
        }
        if (value & FileAttributes::COMPRESSED)
        {
            str << "COMPRESSED" << delimiter;
        }
        if (value & FileAttributes::OFFLINE)
        {
            str << "OFFLINE" << delimiter;
        }
        if (value & FileAttributes::NOT_CONTENT_INDEXED)
        {
            str << "NOT_CONTENT_INDEXED" << delimiter;
        }
        if (value & FileAttributes::ENCRYPTED)
        {
            str << "ENCRYPTED" << delimiter;
        }

        return ClearFromLastDelimiter(str.str());
    }

    std::string enumToFlags(const NST::API::SMBv2::ShareAccessFlags value, std::string delimiter = flagDelimiter)
    {
        std::ostringstream str;

        if (value & ShareAccessFlags::SHARE_READ_LE)
        {
            str << "SHARE_READ_LE" << delimiter;
        }
        if (value & ShareAccessFlags::SHARE_WRITE_LE)
        {
            str << "SHARE_WRITE_LE" << delimiter;
        }
        if (value & ShareAccessFlags::SHARE_DELETE_LE)
        {
            str << "SHARE_DELETE_LE" << delimiter;
        }

        return ClearFromLastDelimiter(str.str());
    }

    std::string enumToFlags(const NST::API::SMBv2::CreateOptionsFlags value, std::string delimiter = flagDelimiter)
    {
        std::ostringstream str;

        if (value & CreateOptionsFlags::DIRECTORY_FILE_LE)
        {
            str << "DIRECTORY_FILE_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::WRITE_THROUGH_LE)
        {
            str << "WRITE_THROUGH_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::SEQUENTIAL_ONLY_LE)
        {
            str << "SEQUENTIAL_ONLY_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::NO_INTERMEDIATE_BUFFERRING_LE)
        {
            str << "NO_INTERMEDIATE_BUFFERRING_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::SYNCHRONOUS_IO_ALERT_LE)
        {
            str << "SYNCHRONOUS_IO_ALERT_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::SYNCHRONOUS_IO_NON_ALERT_LE)
        {
            str << "SYNCHRONOUS_IO_NON_ALERT_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::NON_DIRECTORY_FILE_LE)
        {
            str << "NON_DIRECTORY_FILE_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::COMPLETE_IF_OPLOCKED_LE)
        {
            str << "COMPLETE_IF_OPLOCKED_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::NO_EA_KNOWLEDGE_LE)
        {
            str << "NO_EA_KNOWLEDGE_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::RANDOM_ACCESS_LE)
        {
            str << "RANDOM_ACCESS_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::DELETE_ON_CLOSE_LE)
        {
            str << "DELETE_ON_CLOSE_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::OPEN_BY_FILE_ID_LE)
        {
            str << "OPEN_BY_FILE_ID_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::OPEN_FOR_BACKUP_INTENT_LE)
        {
            str << "OPEN_FOR_BACKUP_INTENT_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::NO_COMPRESSION_LE)
        {
            str << "NO_COMPRESSION_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::RESERVE_OPFILTER_LE)
        {
            str << "RESERVE_OPFILTER_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::OPEN_REPARSE_POINT_LE)
        {
            str << "OPEN_REPARSE_POINT_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::OPEN_NO_RECALL_LE)
        {
            str << "OPEN_NO_RECALL_LE" << delimiter;
        }
        if (value & CreateOptionsFlags::OPEN_FOR_FREE_SPACE_QUERY_LE)
        {
            str << "OPEN_FOR_FREE_SPACE_QUERY_LE" << delimiter;
        }

        return ClearFromLastDelimiter(str.str());
    }

    std::string enumToFlags(const NST::API::SMBv2::WriteFlags value, std::string delimiter = flagDelimiter)
    {
        std::ostringstream str;

        if (value & WriteFlags::SMB2_WRITEFLAG_WRITE_THROUGH)
        {
            str << "SMB2_WRITEFLAG_WRITE_THROUGH" << delimiter;
        }
        if (value & WriteFlags::SMB2_WRITEFLAG_WRITE_UNBUFFERED)
        {
            str << "SMB2_WRITEFLAG_WRITE_UNBUFFERED" << delimiter;
        }

        return ClearFromLastDelimiter(str.str());
    }

    std::string enumToFlags(const NST::API::SMBv2::ShareFlags value, std::string delimiter = flagDelimiter)  
    {
        std::ostringstream str;
        if(value & ShareFlags::MANUAL_CACHING)
        {
            str << "SMB2_SHAREFLAG_MANUAL_CACHING " << delimiter;
        } 
        if(value & ShareFlags::AUTO_CACHING)
        {
            str << "SMB2_SHAREFLAG_AUTO_CACHING" << delimiter;
        } 
        if(value & ShareFlags::VDO_CACHING)
        {
            str << "SMB2_SHAREFLAG_VDO_CACHING" << delimiter;
        } 
        if(value & ShareFlags::NO_CACHING)
        {
            str << "SMB2_SHAREFLAG_NO_CACHING" << delimiter;
        } 
        if(value & (ShareFlags::DFS))
        {
            str << "SMB2_SHAREFLAG_DFS" << delimiter;
        } 
        if(value & ShareFlags::DFS_ROOT)
        {
            str << "SMB2_SHAREFLAG_DFS_ROOT" << delimiter;
        } 
        if(value & ShareFlags::RESTRICT_EXCLUSIVE_OPENS)
        {
            str << "SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS" << delimiter;
        } 
        if(value & ShareFlags::FORCE_SHARED_DELETE)
        {
            str << "SMB2_SHAREFLAG_FORCE_SHARED_DELETE" << delimiter;
        } 
        if(value & ShareFlags::ALLOW_NAMESPACE_CACHING)
        {
            str << "SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING" << delimiter;
        } 
        if(value & ShareFlags::ACCESS_BASED_DIRECTORY_ENUM)
        {
            str << "SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM" << delimiter;
        } 
        if(value & ShareFlags::FORCE_LEVELII_OPLOCK)
        {
            str << "SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK" << delimiter;
        } 
        if(value & ShareFlags::ENABLE_HASH)
        {
            str << "SMB2_SHAREFLAG_ENABLE_HASH_V1" << delimiter;
        } 
        if(value & ShareFlags::ENABLE_HASH_2)
        {
            str << "SMB2_SHAREFLAG_ENABLE_HASH_V2" << delimiter;
        } 
        if(value & ShareFlags::ENABLE_ENCRYPT_DATA)
        {
            str << "SMB2_SHAREFLAG_ENCRYPT_DATA" << delimiter;
        } 
        return ClearFromLastDelimiter(str.str());
    }

    std::string enumToFlags(const NST::API::SMBv2::ShareCapabilities value, std::string delimiter = flagDelimiter)
    {
        std::ostringstream str;
        if(value & ShareCapabilities::DFS)
        {
            str << "SMB2_SHARE_CAP_DFS" << delimiter;
        } 
        if(value & ShareCapabilities::CONTINUOUS_AVAILABILITY)
        {
            str << "SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY" << delimiter;
        } 
        if(value & ShareCapabilities::SCALEOUT)
        {
            str << "SMB2_SHARE_CAP_SCALEOUT" << delimiter;
        } 
        if(value & ShareCapabilities::CLUSTER)
        {
            str << "SMB2_SHARE_CAP_CLUSTER" << delimiter;
        } 
        if(value & ShareCapabilities::ASYMMETRIC)
        {
            str << "SMB2_SHARE_CAP_ASYMMETRIC" << delimiter;
        } 
        return ClearFromLastDelimiter(str.str());
    }

    std::string enumToFlags(const NST::API::SMBv2::SecurityModeShort value, std::string delimiter = flagDelimiter)
    {
        std::ostringstream str;
        if(value & SecurityModeShort::SIGNING_ENABLED)
        {
            str << "SIGNING_ENABLED" << delimiter;
        } 
        if(value & SecurityModeShort::SIGNING_REQUIRED)
        {
            str << "SIGNING_REQUIRED" << delimiter;
        } 
        return ClearFromLastDelimiter(str.str());
    }

    std::string enumToFlags(const NST::API::SMBv2::Capabilities value, std::string delimiter = flagDelimiter)
    {
        std::ostringstream str;
        if(value & Capabilities::DFS)
        {
            str << "DFS" << delimiter;
        } 
        if(value & Capabilities::LEASING)
        {
            str << "LEASING" << delimiter;
        } 
        if(value & Capabilities::LARGE_MTU)
        {
            str << "LARGE_MTU" << delimiter;
        } 
        if(value & Capabilities::MULTI_CHANNEL)
        {
            str << "MULTI_CHANNEL" << delimiter;
        } 
        if(value & Capabilities::PERSISTENT_HANDLES)
        {
            str << "PERSISTENT_HANDLES" << delimiter;
        } 
        if(value & Capabilities::DIRECTORY_LEASING)
        {
            str << "DIRECTORY_LEASING" << delimiter;
        } 
        if(value & Capabilities::ENCRYPTION)
        {
            str << "ENCRYPTION" << delimiter;
        } 
        return ClearFromLastDelimiter(str.str());
    }

    std::string enumToFlags(const NST::API::SMBv2::SessionFlags value, std::string delimiter = flagDelimiter)
    {
        std::ostringstream str;
        if(value & SessionFlags::NONE)
        {
            str << "NONE" << delimiter;
        } 
        if(value & SessionFlags::IS_GUEST)
        {
            str << "SMB2_SESSION_FLAG_IS_GUEST" << delimiter;
        } 
        if(value & SessionFlags::IS_NULL)
        {
            str << "SMB2_SESSION_FLAG_IS_NULL" << delimiter;
        } 
        if(value & SessionFlags::IS_ENCRYPT_DATA)
        {
            str << "SMB2_SESSION_FLAG_ENCRYPT_DATA" << delimiter;
        } 
        return ClearFromLastDelimiter(str.str());
    }
}

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

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::FsInfoLevels value)
{
    using namespace NST::API::SMBv2;
    switch(value)
    {
    case FsInfoLevels::SMB2_FS_INFO_01: os << "SMB2_FS_INFO_01"; break;
    case FsInfoLevels::SMB2_FS_INFO_02: os << "SMB2_FS_INFO_02"; break;
    case FsInfoLevels::SMB2_FS_INFO_03: os << "SMB2_FS_INFO_03"; break;
    case FsInfoLevels::SMB2_FS_INFO_04: os << "SMB2_FS_INFO_04"; break;
    case FsInfoLevels::SMB2_FS_INFO_05: os << "SMB2_FS_INFO_05"; break;
    case FsInfoLevels::SMB2_FS_INFO_06: os << "SMB2_FS_INFO_06"; break;
    case FsInfoLevels::SMB2_FS_INFO_07: os << "SMB2_FS_INFO_07"; break;
    }
    os << " (";
    print_hex16(os, to_integral(value));
    os << ")";
    return os;
} 


std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::QueryInfoLevels value)
{
    using namespace NST::API::SMBv2;
    switch(value)
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
    os << " (";
    print_hex16(os, to_integral(value));
    os << ")";
    return os;
}
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CtlCodes value)
{
    using namespace NST::API::SMBv2;
    switch(value)
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
    os << " (";
    print_hex16(os, to_integral(value));
    os << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::InfoTypes value)
{
    using namespace NST::API::SMBv2;
    switch(value)
    {
        case InfoTypes::FILE:              os << "SMB2_0_INFO_FILE"; break;
        case InfoTypes::FILESYSTEM:        os << "SMB2_0_INFO_FILESYSTEM"; break;
        case InfoTypes::SECURITY:          os << "SMB2_0_INFO_SECURITY"; break;
        case InfoTypes::QUOTA:             os << "SMB2_0_INFO_QUOTA"; break;
    }
    os << " (";
    print_hex16(os, to_integral(value));
    os << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareTypes value)
{
    os << enumToCharPtr(value);
    os << " (";
    print_hex32(os, to_integral(value)); 
    os << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::OplockLevels value)
{
    os << "(" << enumToCharPtr(value) << ") ";
    print_hex8(os, to_integral(value)); 
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ImpersonationLevels value)
{
    os << "(" << enumToCharPtr(value) << ") "
       << to_integral(value);

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::DesiredAccessFlags value)
{
    print_hex32(os, to_integral(value)); 
    os << " (" << enumToFlags(value) << ") "; 
    return os;
}


std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareFlags value)
{
    using namespace NST::API::SMBv2; 
    print_hex32(os, to_integral(value));
    if (to_integral(value) > 0)
    {
        os << " (" << enumToFlags(value) << ") ";
    }
    return os; 
} 

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareCapabilities value)
{
    using namespace NST::API::SMBv2; 
    print_hex32(os, to_integral(value)); 
    if (to_integral(value) > 0)
    {
        os << " (" << enumToFlags(value) << ")";
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::FileAttributes value)
{
    print_hex32(os, to_integral(value));

    if (to_integral(value) > 0)
    {
        os << " (" << enumToFlags(value) << ")";
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareAccessFlags value)
{
    os << to_integral(value);

    if (to_integral(value) > 0)
    {
        os << " (" << enumToFlags(value) << ")";
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CreateDisposition value)
{
    os << " (" << enumToCharPtr(value) << ") "
       << to_integral(value);

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CreateOptionsFlags value)
{
    print_hex32(os, to_integral(value));

    if (to_integral(value) > 0)
    {
        os << " (" << enumToFlags(value) << ") ";
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CreateActions value)
{
    os << " (" << enumToCharPtr(value) << ") " << to_integral(value);

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::WriteFlags value)
{
    print_hex32(os, to_integral(value));

    if (to_integral(value) > 0)
    {
        os << " (" << enumToFlags(value) << ") ";
    }

    return os;
}
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SessionFlagsBinding value)
{
    using namespace NST::API::SMBv2;
    switch(value) 
    {
        case SessionFlagsBinding::NONE:     os << "NONE"; break;
        case SessionFlagsBinding::BINDING:  os << "BINDING"; break;
    }
    os << " (";
    print_hex32(os, to_integral(value));
    os << ")";
    return os;
}
std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SecurityModeShort value)
{
    print_hex32(os, to_integral(value));

    if (to_integral(value) > 0)
    {
        os << " (" << enumToFlags(value) << ") ";
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::Capabilities value)
{
    using namespace NST::API::SMBv2; 
    print_hex32(os, to_integral(value));
    if (to_integral(value) > 0)
    {
        os << " (" << enumToFlags(value) << ")";
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SessionFlags value) 
{
    using namespace NST::API::SMBv2; 
    print_hex32(os, to_integral(value));
    if (to_integral(value) > 0)
    {
        os << " (" << enumToFlags(value) << ")";
    }
    return os;
}

} // namespace CIFSv2
} // namespace protocols
} // namespace NST
