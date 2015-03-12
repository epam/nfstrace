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
static const std::string flagDelimiter = " | ";
using namespace NST::API::SMBv2;
namespace 
{ 
    template<typename T>
    inline bool operator&(T lhs, T rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    } 
} 

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::OplockLevels value)
{
    switch (value)
    {
        case OplockLevels::NONE:      os << "NONE";break;
        case OplockLevels::II:        os << "II";break;
        case OplockLevels::EXCLUSIVE: os << "EXCLUSIVE";break;
        case OplockLevels::BATCH:     os << "BATCH";break;
        case OplockLevels::LEASE:     os << "LEASE";break;
        default: 
        assert("Cannot convert OplockLevels value into string representation.");
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ImpersonationLevels value)
{
    switch (value)
    {
        case ImpersonationLevels::ANONYMOUS:        os << "ANONYMOUS";break;
        case ImpersonationLevels::IDENTIFICATION:   os << "IDENTIFICATION";break;
        case ImpersonationLevels::IMPERSONATION:    os << "IMPERSONATION";break;
        case ImpersonationLevels::DELEGATE:         os << "DELEGATE";break;
        default:
        assert("Cannot convert ImpersonationLevels value into string representation.");
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CreateDisposition value)
{
    switch(value)
    {
        case CreateDisposition::SUPERSEDE:       os << "SUPERSEDE";break;
        case CreateDisposition::OPEN:            os << "OPEN";break; 
        case CreateDisposition::CREATE:          os << "CREATE";break;
        case CreateDisposition::OPEN_IF:         os << "OPEN_IF";break;
        case CreateDisposition::OVERWRITE:       os << "OVERWRITE";break;
        case CreateDisposition::OVERWRITE_IF:    os << "OVERWRITE_IF";break;
        default:
        assert("Cannot convert CreateDisposition value into string representation.");
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CreateActions value)
{
    switch(value)
    {
        case CreateActions::SUPERSEDED:          os << "SUPERSEDED";break;
        case CreateActions::OPENED:              os << "OPENED";break;
        case CreateActions::CREATED:             os << "CREATED";break;
        case CreateActions::FILE_OVERWRITTEN:    os << "FILE_OVERWRITTEN";break;
        default: 
        assert("Cannot convert CreateActions into string representation.");
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareTypes value)
{ 
    using namespace NST::API::SMBv2;
    switch(value)
    {
        case ShareTypes::DISK:        os << "SMB2_SHARE_TYPE_DISK";break;
        case ShareTypes::PIPE:        os << "SMB2_SHARE_TYPE_PIPE";break;
        case ShareTypes::PRINT:       os << "SMB2_SHARE_TYPE_PRINT";break;
        default:
        assert("Cannot conver ShareTypes value into string representation.");
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::NTStatus value)
{ 
    using namespace NST::API::SMBv2;
    switch(value)
    {
        case NTStatus::STATUS_SUCCESS:                  os << "STATUS_SUCCESS";break;
        case NTStatus::STATUS_NO_MORE_FILES:            os << "STATUS_NO_MORE_FILES";break;
        case NTStatus::STATUS_INVALID_HANDLE:           os << "STATUS_INVALID_HANDLE";break;
        case NTStatus::STATUS_INVALID_PARAMETER:        os << "STATUS_INVALID_PARAMETER";break;
        case NTStatus::STATUS_NO_SUCH_FILE:             os << "STATUS_NO_SUCH_FILE";break;
        case NTStatus::STATUS_MORE_PROCESSING_REQUIRED: os << "STATUS_MORE_PROCESSING_REQUIRED";break;
        case NTStatus::STATUS_INVALID_SYSTEM_SERVICE:   os << "STATUS_INVALID_SYSTEM_SERVICE";break;
        case NTStatus::STATUS_ACCESS_DENIED:            os << "STATUS_ACCESS_DENIED";break;
        case NTStatus::STATUS_OBJECT_NAME_INVALID:      os << "STATUS_OBJECT_NAME_INVALID";break;
        case NTStatus::STATUS_OBJECT_NAME_NOT_FOUND:    os << "STATUS_OBJECT_NAME_NOT_FOUND";break;
        case NTStatus::STATUS_OBJECT_NAME_COLLISION:    os << "STATUS_OBJECT_NAME_COLLISION";break;
        case NTStatus::STATUS_OBJECT_PATH_NOT_FOUND:    os << "STATUS_OBJECT_PATH_NOT_FOUND";break;
        case NTStatus::STATUS_OBJECT_PATH_SYNTAX_BAD:   os << "STATUS_OBJECT_PATH_SYNTAX_BAD";break;
        case NTStatus::STATUS_SHARING_VIOLATION:        os << "STATUS_SHARING_VIOLATION";break;
        case NTStatus::STATUS_EA_TOO_LARGE:             os << "STATUS_EA_TOO_LARGE";break;
        case NTStatus::STATUS_FILE_LOCK_CONFLICT:       os << "STATUS_FILE_LOCK_CONFLICT";break;
        case NTStatus::STATUS_LOCK_NOT_GRANTED:         os << "STATUS_LOCK_NOT_GRANTED";break;
        case NTStatus::STATUS_LOGON_FAILURE:            os << "STATUS_LOGON_FAILURE";break;
        case NTStatus::STATUS_RANGE_NOT_LOCKED:         os << "STATUS_RANGE_NOT_LOCKED";break;
        case NTStatus::STATUS_FILE_IS_A_DIRECTORY:      os << "STATUS_FILE_IS_A_DIRECTORY";break;
        case NTStatus::STATUS_NOT_SUPPORTED:            os << "STATUS_NOT_SUPPORTED";break;
        case NTStatus::STATUS_BAD_DEVICE_TYPE:          os << "STATUS_BAD_DEVICE_TYPE";break;
        case NTStatus::STATUS_REQUEST_NOT_ACCEPTED:     os << "STATUS_REQUEST_NOT_ACCEPTED";break;
        case NTStatus::STATUS_DIRECTORY_NOT_EMPTY:      os << "STATUS_DIRECTORY_NOT_EMPTY";break;
        case NTStatus::STATUS_NOT_A_DIRECTORY:          os << "STATUS_NOT_A_DIRECTORY";break;
        case NTStatus::STATUS_CANCELLED:                os << "STATUS_CANCELLED";break;
        default:
        assert("Cannot conver NTStatus value into string representation.");
    } 

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::DesiredAccessFlags value)
{
    std::ostringstream str;
    if (value & DesiredAccessFlags::READ_DATA_LE)
    {
        str << "READ_DATA_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::WRITE_DATA_LE)
    {
        str << "WRITE_DATA_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::APPEND_DATA_LE)
    {
        str << "APPEND_DATA_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::READ_EA_LE)
    {
        str << "READ_EA_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::WRITE_EA_LE)
    {
        str << "WRITE_EA_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::EXECUTE_LE)
    {
        str << "EXECUTE_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::READ_ATTRIBUTES_LE)
    {
        str << "READ_ATTRIBUTES_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::WRITE_ATTRIBUTES_LE)
    {
        str << "WRITE_ATTRIBUTES_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::DELETE_LE)
    {
        str << "DELETE_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::READ_CONTROL_LE)
    {
        str << "READ_CONTROL_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::WRITE_DAC_LE)
    {
        str << "WRITE_DAC_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::WRITE_OWNER_LE)
    {
        str << "WRITE_OWNER_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::SYNCHRONIZE_LE)
    {
        str << "SYNCHRONIZE_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::ACCESS_SYSTEM_SECURITY_LE)
    {
        str << "ACCESS_SYSTEM_SECURITY_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::MAXIMAL_ACCESS_LE)
    {
        str << "MAXIMAL_ACCESS_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::GENERIC_ALL_LE)
    {
        str << "GENERIC_ALL_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::GENERIC_EXECUTE_LE)
    {
        str << "GENERIC_EXECUTE_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::GENERIC_WRITE_LE)
    {
        str << "GENERIC_WRITE_LE" << flagDelimiter;
    }
    if (value & DesiredAccessFlags::GENERIC_READ_LE)
    {
        str << "GENERIC_READ_LE" << flagDelimiter;
    }

    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::FileAttributes value)
{
    std::ostringstream str;

    if (value & FileAttributes::READONLY)
    {
        str << "READONLY" << flagDelimiter;
    }
    if (value & FileAttributes::HIDDEN)
    {
        str << "HIDDEN" << flagDelimiter;
    }
    if (value & FileAttributes::SYSTEM)
    {
        str << "SYSTEM" << flagDelimiter;
    }
    if (value & FileAttributes::DIRECTORY)
    {
        str << "DIRECTORY" << flagDelimiter;
    }
    if (value & FileAttributes::ARCHIVE)
    {
        str << "ARCHIVE" << flagDelimiter;
    }
    if (value & FileAttributes::NORMAL)
    {
        str << "NORMAL" << flagDelimiter;
    }
    if (value & FileAttributes::TEMPORARY)
    {
        str << "TEMPORARY" << flagDelimiter;
    }
    if (value & FileAttributes::SPARSE_FILE)
    {
        str << "SPARSE_FILE" << flagDelimiter;
    }
    if (value & FileAttributes::REPARSE_POINT)
    {
        str << "REPARSE_POINT" << flagDelimiter;
    }
    if (value & FileAttributes::COMPRESSED)
    {
        str << "COMPRESSED" << flagDelimiter;
    }
    if (value & FileAttributes::OFFLINE)
    {
        str << "OFFLINE" << flagDelimiter;
    }
    if (value & FileAttributes::NOT_CONTENT_INDEXED)
    {
        str << "NOT_CONTENT_INDEXED" << flagDelimiter;
    }
    if (value & FileAttributes::ENCRYPTED)
    {
        str << "ENCRYPTED" << flagDelimiter;
    }

    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareAccessFlags value)
{
    std::ostringstream str;

    if (value & ShareAccessFlags::SHARE_READ_LE)
    {
        str << "SHARE_READ_LE" << flagDelimiter;
    }
    if (value & ShareAccessFlags::SHARE_WRITE_LE)
    {
        str << "SHARE_WRITE_LE" << flagDelimiter;
    }
    if (value & ShareAccessFlags::SHARE_DELETE_LE)
    {
        str << "SHARE_DELETE_LE" << flagDelimiter;
    }

    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CreateOptionsFlags value)
{
    std::ostringstream str;

    if (value & CreateOptionsFlags::DIRECTORY_FILE_LE)
    {
        str << "DIRECTORY_FILE_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::WRITE_THROUGH_LE)
    {
        str << "WRITE_THROUGH_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::SEQUENTIAL_ONLY_LE)
    {
        str << "SEQUENTIAL_ONLY_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::NO_INTERMEDIATE_BUFFERRING_LE)
    {
        str << "NO_INTERMEDIATE_BUFFERRING_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::SYNCHRONOUS_IO_ALERT_LE)
    {
        str << "SYNCHRONOUS_IO_ALERT_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::SYNCHRONOUS_IO_NON_ALERT_LE)
    {
        str << "SYNCHRONOUS_IO_NON_ALERT_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::NON_DIRECTORY_FILE_LE)
    {
        str << "NON_DIRECTORY_FILE_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::COMPLETE_IF_OPLOCKED_LE)
    {
        str << "COMPLETE_IF_OPLOCKED_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::NO_EA_KNOWLEDGE_LE)
    {
        str << "NO_EA_KNOWLEDGE_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::RANDOM_ACCESS_LE)
    {
        str << "RANDOM_ACCESS_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::DELETE_ON_CLOSE_LE)
    {
        str << "DELETE_ON_CLOSE_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::OPEN_BY_FILE_ID_LE)
    {
        str << "OPEN_BY_FILE_ID_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::OPEN_FOR_BACKUP_INTENT_LE)
    {
        str << "OPEN_FOR_BACKUP_INTENT_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::NO_COMPRESSION_LE)
    {
        str << "NO_COMPRESSION_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::RESERVE_OPFILTER_LE)
    {
        str << "RESERVE_OPFILTER_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::OPEN_REPARSE_POINT_LE)
    {
        str << "OPEN_REPARSE_POINT_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::OPEN_NO_RECALL_LE)
    {
        str << "OPEN_NO_RECALL_LE" << flagDelimiter;
    }
    if (value & CreateOptionsFlags::OPEN_FOR_FREE_SPACE_QUERY_LE)
    {
        str << "OPEN_FOR_FREE_SPACE_QUERY_LE" << flagDelimiter;
    }

    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::WriteFlags value)
{
    std::ostringstream str;

    if (value & WriteFlags::SMB2_WRITEFLAG_WRITE_THROUGH)
    {
        str << "SMB2_WRITEFLAG_WRITE_THROUGH" << flagDelimiter;
    }
    if (value & WriteFlags::SMB2_WRITEFLAG_WRITE_UNBUFFERED)
    {
        str << "SMB2_WRITEFLAG_WRITE_UNBUFFERED" << flagDelimiter;
    }

    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareFlags value)
{
    std::ostringstream str;
    if(value & ShareFlags::MANUAL_CACHING)
    {
        str << "SMB2_SHAREFLAG_MANUAL_CACHING " << flagDelimiter;
    } 
    if(value & ShareFlags::AUTO_CACHING)
    {
        str << "SMB2_SHAREFLAG_AUTO_CACHING" << flagDelimiter;
    } 
    if(value & ShareFlags::VDO_CACHING)
    {
        str << "SMB2_SHAREFLAG_VDO_CACHING" << flagDelimiter;
    } 
    if(value & ShareFlags::NO_CACHING)
    {
        str << "SMB2_SHAREFLAG_NO_CACHING" << flagDelimiter;
    } 
    if(value & (ShareFlags::DFS))
    {
        str << "SMB2_SHAREFLAG_DFS" << flagDelimiter;
    } 
    if(value & ShareFlags::DFS_ROOT)
    {
        str << "SMB2_SHAREFLAG_DFS_ROOT" << flagDelimiter;
    } 
    if(value & ShareFlags::RESTRICT_EXCLUSIVE_OPENS)
    {
        str << "SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS" << flagDelimiter;
    } 
    if(value & ShareFlags::FORCE_SHARED_DELETE)
    {
        str << "SMB2_SHAREFLAG_FORCE_SHARED_DELETE" << flagDelimiter;
    } 
    if(value & ShareFlags::ALLOW_NAMESPACE_CACHING)
    {
        str << "SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING" << flagDelimiter;
    } 
    if(value & ShareFlags::ACCESS_BASED_DIRECTORY_ENUM)
    {
        str << "SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM" << flagDelimiter;
    } 
    if(value & ShareFlags::FORCE_LEVELII_OPLOCK)
    {
        str << "SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK" << flagDelimiter;
    } 
    if(value & ShareFlags::ENABLE_HASH)
    {
        str << "SMB2_SHAREFLAG_ENABLE_HASH_V1" << flagDelimiter;
    } 
    if(value & ShareFlags::ENABLE_HASH_2)
    {
        str << "SMB2_SHAREFLAG_ENABLE_HASH_V2" << flagDelimiter;
    } 
    if(value & ShareFlags::ENABLE_ENCRYPT_DATA)
    {
        str << "SMB2_SHAREFLAG_ENCRYPT_DATA" << flagDelimiter;
    } 
    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::ShareCapabilities value)
{
    std::ostringstream str;
    if(value & ShareCapabilities::DFS)
    {
        str << "SMB2_SHARE_CAP_DFS" << flagDelimiter;
    } 
    if(value & ShareCapabilities::CONTINUOUS_AVAILABILITY)
    {
        str << "SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY" << flagDelimiter;
    } 
    if(value & ShareCapabilities::SCALEOUT)
    {
        str << "SMB2_SHARE_CAP_SCALEOUT" << flagDelimiter;
    } 
    if(value & ShareCapabilities::CLUSTER)
    {
        str << "SMB2_SHARE_CAP_CLUSTER" << flagDelimiter;
    } 
    if(value & ShareCapabilities::ASYMMETRIC)
    {
        str << "SMB2_SHARE_CAP_ASYMMETRIC" << flagDelimiter;
    } 
    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SecurityModeShort value)
{
    std::ostringstream str;
    if(value & SecurityModeShort::SIGNING_ENABLED)
    {
        str << "SIGNING_ENABLED" << flagDelimiter;
    } 
    if(value & SecurityModeShort::SIGNING_REQUIRED)
    {
        str << "SIGNING_REQUIRED" << flagDelimiter;
    } 
    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::Capabilities value)
{
    std::ostringstream str;
    if(value & Capabilities::DFS)
    {
        str << "DFS" << flagDelimiter;
    } 
    if(value & Capabilities::LEASING)
    {
        str << "LEASING" << flagDelimiter;
    } 
    if(value & Capabilities::LARGE_MTU)
    {
        str << "LARGE_MTU" << flagDelimiter;
    } 
    if(value & Capabilities::MULTI_CHANNEL)
    {
        str << "MULTI_CHANNEL" << flagDelimiter;
    } 
    if(value & Capabilities::PERSISTENT_HANDLES)
    {
        str << "PERSISTENT_HANDLES" << flagDelimiter;
    } 
    if(value & Capabilities::DIRECTORY_LEASING)
    {
        str << "DIRECTORY_LEASING" << flagDelimiter;
    } 
    if(value & Capabilities::ENCRYPTION)
    {
        str << "ENCRYPTION" << flagDelimiter;
    } 
    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SessionFlags value)
{
    std::ostringstream str;
    if(value & SessionFlags::NONE)
    {
        str << "NONE" << flagDelimiter;
    } 
    if(value & SessionFlags::IS_GUEST)
    {
        str << "SMB2_SESSION_FLAG_IS_GUEST" << flagDelimiter;
    } 
    if(value & SessionFlags::IS_NULL)
    {
        str << "SMB2_SESSION_FLAG_IS_NULL" << flagDelimiter;
    } 
    if(value & SessionFlags::IS_ENCRYPT_DATA)
    {
        str << "SMB2_SESSION_FLAG_ENCRYPT_DATA" << flagDelimiter;
    } 
    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::AccessMask value)
{
    std::ostringstream str;
    if(value & AccessMask::FILE_READ_DATA)
    {
        str << "FILE_READ_DATA" << flagDelimiter;
    } 
    if(value & AccessMask::FILE_WRITE_DATA)
    {
        str << "FILE_WRITE_DATA" << flagDelimiter;
    } 
    if(value & AccessMask::FILE_APPEND_DATA)
    {
        str << "FILE_APPEND_DATA" << flagDelimiter;
    } 
    if(value & AccessMask::FILE_READ_EA)
    {
        str << "FILE_READ_EA" << flagDelimiter;
    } 
    if(value & AccessMask::FILE_WRITE_EA)
    {
        str << "FILE_WRITE_EA" << flagDelimiter;
    } 
    if(value & AccessMask::FILE_DELETE_CHILD)
    {
        str << "FILE_DELETE_CHILD" << flagDelimiter;
    } 
    if(value & AccessMask::FILE_EXECUTE)
    {
        str << "FILE_EXECUTE" << flagDelimiter;
    } 
    if(value & AccessMask::FILE_READ_ATTRIBUTES)
    {
        str << "FILE_READ_ATTRIBUTES" << flagDelimiter;
    } 
    if(value & AccessMask::FILE_WRITE_ATTRIBUTES)
    {
        str << "FILE_WRITE_ATTRIBUTES" << flagDelimiter;
    } 
    if(value & AccessMask::DELETE)
    {
        str << "DELETE" << flagDelimiter;
    } 
    if(value & AccessMask::READ_CONTROL)
    {
        str << "READ_CONTROL" << flagDelimiter;
    } 
    if(value & AccessMask::WRITE_DAC)
    {
        str << "WRITE_DAC" << flagDelimiter;
    } 
    if(value & AccessMask::WRITE_OWNER)
    {
        str << "WRITE_OWNER" << flagDelimiter;
    } 
    if(value & AccessMask::SYNCHRONIZE)
    {
        str << "SYNCHRONIZE" << flagDelimiter;
    } 
    if(value & AccessMask::ACCESS_SYSTEM_SECURITY)
    {
        str << "ACCESS_SYSTEM_SECURITY" << flagDelimiter;
    } 
    if(value & AccessMask::MAXIMUM_ALLOWED)
    {
        str << "MAXIMUM_ALLOWED" << flagDelimiter;
    } 
    if(value & AccessMask::GENERIC_ALL)
    {
        str << "GENERIC_ALL" << flagDelimiter;
    } 
    if(value & AccessMask::GENERIC_EXECUTE)
    {
        str << "GENERIC_EXECUTE" << flagDelimiter;
    } 
    if(value & AccessMask::GENERIC_WRITE)
    {
        str << "GENERIC_WRITE" << flagDelimiter;
    } 
    if(value & AccessMask::GENERIC_READ)
    {
        str << "GENERIC_READ" << flagDelimiter;
    } 
    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CloseFlags value)
{
    using namespace NST::API::SMBv2;
    std::ostringstream str;

    if (value & CloseFlags::POSTQUERY_ATTRIB)
    {
        os << "POSTQUERY_ATTRIB";
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SecurityMode value)
{
    std::ostringstream str;

    if (value & SecurityMode::SIGNING_ENABLED)
    {
        str << "SIGNING_ENABLED" << flagDelimiter;
    }
    if (value & SecurityMode::SIGNING_REQUIRED)
    {
        str << "SIGNING_REQUIRED" << flagDelimiter;
    }

    os << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::FsInfoLevels value)
{
    switch(value)
    {
        case FsInfoLevels::SMB2_FS_INFO_01: os << "SMB2_FS_INFO_01";break;
        case FsInfoLevels::SMB2_FS_INFO_02: os << "SMB2_FS_INFO_02";break;
        case FsInfoLevels::SMB2_FS_INFO_03: os << "SMB2_FS_INFO_03";break;
        case FsInfoLevels::SMB2_FS_INFO_04: os << "SMB2_FS_INFO_04";break;
        case FsInfoLevels::SMB2_FS_INFO_05: os << "SMB2_FS_INFO_05";break;
        case FsInfoLevels::SMB2_FS_INFO_06: os << "SMB2_FS_INFO_06";break;
        case FsInfoLevels::SMB2_FS_INFO_07: os << "SMB2_FS_INFO_07";break;
        default:
        assert("Cannot convert FsInfoLevels value into string representation.");
    } 
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::QueryInfoLevels value)
{
    switch(value)
    {
        case QueryInfoLevels::DIRECTORY_INFORMATION:             os << "DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::FULL_DIRECTORY_INFORMATION:        os << "FULL_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::BOTH_DIRECTORY_INFORMATION:        os << "BOTH_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::BASIC_INFORMATION:                 os << "BASIC_INFORMATION";break;
        case QueryInfoLevels::STANDARD_INFORMATION:              os << "STANDARD_INFORMATION";break;
        case QueryInfoLevels::INTERNAL_INFORMATION:              os << "INTERNAL_INFORMATION";break;
        case QueryInfoLevels::EA_INFORMATION:                    os << "EA_INFORMATION";break;
        case QueryInfoLevels::ACCESS_INFORMATION:                os << "ACCESS_INFORMATION";break;
        case QueryInfoLevels::NAME_INFORMATION:                  os << "NAME_INFORMATION";break;
        case QueryInfoLevels::RENAME_INFORMATION:                os << "RENAME_INFORMATION";break;
        case QueryInfoLevels::LINK_INFORMATION:                  os << "LINK_INFORMATION";break;
        case QueryInfoLevels::NAMES_INFORMATION:                 os << "NAMES_INFORMATION";break;
        case QueryInfoLevels::DISPOSITION_INFORMATION:           os << "DISPOSITION_INFORMATION";break;
        case QueryInfoLevels::POSITION_INFORMATION:              os << "POSITION_INFORMATION";break;
        case QueryInfoLevels::FULL_EA_INFORMATION:               os << "FULL_EA_INFORMATION";break;
        case QueryInfoLevels::MODE_INFORMATION:                  os << "MODE_INFORMATION";break;
        case QueryInfoLevels::ALIGNMENT_INFORMATION:             os << "ALIGNMENT_INFORMATION";break;
        case QueryInfoLevels::ALL_INFORMATION:                   os << "ALL_INFORMATION";break;
        case QueryInfoLevels::ALLOCATION_INFORMATION:            os << "ALLOCATION_INFORMATION";break;
        case QueryInfoLevels::END_OF_FILE_INFORMATION:           os << "END_OF_FILE_INFORMATION";break;
        case QueryInfoLevels::ALTERNATE_NAME_INFORMATION:        os << "ALTERNATE_NAME_INFORMATION";break;
        case QueryInfoLevels::STREAM_INFORMATION:                os << "STREAM_INFORMATION";break;
        case QueryInfoLevels::PIPE_INFORMATION:                  os << "PIPE_INFORMATION";break;
        case QueryInfoLevels::PIPE_LOCAL_INFORMATION:            os << "PIPE_LOCAL_INFORMATION";break;
        case QueryInfoLevels::PIPE_REMOTE_INFORMATION:           os << "PIPE_REMOTE_INFORMATION";break;
        case QueryInfoLevels::MAILSLOT_QUERY_INFORMATION:        os << "MAILSLOT_QUERY_INFORMATION";break;
        case QueryInfoLevels::MAILSLOT_SET_INFORMATION:          os << "MAILSLOT_SET_INFORMATION";break;
        case QueryInfoLevels::COMPRESSION_INFORMATION:           os << "COMPRESSION_INFORMATION";break;
        case QueryInfoLevels::OBJECT_ID_INFORMATION:             os << "OBJECT_ID_INFORMATION";break;
        case QueryInfoLevels::MOVE_CLUSTER_INFORMATION:          os << "MOVE_CLUSTER_INFORMATION";break;
        case QueryInfoLevels::QUOTA_INFORMATION:                 os << "QUOTA_INFORMATION";break;
        case QueryInfoLevels::REPARSE_POINT_INFORMATION:         os << "REPARSE_POINT_INFORMATION";break;
        case QueryInfoLevels::NETWORK_OPEN_INFORMATION:          os << "NETWORK_OPEN_INFORMATION";break;
        case QueryInfoLevels::ATTRIBUTE_TAG_INFORMATION:         os << "ATTRIBUTE_TAG_INFORMATION";break;
        case QueryInfoLevels::TRACKING_INFORMATION:              os << "TRACKING_INFORMATION";break;
        case QueryInfoLevels::ID_BOTH_DIRECTORY_INFORMATION:     os << "ID_BOTH_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::ID_FULL_DIRECTORY_INFORMATION:     os << "ID_FULL_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::VALID_DATA_LENGTH_INFORMATION:     os << "VALID_DATA_LENGTH_INFORMATION";break;
        case QueryInfoLevels::SHORT_NAME_INFORMATION:            os << "SHORT_NAME_INFORMATION";break;
        case QueryInfoLevels::SFIO_RESERVE_INFORMATION:          os << "SFIO_RESERVE_INFORMATION";break;
        case QueryInfoLevels::SFIO_VOLUME_INFORMATION:           os << "SFIO_VOLUME_INFORMATION";break;
        case QueryInfoLevels::HARD_LINK_INFORMATION:             os << "HARD_LINK_INFORMATION";break;
        case QueryInfoLevels::NORMALIZED_NAME_INFORMATION:       os << "NORMALIZED_NAME_INFORMATION";break;
        case QueryInfoLevels::ID_GLOBAL_TX_DIRECTORY_INFORMATION:os << "ID_GLOBAL_TX_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::STANDARD_LINK_INFORMATION:         os << "STANDARD_LINK_INFORMATION";break;
        default: 
        assert("Cannot convert QueryInfoLevels value into string representation.");
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::CtlCodes value)
{
    using namespace NST::API::SMBv2;
    switch(value)
    {
        case CtlCodes::SCTL_DFS_GET_REFERRALS:              os << "SCTL_DFS_GET_REFERRALS";break;
        case CtlCodes::FSCTL_PIPE_PEEK:                     os << "FSCTL_PIPE_PEEK";break;
        case CtlCodes::FSCTL_PIPE_WAIT:                     os << "FSCTL_PIPE_WAIT";break;
        case CtlCodes::FSCTL_PIPE_TRANSCEIVE:               os << "FSCTL_PIPE_TRANSCEIVE";break;
        case CtlCodes::FSCTL_SRV_COPYCHUNK:                 os << "FSCTL_SRV_COPYCHUNK";break;
        case CtlCodes::FSCTL_SRV_ENUMERATE_SNAPSHOTS:       os << "FSCTL_SRV_ENUMERATE_SNAPSHOTS";break;
        case CtlCodes::FSCTL_SRV_REQUEST_RESUME_KEY:        os << "FSCTL_SRV_REQUEST_RESUME_KEY";break;
        case CtlCodes::FSCTL_SRV_READ_HASH:                 os << "FSCTL_SRV_READ_HASH";break;
        case CtlCodes::FSCTL_SRV_COPYCHUNK_WRITE:           os << "FSCTL_SRV_COPYCHUNK_WRITE";break;
        case CtlCodes::FSCTL_LMR_REQUEST_RESILIENCY:        os << "FSCTL_LMR_REQUEST_RESILIENCY";break;
        case CtlCodes::FSCTL_QUERY_NETWORK_INTERFACE_INFO:  os << "FSCTL_QUERY_NETWORK_INTERFACE_INFO";break;
        case CtlCodes::FSCTL_SET_REPARSE_POINT:             os << "FSCTL_SET_REPARSE_POINT";break;
        case CtlCodes::FSCTL_DFS_GET_REFERRALS_EX:          os << "FSCTL_DFS_GET_REFERRALS_EX";break;
        case CtlCodes::FSCTL_FILE_LEVEL_TRIM:               os << "FSCTL_FILE_LEVEL_TRIM";break;
        case CtlCodes::FSCTL_VALIDATE_NEGOTIATE_INFO:       os << "FSCTL_VALIDATE_NEGOTIATE_INFO";break;
        default: 
        assert("Cannot convert CtlCodes value into string representation.");
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::InfoTypes value)
{
    using namespace NST::API::SMBv2;
    switch(value)
    {
        case InfoTypes::FILE:              os << "SMB2_0_INFO_FILE";break;
        case InfoTypes::FILESYSTEM:        os << "SMB2_0_INFO_FILESYSTEM";break;
        case InfoTypes::SECURITY:          os << "SMB2_0_INFO_SECURITY";break;
        case InfoTypes::QUOTA:             os << "SMB2_0_INFO_QUOTA";break;
        default: 
        assert("Cannot convert InfoTypes value into string representation.");
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const NST::API::SMBv2::SessionFlagsBinding value)
{
    using namespace NST::API::SMBv2;
    switch(value)
    {
        case SessionFlagsBinding::NONE:     os << "NONE";break;
        case SessionFlagsBinding::BINDING:  os << "BINDING";break;
        default: 
        assert("Cannot convert SessionFlagsBinding value into string representation.");
    }
    return os;
} 

void print_info_levels(std::ostream& os, const NST::API::SMBv2::InfoTypes infoType, const uint8_t infoClass)
{
    using namespace NST::API::SMBv2;
    switch(infoType)
    {
        case InfoTypes::FILE:
            print_enum(os, "InfoLevel", static_cast<QueryInfoLevels>(infoClass));
            break;
        case InfoTypes::FILESYSTEM:
            print_enum(os, "InfoLevel", static_cast<FsInfoLevels>(infoClass));
            break;
        default:
            //we dont handle other classes
            ;
    }
} 
} // namespace CIFSv2
} // namespace protocols
} // namespace NST

