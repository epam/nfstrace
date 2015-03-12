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
#include <bitset>
#include <sstream>

#include "cifs2_utils.h"
#include "protocols/nfs/nfs_utils.h"
//------------------------------------------------------------------------------
static const std::string flagDelimiter = " | ";
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace CIFSv2
{
using namespace NST::API::SMBv2;

namespace 
{ 
    template<typename T>
    inline bool operator&(T lhs, T rhs)
    {
        return to_integral(lhs) & to_integral(rhs);
    } 
} 

std::ostream& operator<<(std::ostream& out, const OplockLevels value)
{
    switch (value)
    {
        case OplockLevels::NONE:      out << "NONE";break;
        case OplockLevels::II:        out << "II";break;
        case OplockLevels::EXCLUSIVE: out << "EXCLUSIVE";break;
        case OplockLevels::BATCH:     out << "BATCH";break;
        case OplockLevels::LEASE:     out << "LEASE";break;
        default: 
        assert("Cannot convert OplockLevels value into string representation.");
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const ImpersonationLevels value)
{
    switch (value)
    {
        case ImpersonationLevels::ANONYMOUS:        out << "ANONYMOUS";break;
        case ImpersonationLevels::IDENTIFICATION:   out << "IDENTIFICATION";break;
        case ImpersonationLevels::IMPERSONATION:    out << "IMPERSONATION";break;
        case ImpersonationLevels::DELEGATE:         out << "DELEGATE";break;
        default:
        assert("Cannot convert ImpersonationLevels value into string representation.");
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const CreateDisposition value)
{
    switch(value)
    {
        case CreateDisposition::SUPERSEDE:       out << "SUPERSEDE";break;
        case CreateDisposition::OPEN:            out << "OPEN";break;
        case CreateDisposition::CREATE:          out << "CREATE";break;
        case CreateDisposition::OPEN_IF:         out << "OPEN_IF";break;
        case CreateDisposition::OVERWRITE:       out << "OVERWRITE";break;
        case CreateDisposition::OVERWRITE_IF:    out << "OVERWRITE_IF";break;
        default:
        assert("Cannot convert CreateDisposition value into string representation.");
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const CreateActions value)
{
    switch(value)
    {
        case CreateActions::SUPERSEDED:          out << "SUPERSEDED";break;
        case CreateActions::OPENED:              out << "OPENED";break;
        case CreateActions::CREATED:             out << "CREATED";break;
        case CreateActions::FILE_OVERWRITTEN:    out << "FILE_OVERWRITTEN";break;
        default: 
        assert("Cannot convert CreateActions into string representation.");
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const ShareTypes value)
{ 
    switch(value)
    {
        case ShareTypes::DISK:        out << "SMB2_SHARE_TYPE_DISK";break;
        case ShareTypes::PIPE:        out << "SMB2_SHARE_TYPE_PIPE";break;
        case ShareTypes::PRINT:       out << "SMB2_SHARE_TYPE_PRINT";break;
        default:
        assert("Cannot conver ShareTypes value into string representation.");
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const NTStatus value)
{ 
    switch(value)
    {
        case NTStatus::STATUS_SUCCESS:                  out << "STATUS_SUCCESS";break;
        case NTStatus::STATUS_NO_MORE_FILES:            out << "STATUS_NO_MORE_FILES";break;
        case NTStatus::STATUS_INVALID_HANDLE:           out << "STATUS_INVALID_HANDLE";break;
        case NTStatus::STATUS_INVALID_PARAMETER:        out << "STATUS_INVALID_PARAMETER";break;
        case NTStatus::STATUS_NO_SUCH_FILE:             out << "STATUS_NO_SUCH_FILE";break;
        case NTStatus::STATUS_MORE_PROCESSING_REQUIRED: out << "STATUS_MORE_PROCESSING_REQUIRED";break;
        case NTStatus::STATUS_INVALID_SYSTEM_SERVICE:   out << "STATUS_INVALID_SYSTEM_SERVICE";break;
        case NTStatus::STATUS_ACCESS_DENIED:            out << "STATUS_ACCESS_DENIED";break;
        case NTStatus::STATUS_OBJECT_NAME_INVALID:      out << "STATUS_OBJECT_NAME_INVALID";break;
        case NTStatus::STATUS_OBJECT_NAME_NOT_FOUND:    out << "STATUS_OBJECT_NAME_NOT_FOUND";break;
        case NTStatus::STATUS_OBJECT_NAME_COLLISION:    out << "STATUS_OBJECT_NAME_COLLISION";break;
        case NTStatus::STATUS_OBJECT_PATH_NOT_FOUND:    out << "STATUS_OBJECT_PATH_NOT_FOUND";break;
        case NTStatus::STATUS_OBJECT_PATH_SYNTAX_BAD:   out << "STATUS_OBJECT_PATH_SYNTAX_BAD";break;
        case NTStatus::STATUS_SHARING_VIOLATION:        out << "STATUS_SHARING_VIOLATION";break;
        case NTStatus::STATUS_EA_TOO_LARGE:             out << "STATUS_EA_TOO_LARGE";break;
        case NTStatus::STATUS_FILE_LOCK_CONFLICT:       out << "STATUS_FILE_LOCK_CONFLICT";break;
        case NTStatus::STATUS_LOCK_NOT_GRANTED:         out << "STATUS_LOCK_NOT_GRANTED";break;
        case NTStatus::STATUS_LOGON_FAILURE:            out << "STATUS_LOGON_FAILURE";break;
        case NTStatus::STATUS_RANGE_NOT_LOCKED:         out << "STATUS_RANGE_NOT_LOCKED";break;
        case NTStatus::STATUS_FILE_IS_A_DIRECTORY:      out << "STATUS_FILE_IS_A_DIRECTORY";break;
        case NTStatus::STATUS_NOT_SUPPORTED:            out << "STATUS_NOT_SUPPORTED";break;
        case NTStatus::STATUS_BAD_DEVICE_TYPE:          out << "STATUS_BAD_DEVICE_TYPE";break;
        case NTStatus::STATUS_REQUEST_NOT_ACCEPTED:     out << "STATUS_REQUEST_NOT_ACCEPTED";break;
        case NTStatus::STATUS_DIRECTORY_NOT_EMPTY:      out << "STATUS_DIRECTORY_NOT_EMPTY";break;
        case NTStatus::STATUS_NOT_A_DIRECTORY:          out << "STATUS_NOT_A_DIRECTORY";break;
        case NTStatus::STATUS_CANCELLED:                out << "STATUS_CANCELLED";break;
        default:
        assert("Cannot conver NTStatus value into string representation.");
    } 

    return out;
}

std::ostream& operator<<(std::ostream& out, const DesiredAccessFlags value)
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

    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const FileAttributes value)
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

    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const ShareAccessFlags value)
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

    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const CreateOptionsFlags value)
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

    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const WriteFlags value)
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

    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const ShareFlags value)
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
    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const ShareCapabilities value)
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
    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const SecurityModeShort value)
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
    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const Capabilities value)
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
    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const SessionFlags value)
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
    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const AccessMask value)
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
    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const CloseFlags value)
{
    std::ostringstream str;

    if (value & CloseFlags::POSTQUERY_ATTRIB)
    {
        out << "POSTQUERY_ATTRIB";
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const SecurityMode value)
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

    out << ClearFromLastDelimiter(str.str(), flagDelimiter);
    return out;
}

std::ostream& operator<<(std::ostream& out, const FsInfoLevels value)
{
    switch(value)
    {
        case FsInfoLevels::SMB2_FS_INFO_01: out << "SMB2_FS_INFO_01";break;
        case FsInfoLevels::SMB2_FS_INFO_02: out << "SMB2_FS_INFO_02";break;
        case FsInfoLevels::SMB2_FS_INFO_03: out << "SMB2_FS_INFO_03";break;
        case FsInfoLevels::SMB2_FS_INFO_04: out << "SMB2_FS_INFO_04";break;
        case FsInfoLevels::SMB2_FS_INFO_05: out << "SMB2_FS_INFO_05";break;
        case FsInfoLevels::SMB2_FS_INFO_06: out << "SMB2_FS_INFO_06";break;
        case FsInfoLevels::SMB2_FS_INFO_07: out << "SMB2_FS_INFO_07";break;
        default:
        assert("Cannot convert FsInfoLevels value into string representation.");
    } 
    return out;
}

std::ostream& operator<<(std::ostream& out, const QueryInfoLevels value)
{
    switch(value)
    {
        case QueryInfoLevels::DIRECTORY_INFORMATION:             out << "DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::FULL_DIRECTORY_INFORMATION:        out << "FULL_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::BOTH_DIRECTORY_INFORMATION:        out << "BOTH_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::BASIC_INFORMATION:                 out << "BASIC_INFORMATION";break;
        case QueryInfoLevels::STANDARD_INFORMATION:              out << "STANDARD_INFORMATION";break;
        case QueryInfoLevels::INTERNAL_INFORMATION:              out << "INTERNAL_INFORMATION";break;
        case QueryInfoLevels::EA_INFORMATION:                    out << "EA_INFORMATION";break;
        case QueryInfoLevels::ACCESS_INFORMATION:                out << "ACCESS_INFORMATION";break;
        case QueryInfoLevels::NAME_INFORMATION:                  out << "NAME_INFORMATION";break;
        case QueryInfoLevels::RENAME_INFORMATION:                out << "RENAME_INFORMATION";break;
        case QueryInfoLevels::LINK_INFORMATION:                  out << "LINK_INFORMATION";break;
        case QueryInfoLevels::NAMES_INFORMATION:                 out << "NAMES_INFORMATION";break;
        case QueryInfoLevels::DISPOSITION_INFORMATION:           out << "DISPOSITION_INFORMATION";break;
        case QueryInfoLevels::POSITION_INFORMATION:              out << "POSITION_INFORMATION";break;
        case QueryInfoLevels::FULL_EA_INFORMATION:               out << "FULL_EA_INFORMATION";break;
        case QueryInfoLevels::MODE_INFORMATION:                  out << "MODE_INFORMATION";break;
        case QueryInfoLevels::ALIGNMENT_INFORMATION:             out << "ALIGNMENT_INFORMATION";break;
        case QueryInfoLevels::ALL_INFORMATION:                   out << "ALL_INFORMATION";break;
        case QueryInfoLevels::ALLOCATION_INFORMATION:            out << "ALLOCATION_INFORMATION";break;
        case QueryInfoLevels::END_OF_FILE_INFORMATION:           out << "END_OF_FILE_INFORMATION";break;
        case QueryInfoLevels::ALTERNATE_NAME_INFORMATION:        out << "ALTERNATE_NAME_INFORMATION";break;
        case QueryInfoLevels::STREAM_INFORMATION:                out << "STREAM_INFORMATION";break;
        case QueryInfoLevels::PIPE_INFORMATION:                  out << "PIPE_INFORMATION";break;
        case QueryInfoLevels::PIPE_LOCAL_INFORMATION:            out << "PIPE_LOCAL_INFORMATION";break;
        case QueryInfoLevels::PIPE_REMOTE_INFORMATION:           out << "PIPE_REMOTE_INFORMATION";break;
        case QueryInfoLevels::MAILSLOT_QUERY_INFORMATION:        out << "MAILSLOT_QUERY_INFORMATION";break;
        case QueryInfoLevels::MAILSLOT_SET_INFORMATION:          out << "MAILSLOT_SET_INFORMATION";break;
        case QueryInfoLevels::COMPRESSION_INFORMATION:           out << "COMPRESSION_INFORMATION";break;
        case QueryInfoLevels::OBJECT_ID_INFORMATION:             out << "OBJECT_ID_INFORMATION";break;
        case QueryInfoLevels::MOVE_CLUSTER_INFORMATION:          out << "MOVE_CLUSTER_INFORMATION";break;
        case QueryInfoLevels::QUOTA_INFORMATION:                 out << "QUOTA_INFORMATION";break;
        case QueryInfoLevels::REPARSE_POINT_INFORMATION:         out << "REPARSE_POINT_INFORMATION";break;
        case QueryInfoLevels::NETWORK_OPEN_INFORMATION:          out << "NETWORK_OPEN_INFORMATION";break;
        case QueryInfoLevels::ATTRIBUTE_TAG_INFORMATION:         out << "ATTRIBUTE_TAG_INFORMATION";break;
        case QueryInfoLevels::TRACKING_INFORMATION:              out << "TRACKING_INFORMATION";break;
        case QueryInfoLevels::ID_BOTH_DIRECTORY_INFORMATION:     out << "ID_BOTH_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::ID_FULL_DIRECTORY_INFORMATION:     out << "ID_FULL_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::VALID_DATA_LENGTH_INFORMATION:     out << "VALID_DATA_LENGTH_INFORMATION";break;
        case QueryInfoLevels::SHORT_NAME_INFORMATION:            out << "SHORT_NAME_INFORMATION";break;
        case QueryInfoLevels::SFIO_RESERVE_INFORMATION:          out << "SFIO_RESERVE_INFORMATION";break;
        case QueryInfoLevels::SFIO_VOLUME_INFORMATION:           out << "SFIO_VOLUME_INFORMATION";break;
        case QueryInfoLevels::HARD_LINK_INFORMATION:             out << "HARD_LINK_INFORMATION";break;
        case QueryInfoLevels::NORMALIZED_NAME_INFORMATION:       out << "NORMALIZED_NAME_INFORMATION";break;
        case QueryInfoLevels::ID_GLOBAL_TX_DIRECTORY_INFORMATION:out << "ID_GLOBAL_TX_DIRECTORY_INFORMATION";break;
        case QueryInfoLevels::STANDARD_LINK_INFORMATION:         out << "STANDARD_LINK_INFORMATION";break;
        default: 
        assert("Cannot convert QueryInfoLevels value into string representation.");
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const CtlCodes value)
{
    switch(value)
    {
        case CtlCodes::SCTL_DFS_GET_REFERRALS:              out << "SCTL_DFS_GET_REFERRALS";break;
        case CtlCodes::FSCTL_PIPE_PEEK:                     out << "FSCTL_PIPE_PEEK";break;
        case CtlCodes::FSCTL_PIPE_WAIT:                     out << "FSCTL_PIPE_WAIT";break;
        case CtlCodes::FSCTL_PIPE_TRANSCEIVE:               out << "FSCTL_PIPE_TRANSCEIVE";break;
        case CtlCodes::FSCTL_SRV_COPYCHUNK:                 out << "FSCTL_SRV_COPYCHUNK";break;
        case CtlCodes::FSCTL_SRV_ENUMERATE_SNAPSHOTS:       out << "FSCTL_SRV_ENUMERATE_SNAPSHOTS";break;
        case CtlCodes::FSCTL_SRV_REQUEST_RESUME_KEY:        out << "FSCTL_SRV_REQUEST_RESUME_KEY";break;
        case CtlCodes::FSCTL_SRV_READ_HASH:                 out << "FSCTL_SRV_READ_HASH";break;
        case CtlCodes::FSCTL_SRV_COPYCHUNK_WRITE:           out << "FSCTL_SRV_COPYCHUNK_WRITE";break;
        case CtlCodes::FSCTL_LMR_REQUEST_RESILIENCY:        out << "FSCTL_LMR_REQUEST_RESILIENCY";break;
        case CtlCodes::FSCTL_QUERY_NETWORK_INTERFACE_INFO:  out << "FSCTL_QUERY_NETWORK_INTERFACE_INFO";break;
        case CtlCodes::FSCTL_SET_REPARSE_POINT:             out << "FSCTL_SET_REPARSE_POINT";break;
        case CtlCodes::FSCTL_DFS_GET_REFERRALS_EX:          out << "FSCTL_DFS_GET_REFERRALS_EX";break;
        case CtlCodes::FSCTL_FILE_LEVEL_TRIM:               out << "FSCTL_FILE_LEVEL_TRIM";break;
        case CtlCodes::FSCTL_VALIDATE_NEGOTIATE_INFO:       out << "FSCTL_VALIDATE_NEGOTIATE_INFO";break;
        default: 
        assert("Cannot convert CtlCodes value into string representation.");
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const InfoTypes value)
{
    switch(value)
    {
        case InfoTypes::FILE:              out << "SMB2_0_INFO_FILE";break;
        case InfoTypes::FILESYSTEM:        out << "SMB2_0_INFO_FILESYSTEM";break;
        case InfoTypes::SECURITY:          out << "SMB2_0_INFO_SECURITY";break;
        case InfoTypes::QUOTA:             out << "SMB2_0_INFO_QUOTA";break;
        default: 
        assert("Cannot convert InfoTypes value into string representation.");
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const SessionFlagsBinding value)
{
    switch(value)
    {
        case SessionFlagsBinding::NONE:     out << "NONE";break;
        case SessionFlagsBinding::BINDING:  out << "BINDING";break;
        default: 
        assert("Cannot convert SessionFlagsBinding value into string representation.");
    }
    return out;
} 

void print_info_levels(std::ostream& out, const InfoTypes infoType, const uint8_t infoClass)
{
    switch(infoType)
    {
        case InfoTypes::FILE:
            print_enum(out, "InfoLevel", static_cast<QueryInfoLevels>(infoClass));
            break;
        case InfoTypes::FILESYSTEM:
            print_enum(out, "InfoLevel", static_cast<FsInfoLevels>(infoClass));
            break;
        default:
            //we dont handle other classes
            ;
    }
} 
} // namespace CIFSv2
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
