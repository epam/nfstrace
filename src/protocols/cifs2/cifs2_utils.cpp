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
#include <iostream>
#include <type_traits>

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

std::ostream& operator<<(std::ostream& out, const OplockLevels value)
{
    switch (value)
    {
        case OplockLevels::NONE:      return out << "NONE";
        case OplockLevels::II:        return out << "II";
        case OplockLevels::EXCLUSIVE: return out << "EXCLUSIVE";
        case OplockLevels::BATCH:     return out << "BATCH";
        case OplockLevels::LEASE:     return out << "LEASE";
        default:
            // empty default block
            ;
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const ImpersonationLevels value)
{
    switch (value)
    {
        case ImpersonationLevels::ANONYMOUS:        return out << "ANONYMOUS";
        case ImpersonationLevels::IDENTIFICATION:   return out << "IDENTIFICATION";
        case ImpersonationLevels::IMPERSONATION:    return out << "IMPERSONATION";
        case ImpersonationLevels::DELEGATE:         return out << "DELEGATE";
        default:
            // empty default block
            ;
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const CreateDisposition value)
{
    switch(value)
    {
        case CreateDisposition::SUPERSEDE:       return out << "SUPERSEDE";
        case CreateDisposition::OPEN:            return out << "OPEN";
        case CreateDisposition::CREATE:          return out << "CREATE";
        case CreateDisposition::OPEN_IF:         return out << "OPEN_IF";
        case CreateDisposition::OVERWRITE:       return out << "OVERWRITE";
        case CreateDisposition::OVERWRITE_IF:    return out << "OVERWRITE_IF";
        default:
            // empty default block
            ;
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const CreateActions value)
{
    switch(value)
    {
        case CreateActions::SUPERSEDED:          return out << "SUPERSEDED";
        case CreateActions::OPENED:              return out << "OPENED";
        case CreateActions::CREATED:             return out << "CREATED";
        case CreateActions::FILE_OVERWRITTEN:    return out << "FILE_OVERWRITTEN";
        default:
            // empty default block
            ;
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const ShareTypes value)
{ 
    switch(value)
    {
        case ShareTypes::DISK:  return out << "SMB2_SHARE_TYPE_DISK";
        case ShareTypes::PIPE:  return out << "SMB2_SHARE_TYPE_PIPE";
        case ShareTypes::PRINT: return out << "SMB2_SHARE_TYPE_PRINT";
        default:
            // empty default block
            ;
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const NTStatus value)
{ 
    switch(value)
    {
        case NTStatus::STATUS_SUCCESS:                  return out << "STATUS_SUCCESS";
        case NTStatus::STATUS_NO_MORE_FILES:            return out << "STATUS_NO_MORE_FILES";
        case NTStatus::STATUS_INVALID_HANDLE:           return out << "STATUS_INVALID_HANDLE";
        case NTStatus::STATUS_INVALID_PARAMETER:        return out << "STATUS_INVALID_PARAMETER";
        case NTStatus::STATUS_NO_SUCH_FILE:             return out << "STATUS_NO_SUCH_FILE";
        case NTStatus::STATUS_MORE_PROCESSING_REQUIRED: return out << "STATUS_MORE_PROCESSING_REQUIRED";
        case NTStatus::STATUS_INVALID_SYSTEM_SERVICE:   return out << "STATUS_INVALID_SYSTEM_SERVICE";
        case NTStatus::STATUS_ACCESS_DENIED:            return out << "STATUS_ACCESS_DENIED";
        case NTStatus::STATUS_OBJECT_NAME_INVALID:      return out << "STATUS_OBJECT_NAME_INVALID";
        case NTStatus::STATUS_OBJECT_NAME_NOT_FOUND:    return out << "STATUS_OBJECT_NAME_NOT_FOUND";
        case NTStatus::STATUS_OBJECT_NAME_COLLISION:    return out << "STATUS_OBJECT_NAME_COLLISION";
        case NTStatus::STATUS_OBJECT_PATH_NOT_FOUND:    return out << "STATUS_OBJECT_PATH_NOT_FOUND";
        case NTStatus::STATUS_OBJECT_PATH_SYNTAX_BAD:   return out << "STATUS_OBJECT_PATH_SYNTAX_BAD";
        case NTStatus::STATUS_SHARING_VIOLATION:        return out << "STATUS_SHARING_VIOLATION";
        case NTStatus::STATUS_EA_TOO_LARGE:             return out << "STATUS_EA_TOO_LARGE";
        case NTStatus::STATUS_FILE_LOCK_CONFLICT:       return out << "STATUS_FILE_LOCK_CONFLICT";
        case NTStatus::STATUS_LOCK_NOT_GRANTED:         return out << "STATUS_LOCK_NOT_GRANTED";
        case NTStatus::STATUS_LOGON_FAILURE:            return out << "STATUS_LOGON_FAILURE";
        case NTStatus::STATUS_RANGE_NOT_LOCKED:         return out << "STATUS_RANGE_NOT_LOCKED";
        case NTStatus::STATUS_FILE_IS_A_DIRECTORY:      return out << "STATUS_FILE_IS_A_DIRECTORY";
        case NTStatus::STATUS_NOT_SUPPORTED:            return out << "STATUS_NOT_SUPPORTED";
        case NTStatus::STATUS_BAD_DEVICE_TYPE:          return out << "STATUS_BAD_DEVICE_TYPE";
        case NTStatus::STATUS_REQUEST_NOT_ACCEPTED:     return out << "STATUS_REQUEST_NOT_ACCEPTED";
        case NTStatus::STATUS_DIRECTORY_NOT_EMPTY:      return out << "STATUS_DIRECTORY_NOT_EMPTY";
        case NTStatus::STATUS_NOT_A_DIRECTORY:          return out << "STATUS_NOT_A_DIRECTORY";
        case NTStatus::STATUS_CANCELLED:                return out << "STATUS_CANCELLED";
        default:
            // empty default block
            ;
    } 

    return out;
}

namespace
{
template <typename T>
void print_flag_if_set(std::ostream& out, const std::string& name, typename std::underlying_type<T>::type& value, T flag)
{
    auto int_flag = to_integral(flag);
    if (value & int_flag)
    {
        out << name;
        value = value & ~int_flag;
        if(value > 0)
            out << flagDelimiter;
    }
}
}

std::ostream& operator<<(std::ostream& out, const DesiredAccessFlags value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "READ_DATA_LE",                 int_value, DesiredAccessFlags::READ_DATA_LE);
    print_flag_if_set(out, "WRITE_DATA_LE",                int_value, DesiredAccessFlags::WRITE_DATA_LE);
    print_flag_if_set(out, "APPEND_DATA_LE",               int_value, DesiredAccessFlags::APPEND_DATA_LE);
    print_flag_if_set(out, "READ_EA_LE",                   int_value, DesiredAccessFlags::READ_EA_LE);
    print_flag_if_set(out, "WRITE_EA_LE",                  int_value, DesiredAccessFlags::WRITE_EA_LE);
    print_flag_if_set(out, "EXECUTE_LE",                   int_value, DesiredAccessFlags::EXECUTE_LE);
    print_flag_if_set(out, "READ_ATTRIBUTES_LE",           int_value, DesiredAccessFlags::READ_ATTRIBUTES_LE);
    print_flag_if_set(out, "WRITE_ATTRIBUTES_LE",          int_value, DesiredAccessFlags::WRITE_ATTRIBUTES_LE);
    print_flag_if_set(out, "DELETE_LE",                    int_value, DesiredAccessFlags::DELETE_LE);
    print_flag_if_set(out, "READ_CONTROL_LE",              int_value, DesiredAccessFlags::READ_CONTROL_LE);
    print_flag_if_set(out, "WRITE_DAC_LE",                 int_value, DesiredAccessFlags::WRITE_DAC_LE);
    print_flag_if_set(out, "WRITE_OWNER_LE",               int_value, DesiredAccessFlags::WRITE_OWNER_LE);
    print_flag_if_set(out, "SYNCHRONIZE_LE",               int_value, DesiredAccessFlags::SYNCHRONIZE_LE);
    print_flag_if_set(out, "ACCESS_SYSTEM_SECURITY_LE",    int_value, DesiredAccessFlags::ACCESS_SYSTEM_SECURITY_LE);
    print_flag_if_set(out, "MAXIMAL_ACCESS_LE",            int_value, DesiredAccessFlags::MAXIMAL_ACCESS_LE);
    print_flag_if_set(out, "GENERIC_ALL_LE",               int_value, DesiredAccessFlags::GENERIC_ALL_LE);
    print_flag_if_set(out, "GENERIC_EXECUTE_LE",           int_value, DesiredAccessFlags::GENERIC_EXECUTE_LE);
    print_flag_if_set(out, "GENERIC_WRITE_LE",             int_value, DesiredAccessFlags::GENERIC_WRITE_LE);
    print_flag_if_set(out, "GENERIC_READ_LE",              int_value, DesiredAccessFlags::GENERIC_READ_LE);

    return out;
}

std::ostream& operator<<(std::ostream& out, const FileAttributes value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "READONLY",            int_value, FileAttributes::READONLY);
    print_flag_if_set(out, "HIDDEN",              int_value, FileAttributes::HIDDEN);
    print_flag_if_set(out, "SYSTEM",              int_value, FileAttributes::SYSTEM);
    print_flag_if_set(out, "DIRECTORY",           int_value, FileAttributes::DIRECTORY);
    print_flag_if_set(out, "ARCHIVE",             int_value, FileAttributes::ARCHIVE);
    print_flag_if_set(out, "NORMAL",              int_value, FileAttributes::NORMAL); 
    print_flag_if_set(out, "TEMPORARY",           int_value, FileAttributes::TEMPORARY);
    print_flag_if_set(out, "SPARSE_FILE",         int_value, FileAttributes::SPARSE_FILE);
    print_flag_if_set(out, "REPARSE_POINT",       int_value, FileAttributes::REPARSE_POINT);
    print_flag_if_set(out, "COMPRESSED",          int_value, FileAttributes::COMPRESSED);
    print_flag_if_set(out, "OFFLINE",             int_value, FileAttributes::OFFLINE);
    print_flag_if_set(out, "NOT_CONTENT_INDEXED", int_value, FileAttributes::NOT_CONTENT_INDEXED);
    print_flag_if_set(out, "ENCRYPTED",           int_value, FileAttributes::ENCRYPTED);

    return out;
}

std::ostream& operator<<(std::ostream& out, const ShareAccessFlags value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "SHARE_READ_LE",     int_value, ShareAccessFlags::SHARE_READ_LE);
    print_flag_if_set(out, "SHARE_WRITE_LE",    int_value, ShareAccessFlags::SHARE_WRITE_LE);
    print_flag_if_set(out, "SHARE_DELETE_LE",   int_value, ShareAccessFlags::SHARE_DELETE_LE);

    return out;
}

std::ostream& operator<<(std::ostream& out, const CreateOptionsFlags value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "DIRECTORY_FILE_LE",            int_value, CreateOptionsFlags::DIRECTORY_FILE_LE);
    print_flag_if_set(out, "WRITE_THROUGH_LE",             int_value, CreateOptionsFlags::WRITE_THROUGH_LE);
    print_flag_if_set(out, "SEQUENTIAL_ONLY_LE",           int_value, CreateOptionsFlags::SEQUENTIAL_ONLY_LE);
    print_flag_if_set(out, "NO_INTERMEDIATE_BUFFERRING_LE",int_value, CreateOptionsFlags::NO_INTERMEDIATE_BUFFERRING_LE);
    print_flag_if_set(out, "SYNCHRONOUS_IO_ALERT_LE",      int_value, CreateOptionsFlags::SYNCHRONOUS_IO_ALERT_LE);
    print_flag_if_set(out, "SYNCHRONOUS_IO_NON_ALERT_LE",  int_value, CreateOptionsFlags::SYNCHRONOUS_IO_NON_ALERT_LE);
    print_flag_if_set(out, "NON_DIRECTORY_FILE_LE",        int_value, CreateOptionsFlags::NON_DIRECTORY_FILE_LE);
    print_flag_if_set(out, "COMPLETE_IF_OPLOCKED_LE",      int_value, CreateOptionsFlags::COMPLETE_IF_OPLOCKED_LE);
    print_flag_if_set(out, "NO_EA_KNOWLEDGE_LE",           int_value, CreateOptionsFlags::NO_EA_KNOWLEDGE_LE);
    print_flag_if_set(out, "RANDOM_ACCESS_LE",             int_value, CreateOptionsFlags::RANDOM_ACCESS_LE);
    print_flag_if_set(out, "DELETE_ON_CLOSE_LE",           int_value, CreateOptionsFlags::DELETE_ON_CLOSE_LE);
    print_flag_if_set(out, "OPEN_BY_FILE_ID_LE",           int_value, CreateOptionsFlags::OPEN_BY_FILE_ID_LE);
    print_flag_if_set(out, "OPEN_FOR_BACKUP_INTENT_LE",    int_value, CreateOptionsFlags::OPEN_FOR_BACKUP_INTENT_LE);
    print_flag_if_set(out, "NO_COMPRESSION_LE",            int_value, CreateOptionsFlags::NO_COMPRESSION_LE);
    print_flag_if_set(out, "RESERVE_OPFILTER_LE",          int_value, CreateOptionsFlags::RESERVE_OPFILTER_LE);
    print_flag_if_set(out, "OPEN_REPARSE_POINT_LE",        int_value, CreateOptionsFlags::OPEN_REPARSE_POINT_LE);
    print_flag_if_set(out, "OPEN_NO_RECALL_LE",            int_value, CreateOptionsFlags::OPEN_NO_RECALL_LE);
    print_flag_if_set(out, "OPEN_FOR_FREE_SPACE_QUERY_LE", int_value, CreateOptionsFlags::OPEN_FOR_FREE_SPACE_QUERY_LE);

    return out;
}

std::ostream& operator<<(std::ostream& out, const WriteFlags value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "SMB2_WRITEFLAG_WRITE_THROUGH",     int_value, WriteFlags::SMB2_WRITEFLAG_WRITE_THROUGH);
    print_flag_if_set(out, "SMB2_WRITEFLAG_WRITE_UNBUFFERED",  int_value, WriteFlags::SMB2_WRITEFLAG_WRITE_UNBUFFERED);

    return out;
}

std::ostream& operator<<(std::ostream& out, const ShareFlags value)
{
    auto int_value = to_integral(value) & ~to_integral(ShareFlags::NO_CACHING);

    out << "Caching policy = ";
    switch(to_integral(value) & to_integral(ShareFlags::NO_CACHING))
    {
        case to_integral(ShareFlags::MANUAL_CACHING):    out << "MANUAL_CACHING"; break;
        case to_integral(ShareFlags::AUTO_CACHING):      out << "AUTO_CACHING";   break; 
        case to_integral(ShareFlags::VDO_CACHING):       out << "VDO_CACHING";    break;
        case to_integral(ShareFlags::NO_CACHING):        out << "NO_CACHING";     break;
    } 

    if(int_value > 0)
    {
        out << flagDelimiter; 
        print_flag_if_set(out, "SMB2_SHAREFLAG_DFS",                           int_value, ShareFlags::DFS);
        print_flag_if_set(out, "SMB2_SHAREFLAG_DFS_ROOT",                      int_value, ShareFlags::DFS_ROOT);
        print_flag_if_set(out, "SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS",      int_value, ShareFlags::RESTRICT_EXCLUSIVE_OPENS);
        print_flag_if_set(out, "SMB2_SHAREFLAG_FORCE_SHARED_DELETE",           int_value, ShareFlags::FORCE_SHARED_DELETE);
        print_flag_if_set(out, "SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING",       int_value, ShareFlags::ALLOW_NAMESPACE_CACHING);
        print_flag_if_set(out, "SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM",   int_value, ShareFlags::ACCESS_BASED_DIRECTORY_ENUM);
        print_flag_if_set(out, "SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK",          int_value, ShareFlags::FORCE_LEVELII_OPLOCK);
        print_flag_if_set(out, "SMB2_SHAREFLAG_ENABLE_HASH_V1",                int_value, ShareFlags::ENABLE_HASH);
        print_flag_if_set(out, "SMB2_SHAREFLAG_ENABLE_HASH_V2",                int_value, ShareFlags::ENABLE_HASH_2);
        print_flag_if_set(out, "SMB2_SHAREFLAG_ENCRYPT_DATA",                  int_value, ShareFlags::ENABLE_ENCRYPT_DATA); 
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const ShareCapabilities value)
{
    auto int_value = to_integral(value);

    if(int_value > 0)
    { 
        print_flag_if_set(out, "SMB2_SHARE_CAP_DFS",                       int_value, ShareCapabilities::DFS);
        print_flag_if_set(out, "SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY",   int_value, ShareCapabilities::CONTINUOUS_AVAILABILITY);
        print_flag_if_set(out, "SMB2_SHARE_CAP_SCALEOUT",                  int_value, ShareCapabilities::SCALEOUT);
        print_flag_if_set(out, "SMB2_SHARE_CAP_CLUSTER",                   int_value, ShareCapabilities::CLUSTER);
        print_flag_if_set(out, "SMB2_SHARE_CAP_ASYMMETRIC",                int_value, ShareCapabilities::ASYMMETRIC);
    } else 
    {
        out << "Capabilities field is not set";
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const SecurityModeShort value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "SIGNING_ENABLED",   int_value, SecurityModeShort::SIGNING_ENABLED);
    print_flag_if_set(out, "SIGNING_REQUIRED",  int_value, SecurityModeShort::SIGNING_REQUIRED);

    return out;
}

std::ostream& operator<<(std::ostream& out, const Capabilities value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "DFS",               int_value, Capabilities::DFS);
    print_flag_if_set(out, "LEASING",           int_value, Capabilities::LEASING);
    print_flag_if_set(out, "LARGE_MTU",         int_value, Capabilities::LARGE_MTU);
    print_flag_if_set(out, "MULTI_CHANNEL",     int_value, Capabilities::MULTI_CHANNEL);
    print_flag_if_set(out, "PERSISTENT_HANDLES",int_value, Capabilities::PERSISTENT_HANDLES);
    print_flag_if_set(out, "DIRECTORY_LEASING", int_value, Capabilities::DIRECTORY_LEASING);
    print_flag_if_set(out, "ENCRYPTION",        int_value, Capabilities::ENCRYPTION);

    return out;
}

std::ostream& operator<<(std::ostream& out, const SessionFlags value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "NONE",                          int_value, SessionFlags::NONE);
    print_flag_if_set(out, "SMB2_SESSION_FLAG_IS_GUEST",    int_value, SessionFlags::IS_GUEST);
    print_flag_if_set(out, "SMB2_SESSION_FLAG_IS_NULL",     int_value, SessionFlags::IS_NULL);
    print_flag_if_set(out, "SMB2_SESSION_FLAG_ENCRYPT_DATA",int_value, SessionFlags::IS_ENCRYPT_DATA);

    return out;
}

std::ostream& operator<<(std::ostream& out, const AccessMask value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "FILE_READ_DATA",           int_value, AccessMask::FILE_READ_DATA);
    print_flag_if_set(out, "FILE_WRITE_DATA",          int_value, AccessMask::FILE_WRITE_DATA);
    print_flag_if_set(out, "FILE_APPEND_DATA",         int_value, AccessMask::FILE_APPEND_DATA);
    print_flag_if_set(out, "FILE_READ_EA",             int_value, AccessMask::FILE_READ_EA);
    print_flag_if_set(out, "FILE_WRITE_EA",            int_value, AccessMask::FILE_WRITE_EA);
    print_flag_if_set(out, "FILE_DELETE_CHILD",        int_value, AccessMask::FILE_DELETE_CHILD);
    print_flag_if_set(out, "FILE_EXECUTE",             int_value, AccessMask::FILE_EXECUTE);
    print_flag_if_set(out, "FILE_READ_ATTRIBUTES",     int_value, AccessMask::FILE_READ_ATTRIBUTES);
    print_flag_if_set(out, "FILE_WRITE_ATTRIBUTES",    int_value, AccessMask::FILE_WRITE_ATTRIBUTES);
    print_flag_if_set(out, "DELETE",                   int_value, AccessMask::DELETE);
    print_flag_if_set(out, "READ_CONTROL",             int_value, AccessMask::READ_CONTROL);
    print_flag_if_set(out, "WRITE_DAC",                int_value, AccessMask::WRITE_DAC);
    print_flag_if_set(out, "WRITE_OWNER",              int_value, AccessMask::WRITE_OWNER);
    print_flag_if_set(out, "SYNCHRONIZE",              int_value, AccessMask::SYNCHRONIZE);
    print_flag_if_set(out, "ACCESS_SYSTEM_SECURITY",   int_value, AccessMask::ACCESS_SYSTEM_SECURITY);
    print_flag_if_set(out, "MAXIMUM_ALLOWED",          int_value, AccessMask::MAXIMUM_ALLOWED);
    print_flag_if_set(out, "GENERIC_ALL",              int_value, AccessMask::GENERIC_ALL);
    print_flag_if_set(out, "GENERIC_EXECUTE",          int_value, AccessMask::GENERIC_EXECUTE);
    print_flag_if_set(out, "GENERIC_WRITE",            int_value, AccessMask::GENERIC_WRITE);
    print_flag_if_set(out, "GENERIC_READ",             int_value, AccessMask::GENERIC_READ);

    return out;
}

std::ostream& operator<<(std::ostream& out, const CloseFlags value)
{
    auto int_value = to_integral(value);

    if(int_value > 0)
    {
        print_flag_if_set(out, "POSTQUERY_ATTRIB",   int_value, CloseFlags::POSTQUERY_ATTRIB);
    } else 
    {
        out << "Close Flag field is not set";
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const SecurityMode value)
{
    auto int_value = to_integral(value);

    print_flag_if_set(out, "SIGNING_ENABLED",   int_value, SecurityMode::SIGNING_ENABLED);
    print_flag_if_set(out, "SIGNING_REQUIRED",  int_value, SecurityMode::SIGNING_REQUIRED);

    return out;
}

std::ostream& operator<<(std::ostream& out, const FsInfoLevels value)
{
    switch(value)
    {
        case FsInfoLevels::SMB2_FS_INFO_01: return out << "SMB2_FS_INFO_01";
        case FsInfoLevels::SMB2_FS_INFO_02: return out << "SMB2_FS_INFO_02";
        case FsInfoLevels::SMB2_FS_INFO_03: return out << "SMB2_FS_INFO_03";
        case FsInfoLevels::SMB2_FS_INFO_04: return out << "SMB2_FS_INFO_04";
        case FsInfoLevels::SMB2_FS_INFO_05: return out << "SMB2_FS_INFO_05";
        case FsInfoLevels::SMB2_FS_INFO_06: return out << "SMB2_FS_INFO_06";
        case FsInfoLevels::SMB2_FS_INFO_07: return out << "SMB2_FS_INFO_07";
        default:
            // empty default block
            ;
    } 
    return out;
}

std::ostream& operator<<(std::ostream& out, const QueryInfoLevels value)
{
    switch(value)
    {
        case QueryInfoLevels::DIRECTORY_INFORMATION:              return out << "DIRECTORY_INFORMATION";
        case QueryInfoLevels::FULL_DIRECTORY_INFORMATION:         return out << "FULL_DIRECTORY_INFORMATION";
        case QueryInfoLevels::BOTH_DIRECTORY_INFORMATION:         return out << "BOTH_DIRECTORY_INFORMATION";
        case QueryInfoLevels::BASIC_INFORMATION:                  return out << "BASIC_INFORMATION";
        case QueryInfoLevels::STANDARD_INFORMATION:               return out << "STANDARD_INFORMATION";
        case QueryInfoLevels::INTERNAL_INFORMATION:               return out << "INTERNAL_INFORMATION";
        case QueryInfoLevels::EA_INFORMATION:                     return out << "EA_INFORMATION";
        case QueryInfoLevels::ACCESS_INFORMATION:                 return out << "ACCESS_INFORMATION";
        case QueryInfoLevels::NAME_INFORMATION:                   return out << "NAME_INFORMATION";
        case QueryInfoLevels::RENAME_INFORMATION:                 return out << "RENAME_INFORMATION";
        case QueryInfoLevels::LINK_INFORMATION:                   return out << "LINK_INFORMATION";
        case QueryInfoLevels::NAMES_INFORMATION:                  return out << "NAMES_INFORMATION";
        case QueryInfoLevels::DISPOSITION_INFORMATION:            return out << "DISPOSITION_INFORMATION";
        case QueryInfoLevels::POSITION_INFORMATION:               return out << "POSITION_INFORMATION";
        case QueryInfoLevels::FULL_EA_INFORMATION:                return out << "FULL_EA_INFORMATION";
        case QueryInfoLevels::MODE_INFORMATION:                   return out << "MODE_INFORMATION";
        case QueryInfoLevels::ALIGNMENT_INFORMATION:              return out << "ALIGNMENT_INFORMATION";
        case QueryInfoLevels::ALL_INFORMATION:                    return out << "ALL_INFORMATION";
        case QueryInfoLevels::ALLOCATION_INFORMATION:             return out << "ALLOCATION_INFORMATION";
        case QueryInfoLevels::END_OF_FILE_INFORMATION:            return out << "END_OF_FILE_INFORMATION";
        case QueryInfoLevels::ALTERNATE_NAME_INFORMATION:         return out << "ALTERNATE_NAME_INFORMATION";
        case QueryInfoLevels::STREAM_INFORMATION:                 return out << "STREAM_INFORMATION";
        case QueryInfoLevels::PIPE_INFORMATION:                   return out << "PIPE_INFORMATION";
        case QueryInfoLevels::PIPE_LOCAL_INFORMATION:             return out << "PIPE_LOCAL_INFORMATION";
        case QueryInfoLevels::PIPE_REMOTE_INFORMATION:            return out << "PIPE_REMOTE_INFORMATION";
        case QueryInfoLevels::MAILSLOT_QUERY_INFORMATION:         return out << "MAILSLOT_QUERY_INFORMATION";
        case QueryInfoLevels::MAILSLOT_SET_INFORMATION:           return out << "MAILSLOT_SET_INFORMATION";
        case QueryInfoLevels::COMPRESSION_INFORMATION:            return out << "COMPRESSION_INFORMATION";
        case QueryInfoLevels::OBJECT_ID_INFORMATION:              return out << "OBJECT_ID_INFORMATION";
        case QueryInfoLevels::MOVE_CLUSTER_INFORMATION:           return out << "MOVE_CLUSTER_INFORMATION";
        case QueryInfoLevels::QUOTA_INFORMATION:                  return out << "QUOTA_INFORMATION";
        case QueryInfoLevels::REPARSE_POINT_INFORMATION:          return out << "REPARSE_POINT_INFORMATION";
        case QueryInfoLevels::NETWORK_OPEN_INFORMATION:           return out << "NETWORK_OPEN_INFORMATION";
        case QueryInfoLevels::ATTRIBUTE_TAG_INFORMATION:          return out << "ATTRIBUTE_TAG_INFORMATION";
        case QueryInfoLevels::TRACKING_INFORMATION:               return out << "TRACKING_INFORMATION";
        case QueryInfoLevels::ID_BOTH_DIRECTORY_INFORMATION:      return out << "ID_BOTH_DIRECTORY_INFORMATION";
        case QueryInfoLevels::ID_FULL_DIRECTORY_INFORMATION:      return out << "ID_FULL_DIRECTORY_INFORMATION";
        case QueryInfoLevels::VALID_DATA_LENGTH_INFORMATION:      return out << "VALID_DATA_LENGTH_INFORMATION";
        case QueryInfoLevels::SHORT_NAME_INFORMATION:             return out << "SHORT_NAME_INFORMATION";
        case QueryInfoLevels::SFIO_RESERVE_INFORMATION:           return out << "SFIO_RESERVE_INFORMATION";
        case QueryInfoLevels::SFIO_VOLUME_INFORMATION:            return out << "SFIO_VOLUME_INFORMATION";
        case QueryInfoLevels::HARD_LINK_INFORMATION:              return out << "HARD_LINK_INFORMATION";
        case QueryInfoLevels::NORMALIZED_NAME_INFORMATION:        return out << "NORMALIZED_NAME_INFORMATION";
        case QueryInfoLevels::ID_GLOBAL_TX_DIRECTORY_INFORMATION: return out << "ID_GLOBAL_TX_DIRECTORY_INFORMATION";
        case QueryInfoLevels::STANDARD_LINK_INFORMATION:          return out << "STANDARD_LINK_INFORMATION";
        default:
            // empty default block
            ;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const CtlCodes value)
{
    switch(value)
    {
        case CtlCodes::SCTL_DFS_GET_REFERRALS:              return out << "SCTL_DFS_GET_REFERRALS";
        case CtlCodes::FSCTL_PIPE_PEEK:                     return out << "FSCTL_PIPE_PEEK";
        case CtlCodes::FSCTL_PIPE_WAIT:                     return out << "FSCTL_PIPE_WAIT";
        case CtlCodes::FSCTL_PIPE_TRANSCEIVE:               return out << "FSCTL_PIPE_TRANSCEIVE";
        case CtlCodes::FSCTL_SRV_COPYCHUNK:                 return out << "FSCTL_SRV_COPYCHUNK";
        case CtlCodes::FSCTL_SRV_ENUMERATE_SNAPSHOTS:       return out << "FSCTL_SRV_ENUMERATE_SNAPSHOTS";
        case CtlCodes::FSCTL_SRV_REQUEST_RESUME_KEY:        return out << "FSCTL_SRV_REQUEST_RESUME_KEY";
        case CtlCodes::FSCTL_SRV_READ_HASH:                 return out << "FSCTL_SRV_READ_HASH";
        case CtlCodes::FSCTL_SRV_COPYCHUNK_WRITE:           return out << "FSCTL_SRV_COPYCHUNK_WRITE";
        case CtlCodes::FSCTL_LMR_REQUEST_RESILIENCY:        return out << "FSCTL_LMR_REQUEST_RESILIENCY";
        case CtlCodes::FSCTL_QUERY_NETWORK_INTERFACE_INFO:  return out << "FSCTL_QUERY_NETWORK_INTERFACE_INFO";
        case CtlCodes::FSCTL_SET_REPARSE_POINT:             return out << "FSCTL_SET_REPARSE_POINT";
        case CtlCodes::FSCTL_DFS_GET_REFERRALS_EX:          return out << "FSCTL_DFS_GET_REFERRALS_EX";
        case CtlCodes::FSCTL_FILE_LEVEL_TRIM:               return out << "FSCTL_FILE_LEVEL_TRIM";
        case CtlCodes::FSCTL_VALIDATE_NEGOTIATE_INFO:       return out << "FSCTL_VALIDATE_NEGOTIATE_INFO";
        default:
            // empty default block
            ;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const InfoTypes value)
{
    switch(value)
    {
        case InfoTypes::FILE:        return out << "SMB2_0_INFO_FILE";
        case InfoTypes::FILESYSTEM:  return out << "SMB2_0_INFO_FILESYSTEM";
        case InfoTypes::SECURITY:    return out << "SMB2_0_INFO_SECURITY";
        case InfoTypes::QUOTA:       return out << "SMB2_0_INFO_QUOTA";
        default:
            // empty default block
            ;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const SessionFlagsBinding value)
{
    switch(value)
    {
        case SessionFlagsBinding::NONE:     return out << "NONE";
        case SessionFlagsBinding::BINDING:  return out << "BINDING";
        default:
            // empty default block
            ;
    }
    return out;
} 

std::ostream& print_info_levels(std::ostream& out, const InfoTypes infoType, const uint8_t infoClass)
{
    switch(infoType)
    {
        case InfoTypes::FILE:
            print_enum(out, "InfoLevel", static_cast<QueryInfoLevels>(infoClass));
            
        case InfoTypes::FILESYSTEM:
            print_enum(out, "InfoLevel", static_cast<FsInfoLevels>(infoClass));
            
        default:
            //we dont handle other classes
            ;
    }
    return out;
} 
} // namespace CIFSv2
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
