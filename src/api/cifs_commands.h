//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Definition of CIFS commands
// Copyright (c) 2014 EPAM Systems
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
#ifndef _SMBv2_COMMANDS_H
#define _SMBv2_COMMANDS_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

/*! SMB 2 version
 */
namespace SMBv2
{

#define SMB2_ERROR_STRUCTURE_SIZE2 __constant_cpu_to_le16(9)
#define cpu_to_le32

/*!
 * \brief The errResponse struct
 * The SMB2 ERROR Response packet is sent by the server to respond to a request that has failed or encountered an error.
 */
struct errResponse {
    uint16_t structureSize;
    uint16_t reserved;                           //!< 0
    uint32_t byteCount;                          //!< even if zero, at least one byte follows
    uint8_t  errorData[1];                       //!< Error message. Variable length
}  __attribute__ ((__packed__));

/*!
 * security modes. The security mode field specifies whether SMB signing is enabled or required at the client.
 */
enum class SecurityMode : uint16_t
{
    SIGNING_ENABLED   = 0x0001,                   //!< When set, indicates that security signatures are enabled on the client.
    SIGNING_REQUIRED  = 0x0002                    //!< When set, indicates that security signatures are required by the client.
};

/*!
 * Capabilities flags
 * If the client implements the SMB 3.x dialect family, the Capabilities field MUST be constructed using the following values.
 * Otherwise, this field MUST be set to 0.
 */
enum class Capabilities : uint32_t
{
    DFS                 = 0x00000001,             //!< When set, indicates that the client supports the Distributed File System (DFS).
    LEASING             = 0x00000002,             //!< When set, indicates that the client supports leasing.
    LARGE_MTU           = 0x00000004,             //!< When set, indicates that the client supports multi-credit operations.
    MULTI_CHANNEL       = 0x00000008,             //!< When set, indicates that the client supports establishing multiple channels for a single session.
    PERSISTENT_HANDLES  = 0x00000010,             //!< When set, indicates that the client supports persistent handles.
    DIRECTORY_LEASING   = 0x00000020,             //!< When set, indicates that the client supports directory leasing.
    ENCRYPTION          = 0x00000040              //!< When set, indicates that the client supports encryption.
};

/*!
 * Supported dialect revision numbers
 */
enum class Dialects
{

    SMB_2_002          = 0x0202,                  //!< SMB 2.002 dialect revision number.
    SMB_2_1            = 0x0210,                  //!< SMB 2.1 dialect revision number.
    SMB_3_0            = 0x0300,                  //!< SMB 3.0 dialect revision number.
    SMB_3_02           = 0x0302                   //!< SMB 3.02 dialect revision number.
};

/*!
 * \brief The negotiateRequest struct
 * The SMB2 NEGOTIATE Request packet is used by the client to notify the server what dialects of the SMB 2 Protocol the client understands. This request is composed of an SMB2 header, followed by this request structure.
 */
struct negotiateRequest {
    uint16_t structureSize;                      //!< Must be 36
    uint16_t dialectCount;                       //!< The number of dialects that are contained in the Dialects[] array
    SecurityMode securityMode;                   //!< The security mode field specifies whether SMB signing is enabled or required at the client.
    uint16_t _;                                  //!< Reserved
    Capabilities capabilities;                   //!< Client's capabilities
    uint8_t  clientGUID[16];                     //!< Must be 0
    uint64_t clientStartTime;                    //!< Must be 0
    Dialects dialects[1];                        //!< An array of one or more 16-bit integers specifying the supported dialect revision numbers. The array MUST contain at least one of the following values. Variable length
}  __attribute__ ((__packed__));

/*!
 * \brief The negotiateResponse struct
 * The SMB2 NEGOTIATE Response packet is sent by the server to notify the client of the preferred common dialect. This response is composed of an SMB2 header, followed by this response structure.
 */
struct negotiateResponse {
    uint16_t structureSize;                      //!< Must be 65
    SecurityMode securityMode;                   //!< The security mode field specifies whether SMB signing is enabled, required at the server, or both.
    uint16_t dialectRevision;                    //!< The preferred common SMB 2 Protocol dialect number from the Dialects array that is sent in the SMB2 NEGOTIATE Request or the SMB2 wildcard revision number
    uint16_t reserved;                           //!< Must be 0
    uint8_t  serverGUID[16];                     //!< A globally unique identifier that is generated by the server to uniquely identify this server.
    Capabilities capabilities;                   //!< The Capabilities field specifies protocol capabilities for the server.
    uint32_t maxTransactSize;                    //!< The maximum size, in bytes, of the buffer that can be used for QUERY_INFO, QUERY_DIRECTORY, SET_INFO and CHANGE_NOTIFY operations.
    uint32_t maxReadSize;                        //!< The maximum size, in bytes, of the Length in an SMB2 READ Request (section 2.2.19) that the server will accept.
    uint32_t maxWriteSize;                       //!< The maximum size, in bytes, of the Length in an SMB2 WRITE Request (section 2.2.21) that the server will accept.
    uint64_t systemTime;                         //!< The system time of the SMB2 server when the SMB2 NEGOTIATE Request was processed
    uint64_t serverStartTime;                    //!< The SMB2 server start time, in FILETIME format
    uint16_t securityBufferOffset;               //!< The offset, in bytes, from the beginning of the SMB2 header to the security buffer.
    uint16_t securityBufferLength;               //!< The length, in bytes, of the security buffer.
    uint32_t reserved2;                          //!< /* may be any value, ignore */
    uint8_t  buffer[1];                          //!< /* variable length GSS security buffer */
}  __attribute__ ((__packed__));

struct sess_setupRequest {
    uint16_t structureSize; /* Must be 25 */
    uint8_t  VcNumber;
    uint8_t  securityMode;
    Capabilities capabilities;
    uint32_t Channel;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    uint64_t PreviousSessionId;
    uint8_t  Buffer[1]; /* variable length GSS security buffer */
}  __attribute__ ((__packed__));

/*! Currently defined SessionFlags
 */
enum class SessionFlags : uint16_t
{
    IS_GUEST = 0x0001,
    IS_NULL  = 0x0002
};

struct sess_setupResponse {
    uint16_t structureSize; /* Must be 9 */
    uint16_t SessionFlags;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    uint8_t  Buffer[1]; /* variable length GSS security buffer */
}  __attribute__ ((__packed__));

struct logoffRequest {
    uint16_t structureSize; /* Must be 4 */
    uint16_t Reserved;
}  __attribute__ ((__packed__));

struct logoffResponse {
    uint16_t structureSize; /* Must be 4 */
    uint16_t Reserved;
}  __attribute__ ((__packed__));

struct tree_connectRequest {
    uint16_t structureSize; /* Must be 9 */
    uint16_t Reserved;
    uint16_t PathOffset;
    uint16_t PathLength;
    uint8_t  Buffer[1]; /* variable length */
}  __attribute__ ((__packed__));

/*! Possible ShareType values
 */
enum class ShareTypes : uint8_t
{
    DISK  = 0x01,
    PIPE  = 0x02,
    PRINT = 0x03
};

/*!
 * Possible shareFlags - exactly one and only one of the first 4 caching flags
 * must be set (any of the remaining, SHI1005, flags may be set individually
 * or in combination.
 */
enum class ShareFlags : uint32_t
{
    MANUAL_CACHING               = 0x00000000,
    AUTO_CACHING                 = 0x00000010,
    VDO_CACHING                  = 0x00000020,
    NO_CACHING                   = 0x00000030,
    DFS                          = 0x00000001,
    DFS_ROOT                     = 0x00000002,
    RESTRICT_EXCLUSIVE_OPENS     = 0x00000100,
    FORCE_SHARED_DELETE          = 0x00000200,
    ALLOW_NAMESPACE_CACHING      = 0x00000400,
    ACCESS_BASED_DIRECTORY_ENUM  = 0x00000800,
    FORCE_LEVELII_OPLOCK         = 0x00001000,
    ENABLE_HASH                  = 0x00002000
};

struct tree_connectResponse {
    uint16_t structureSize; /* Must be 16 */
    ShareTypes ShareType;  /* see below */
    uint8_t   Reserved;
    ShareFlags shareFlags; /* see below */
    Capabilities capabilities; /* see below */
    uint32_t MaximalAccess;
}  __attribute__ ((__packed__));

struct tree_disconnectRequest {
    uint16_t structureSize; /* Must be 4 */
    uint16_t Reserved;
}  __attribute__ ((__packed__));

struct tree_disconnectResponse {
    uint16_t structureSize; /* Must be 4 */
    uint16_t Reserved;
}  __attribute__ ((__packed__));

/*! File Attrubutes
 */
enum class FileAttributes : uint32_t
{
READONLY            = 0x00000001,
HIDDEN              = 0x00000002,
SYSTEM              = 0x00000004,
DIRECTORY           = 0x00000010,
ARCHIVE             = 0x00000020,
NORMAL              = 0x00000080,
TEMPORARY           = 0x00000100,
SPARSE_FILE         = 0x00000200,
REPARSE_POINT       = 0x00000400,
COMPRESSED          = 0x00000800,
OFFLINE             = 0x00001000,
NOT_CONTENT_INDEXED = 0x00002000,
ENCRYPTED           = 0x00004000
};

/*! Oplock levels
 */
enum class OplockLevels : uint8_t
{
    NONE      = 0x00,
    II        = 0x01,
    EXCLUSIVE = 0x08,
    BATCH     = 0x09,
    LEASE     = 0xFF
};

/*! Desired Access Flags
 */
enum class DesiredAccessFlags : uint32_t
{
    READ_DATA_LE              = cpu_to_le32(0x00000001),
    WRITE_DATA_LE             = cpu_to_le32(0x00000002),
    APPEND_DATA_LE            = cpu_to_le32(0x00000004),
    READ_EA_LE                = cpu_to_le32(0x00000008),
    WRITE_EA_LE               = cpu_to_le32(0x00000010),
    EXECUTE_LE                = cpu_to_le32(0x00000020),
    READ_ATTRIBUTES_LE        = cpu_to_le32(0x00000080),
    WRITE_ATTRIBUTES_LE       = cpu_to_le32(0x00000100),
    DELETE_LE                 = cpu_to_le32(0x00010000),
    READ_CONTROL_LE           = cpu_to_le32(0x00020000),
    WRITE_DAC_LE              = cpu_to_le32(0x00040000),
    WRITE_OWNER_LE            = cpu_to_le32(0x00080000),
    SYNCHRONIZE_LE            = cpu_to_le32(0x00100000),
    ACCESS_SYSTEM_SECURITY_LE = cpu_to_le32(0x01000000),
    MAXIMAL_ACCESS_LE         = cpu_to_le32(0x02000000),
    GENERIC_ALL_LE            = cpu_to_le32(0x10000000),
    GENERIC_EXECUTE_LE        = cpu_to_le32(0x20000000),
    GENERIC_WRITE_LE          = cpu_to_le32(0x40000000),
    GENERIC_READ_LE           = cpu_to_le32(0x80000000)
};

/*! Share Access Flags
 */
enum class ShareAccessFlags : uint32_t
{
    READ_LE     = cpu_to_le32(0x00000001),
    WRITE_LE    = cpu_to_le32(0x00000002),
    DELETE_LE   = cpu_to_le32(0x00000004),
    ALL_LE      = cpu_to_le32(0x00000007)
};

/* CreateDisposition Flags */
enum class CreateDisposition : uint32_t
{
    SUPERSEDE_LE    = cpu_to_le32(0x00000000),
    OPEN_LE         = cpu_to_le32(0x00000001),
    CREATE_LE       = cpu_to_le32(0x00000002),
    OPEN_IF_LE      = cpu_to_le32(0x00000003),
    OVERWRITE_LE    = cpu_to_le32(0x00000004),
    OVERWRITE_IF_LE = cpu_to_le32(0x00000005)
};

/* Create options Flags */
enum class CreateOptionsFlags : uint32_t
{
    DIRECTORY_FILE_LE             = cpu_to_le32(0x00000001), //!< same as CREATE_NOT_FILE_LE cpu_to_le32(0x00000001)
    WRITE_THROUGH_LE              = cpu_to_le32(0x00000002),
    SEQUENTIAL_ONLY_LE            = cpu_to_le32(0x00000004),
    NO_INTERMEDIATE_BUFFERRING_LE = cpu_to_le32(0x00000008),
    SYNCHRONOUS_IO_ALERT_LE       = cpu_to_le32(0x00000010),
    SYNCHRONOUS_IO_NON_ALERT_LE   = cpu_to_le32(0x00000020),
    NON_DIRECTORY_FILE_LE         = cpu_to_le32(0x00000040),
    COMPLETE_IF_OPLOCKED_LE       = cpu_to_le32(0x00000100),
    NO_EA_KNOWLEDGE_LE            = cpu_to_le32(0x00000200),
    RANDOM_ACCESS_LE              = cpu_to_le32(0x00000800),
    DELETE_ON_CLOSE_LE            = cpu_to_le32(0x00001000),
    OPEN_BY_FILE_ID_LE            = cpu_to_le32(0x00002000),
    OPEN_FOR_BACKUP_INTENT_LE     = cpu_to_le32(0x00004000),
    NO_COMPRESSION_LE             = cpu_to_le32(0x00008000),
    RESERVE_OPFILTER_LE           = cpu_to_le32(0x00100000),
    OPEN_REPARSE_POINT_LE         = cpu_to_le32(0x00200000),
    OPEN_NO_RECALL_LE             = cpu_to_le32(0x00400000),
    OPEN_FOR_FREE_SPACE_QUERY_LE  = cpu_to_le32(0x00800000)
};

//FIXME: rid out
#define FILE_READ_RIGHTS_LE (FILE_READ_DATA_LE | FILE_READ_EA_LE \
    | FILE_READ_ATTRIBUTES_LE)
#define FILE_WRITE_RIGHTS_LE (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE \
    | FILE_WRITE_EA_LE | FILE_WRITE_ATTRIBUTES_LE)
#define FILE_EXEC_RIGHTS_LE (FILE_EXECUTE_LE)

/*! Impersonation Levels
 */
enum class ImpersonationLevels : uint32_t
{
    ANONYMOUS      = cpu_to_le32(0x00000000),
    IDENTIFICATION = cpu_to_le32(0x00000001),
    IMPERSONATION  = cpu_to_le32(0x00000002),
    DELEGATE       = cpu_to_le32(0x00000003)
};

//FIXME: WTF?
/*! Create Context Values
 */
#define SMB2_CREATE_EA_BUFFER   "ExtA" /* extended attributes */
#define SMB2_CREATE_SD_BUFFER   "SecD" /* security descriptor */
#define SMB2_CREATE_DURABLE_HANDLE_REQUEST "DHnQ"
#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT "DHnC"
#define SMB2_CREATE_ALLOCATION_SIZE  "AlSi"
#define SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST "MxAc"
#define SMB2_CREATE_TIMEWARP_REQUEST  "TWrp"
#define SMB2_CREATE_QUERY_ON_DISK_ID  "QFid"
#define SMB2_CREATE_REQUEST_LEASE  "RqLs"

struct createRequest {
    uint16_t structureSize; /* Must be 57 */
    uint8_t   SecurityFlags;
    uint8_t   RequestedOplockLevel;
    ImpersonationLevels ImpersonationLevel;
    uint64_t SmbCreateFlags;
    uint64_t Reserved;
    DesiredAccessFlags desiredAccess;
    FileAttributes attributes;
    ShareAccessFlags shareAccess;
    CreateDisposition createDisposition;
    CreateOptionsFlags createOptions;
    uint16_t NameOffset;
    uint16_t NameLength;
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
    uint8_t   Buffer[1];
}  __attribute__ ((__packed__));

struct createResponse {
    uint16_t structureSize; /* Must be 89 */
    uint8_t   OplockLevel;
    uint8_t   Reserved;
    uint32_t CreateAction;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndofFile;
    FileAttributes attributes;
    uint32_t Reserved2;
    uint64_t  PersistentFileId; /* opaque endianness */
    uint64_t  VolatileFileId; /* opaque endianness */
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
    uint8_t   Buffer[1];
}  __attribute__ ((__packed__));

/* Currently defined values for close flags */
#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB cpu_to_le16(0x0001)//FIXME: WTF
struct closeRequest {
    uint16_t structureSize; /* Must be 24 */
    uint16_t Flags;
    uint32_t Reserved;
    uint64_t  PersistentFileId; /* opaque endianness */
    uint64_t  VolatileFileId; /* opaque endianness */
}  __attribute__ ((__packed__));

struct closeResponse {
    uint16_t structureSize; /* 60 */
    uint16_t Flags;
    uint32_t Reserved;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize; /* Beginning of FILE_STANDARD_INFO equivalent */
    uint64_t EndOfFile;
    uint32_t Attributes;
}  __attribute__ ((__packed__));

struct echoRequest {
    uint16_t structureSize; /* Must be 4 */
    uint16_t  Reserved;
}  __attribute__ ((__packed__));

struct echoResponse {
    uint16_t structureSize; /* Must be 4 */
    uint16_t  Reserved;
}  __attribute__ ((__packed__));

/*! Possible InfoType values
 */
enum class InfoTypes : uint8_t
{
    FILE       = 0x01,
    FILESYSTEM = 0x02,
    SECURITY   = 0x03,
    QUOTA      = 0x04
};

struct query_infoRequest {
    uint16_t structureSize; /* Must be 41 */
    InfoTypes infoType;
    uint8_t   FileInfoClass;
    uint32_t OutputBufferLength;
    uint16_t InputBufferOffset;
    uint16_t  Reserved;
    uint32_t InputBufferLength;
    uint32_t AdditionalInformation;
    uint32_t Flags;
    uint64_t  PersistentFileId; /* opaque endianness */
    uint64_t  VolatileFileId; /* opaque endianness */
    uint8_t   Buffer[1];
}  __attribute__ ((__packed__));

struct query_infoResponse {
    uint16_t structureSize; /* Must be 9 */
    uint16_t OutputBufferOffset;
    uint32_t OutputBufferLength;
    uint8_t   Buffer[1];
}  __attribute__ ((__packed__));

/*
 * PDU infolevel structure definitions
 * BB consider moving to a different header
 */

/*! partial list of QUERY INFO levels
 */
enum class QueryInfoLevels
{
    DIRECTORY_INFORMATION                = 1,
    FULL_DIRECTORY_INFORMATION           = 2,
    BOTH_DIRECTORY_INFORMATION           = 3,
    BASIC_INFORMATION                    = 4,
    STANDARD_INFORMATION                 = 5,
    INTERNAL_INFORMATION                 = 6,
    EA_INFORMATION                       = 7,
    ACCESS_INFORMATION                   = 8,
    NAME_INFORMATION                     = 9,
    RENAME_INFORMATION                   = 10,
    LINK_INFORMATION                     = 11,
    NAMES_INFORMATION                    = 12,
    DISPOSITION_INFORMATION              = 13,
    POSITION_INFORMATION                 = 14,
    FULL_EA_INFORMATION                  = 15,
    MODE_INFORMATION                     = 16,
    ALIGNMENT_INFORMATION                = 17,
    ALL_INFORMATION                      = 18,
    ALLOCATION_INFORMATION               = 19,
    END_OF_FILE_INFORMATION              = 20,
    ALTERNATE_NAME_INFORMATION           = 21,
    STREAM_INFORMATION                   = 22,
    PIPE_INFORMATION                     = 23,
    PIPE_LOCAL_INFORMATION               = 24,
    PIPE_REMOTE_INFORMATION              = 25,
    MAILSLOT_QUERY_INFORMATION           = 26,
    MAILSLOT_SET_INFORMATION             = 27,
    COMPRESSION_INFORMATION              = 28,
    OBJECT_ID_INFORMATION                = 29,
    /* Number 30 not defined in documents */
    MOVE_CLUSTER_INFORMATION             = 31,
    QUOTA_INFORMATION                    = 32,
    REPARSE_POINT_INFORMATION            = 33,
    NETWORK_OPEN_INFORMATION             = 34,
    ATTRIBUTE_TAG_INFORMATION            = 35,
    TRACKING_INFORMATION                 = 36,
    ID_BOTH_DIRECTORY_INFORMATION        = 37,
    ID_FULL_DIRECTORY_INFORMATION        = 38,
    VALID_DATA_LENGTH_INFORMATION        = 39,
    SHORT_NAME_INFORMATION               = 40,
    SFIO_RESERVE_INFORMATION             = 44,
    SFIO_VOLUME_INFORMATION              = 45,
    HARD_LINK_INFORMATION                = 46,
    NORMALIZED_NAME_INFORMATION          = 48,
    ID_GLOBAL_TX_DIRECTORY_INFORMATION   = 50,
    STANDARD_LINK_INFORMATION            = 54
};

/*
 * This level 18, although with struct with same name is different from cifs
 * level 0x107. Level 0x107 has an extra u64 between AccessFlags and
 * CurrentByteOffset.
 */
struct file_all_info { /* data block encoding of response to level 18 */
    uint64_t CreationTime; /* Beginning of FILE_BASIC_INFO equivalent */
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint32_t Attributes;
    uint32_t Pad1;  /* End of FILE_BASIC_INFO_INFO equivalent */
    uint64_t AllocationSize; /* Beginning of FILE_STANDARD_INFO equivalent */
    uint64_t EndOfFile; /* size ie offset to first free byte in file */
    uint32_t NumberOfLinks; /* hard links */
    uint8_t  DeletePending;
    uint8_t  Directory;
    uint16_t Pad2;  /* End of FILE_STANDARD_INFO equivalent */
    uint64_t IndexNumber;
    uint32_t EASize;
    uint32_t AccessFlags;
    uint64_t CurrentByteOffset;
    uint32_t Mode;
    uint32_t AlignmentRequirement;
    uint32_t FileNameLength;
    char     FileName [1];
}  __attribute__ ((__packed__)); /* level 18 Query */

} // namespace SMBv2
} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//_SMBv2_COMMANDS_H
//------------------------------------------------------------------------------
