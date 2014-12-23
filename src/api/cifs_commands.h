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
#define cpu_to_le32//FIXME: define cpu_to_le<>
#define cpu_to_le16

/*!
 * \brief The errResponse struct
 * The SMB2 ERROR Response packet is sent by the server
 * to respond to a request that has failed or encountered an error.
 */
struct errResponse
{
    uint16_t structureSize;
    uint16_t reserved;                           //!< 0
    uint32_t byteCount;                          //!< even if zero, at least one byte follows
    uint8_t  errorData[1];                       //!< Error message. Variable length
}  __attribute__ ((__packed__));

/*!
 * security modes. The security mode field specifies whether
 * SMB signing is enabled or required at the client.
 */
enum class SecurityMode : uint16_t
{
    SIGNING_ENABLED   = 0x0001,                   //!< When set, indicates that security signatures are enabled on the client.
    SIGNING_REQUIRED  = 0x0002                    //!< When set, indicates that security signatures are required by the client.
};

/*!
 * security modes. The security mode field specifies whether
 * SMB signing is enabled or required at the client.
 */
enum class SecurityModeShort : uint8_t
{
    SIGNING_ENABLED   = 0x01,                     //!< When set, indicates that security signatures are enabled on the client.
    SIGNING_REQUIRED  = 0x02                      //!< When set, indicates that security signatures are required by the client.
};

/*!
 * Capabilities flags
 * If the client implements the SMB 3.x dialect family,
 * the Capabilities field MUST be constructed using the following values.
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
 * The SMB2 NEGOTIATE Request packet is used by the client to notify
 * the server what dialects of the SMB 2 Protocol the client understands.
 * This request is composed of an SMB2 header,
 * followed by this request structure.
 */
struct NegotiateRequest
{
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
 * The SMB2 NEGOTIATE Response packet is sent by the server to notify
 * the client of the preferred common dialect.
 * This response is composed of an SMB2 header,
 * followed by this response structure.
 */
struct NegotiateResponse
{
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
    uint32_t reserved2;                          //!< This field MUST NOT be used and MUST be reserved. The server may set this to any value, and the client MUST ignore it on receipt.
    uint8_t  buffer[1];                          //!< The variable-length buffer that contains the security buffer for the response
} __attribute__ ((__packed__));

/*! Session binding to connections flags
 * Is used if the client implements the SMB 3.x dialect family.
 * Otherwise, it MUST be set to NONE.
 */
enum class SessionFlagsBinding : uint8_t
{
    NONE     = 0x00,                             //!< Default
    BINDING  = 0x01                              //!< When set, indicates that the request is to bind an existing session to a new connection.
};

/*!
 * \brief The SMB2 SESSION_SETUP Request packet is sent by the client to
 * request a new authenticated session within a new or existing SMB 2 Protocol
 * transport connection to the server. This request is composed of an SMB2
 * header as specified in section 2.2.1 followed by this request structure.
 */
struct SessionSetupRequest
{
    uint16_t structureSize;                      //!< Must be 25
    SessionFlagsBinding  VcNumber;               //!< If the client implements the SMB 3.x dialect family, this field MUST be set to combination of zero or more of the following values. Otherwise, it MUST be set to 0.
    SecurityModeShort  securityMode;             //!< The security mode field specifies whether SMB signing is enabled or required at the client. This field MUST be constructed using the following values.
    Capabilities capabilities;                   //!< Specifies protocol capabilities for the client. This field MUST be constructed using the following values.
    uint32_t Channel;                            //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
    uint16_t SecurityBufferOffset;               //!< The offset, in bytes, from the beginning of the SMB 2 Protocol header to the security buffer.
    uint16_t SecurityBufferLength;               //!< The length, in bytes, of the security buffer.
    uint64_t PreviousSessionId;                  //!< A previously established session identifier. The server uses this value to identify the client session that was disconnected due to a network error.
    uint8_t  Buffer[1];                          //!< A variable-length buffer that contains the security buffer for the request, as specified by SecurityBufferOffset and SecurityBufferLength
} __attribute__ ((__packed__));

/*! Currently defined SessionFlags
 */
enum class SessionFlags : uint16_t
{
    NONE            = 0x0000,                     //!< Default
    IS_GUEST        = 0x0001,                     //!< If set, the client has been authenticated as a guest user.
    IS_NULL         = 0x0002,                     //!< If set, the client has been authenticated as an anonymous user.
    IS_ENCRYPT_DATA = 0x0004                      //!< If set, the server requires encryption of messages on this session. This flag is only valid for the SMB 3.x dialect family.
};

/*!
 * \brief The sess_setupResponse struct
 * The SMB2 SESSION_SETUP Response packet is sent by the server in response to
 * an SMB2 SESSION_SETUP Request packet. This response is composed of an SMB2
 * header, that is followed by this response structure.
 */
struct SessionSetupResponse
{
    uint16_t structureSize;                       //!< Must be 9
    SessionFlags sessionFlags;                    //!< A flags field that indicates additional information about the session.
    uint16_t SecurityBufferOffset;                //!< The offset, in bytes, from the beginning of the SMB2 header to the security buffer.
    uint16_t SecurityBufferLength;                //!< The length, in bytes, of the security buffer.
    uint8_t  Buffer[1];                           //!< A variable-length buffer that contains the security buffer for the response, as specified by SecurityBufferOffset and SecurityBufferLength.
} __attribute__ ((__packed__));

/*!
 * \brief The LogoffRequest struct.
 * The SMB2 LOGOFF Request packet is sent by the client to request termination
 * of a particular session
 */
struct LogOffRequest
{
    uint16_t structureSize;                       //!< Must be 4
    uint16_t Reserved;                            //!< This field MUST NOT be used and MUST be reserved
} __attribute__ ((__packed__));

/*!
 * \brief The LogoffResponse struct
 * The SMB2 LOGOFF Response packet is sent by the server to confirm that an
 * SMB2 LOGOFF Request was completed successfully
 */
struct LogOffResponse
{
    uint16_t structureSize;                       //!< Must be 4
    uint16_t Reserved;                            //!< This field MUST NOT be used and MUST be reserved
} __attribute__ ((__packed__));

/*!
 * \brief The TreeConnectRequest struct
 * The SMB2 TREE_CONNECT Request packet is sent by a client to request
 * access to a particular share on the server
 */
struct TreeConnectRequest
{
    uint16_t structureSize;                      //!< The client MUST set this field to 9, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent.
    uint16_t Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
    uint16_t PathOffset;                         //!< The offset, in bytes, of the full share path name from the beginning of the packet header.
    uint16_t PathLength;                         //!< The length, in bytes, of the path name.
    uint8_t  Buffer[1];                          //!< A variable-length buffer that contains the path name of the share in Unicode in the form "\\server\share" for the request, as described by PathOffset and PathLength
} __attribute__ ((__packed__));

/*!
 * Possible ShareType values
 */
enum class ShareTypes : uint8_t
{
    DISK  = 0x01,                                //!< Physical disk share.
    PIPE  = 0x02,                                //!< Named pipe share.
    PRINT = 0x03                                 //!< Printer share.
};

/*!
 * Possible shareFlags - exactly one and only one of the first 4 caching flags
 * must be set (any of the remaining, SHI1005, flags may be set individually
 * or in combination.
 */
enum class ShareFlags : uint32_t
{
    MANUAL_CACHING               = 0x00000000,   //!< The client may cache files that are explicitly selected by the user for offline use.
    AUTO_CACHING                 = 0x00000010,   //!< The client may automatically cache files that are used by the user for offline access.
    VDO_CACHING                  = 0x00000020,   //!< The client may automatically cache files that are used by the user for offline access and may use those files in an offline mode even if the share is available.
    NO_CACHING                   = 0x00000030,   //!< Offline caching MUST NOT occur.
    DFS                          = 0x00000001,   //!< The specified share is present in a Distributed File System (DFS) tree structure.
    DFS_ROOT                     = 0x00000002,   //!< The specified share is present in a DFS tree structure.
    RESTRICT_EXCLUSIVE_OPENS     = 0x00000100,   //!< The specified share disallows exclusive file opens that deny reads to an open file.
    FORCE_SHARED_DELETE          = 0x00000200,   //!< The specified share disallows clients from opening files on the share in an exclusive mode that prevents the file from being deleted until the client closes the file.
    ALLOW_NAMESPACE_CACHING      = 0x00000400,   //!< The client MUST ignore this flag.
    ACCESS_BASED_DIRECTORY_ENUM  = 0x00000800,   //!< The server will filter directory entries based on the access permissions of the client.
    FORCE_LEVELII_OPLOCK         = 0x00001000,   //!< The server will not issue exclusive caching rights on this share.
    ENABLE_HASH                  = 0x00002000,   //!< The share supports hash generation for branch cache retrieval of data. For more information, see section 2.2.31.2. This flag is not valid for the SMB 2.002 dialect.
    ENABLE_HASH_2                = 0x00004000,   //!< The share supports v2 hash generation for branch cache retrieval of data. For more information, see section 2.2.31.2. This flag is not valid for the SMB 2.002 and SMB 2.1 dialects.
    ENABLE_ENCRYPT_DATA          = 0x00008000    //!< The server requires encryption of remote file access messages on this share, per the conditions specified in section 3.3.5.2.11. This flag is only valid for the SMB 3.x dialect family.
};

/*!
 * \brief The TreeConnectResponse struct
 * The SMB2 TREE_CONNECT Response packet is sent by the server when an SMB2
 * TREE_CONNECT request is processed successfully by the server.
 */
struct TreeConnectResponse {
    uint16_t structureSize;                      //!< Must be 16
    ShareTypes ShareType;                        //!< The type of share being accessed.
    uint8_t   Reserved;                          //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
    ShareFlags shareFlags;                       //!< This field contains properties for this share.
    Capabilities capabilities;                   //!< Indicates various capabilities for this share
    uint32_t MaximalAccess;                      //!< Contains the maximal access for the user that establishes the tree connect on the share based on the share's permissions
}  __attribute__ ((__packed__));

/*!
 * \brief The tree_disconnectRequest struct
 * The SMB2 TREE_DISCONNECT Request packet is sent by the client
 * to request that the tree connect that is specified in the TreeId within
 * the SMB2 header be disconnected.
 */
struct TreeDisconnectRequest {
    uint16_t structureSize;                      //!< The client MUST set this field to 4, indicating the size of the request structure, not including the header.
    uint16_t Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
}  __attribute__ ((__packed__));

/*!
 * \brief The TreeDisconnectResponse struct
 * The SMB2 TREE_DISCONNECT Response packet is sent by the server to confirm
 * that an SMB2 TREE_DISCONNECT Request was successfully processed.
 */
struct TreeDisconnectResponse {
    uint16_t structureSize;                      //!< The client MUST set this field to 4, indicating the size of the request structure, not including the header.
    uint16_t Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
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

/*!
 * Oplock levels
 */
enum class OplockLevels : uint8_t
{
    NONE      = 0x00,                            //!< No oplock is requested.
    II        = 0x01,                            //!< A level II oplock is requested.
    EXCLUSIVE = 0x08,                            //!< An exclusive oplock is requested.
    BATCH     = 0x09,                            //!< A batch oplock is requested.
    LEASE     = 0xFF                             //!< A lease is requested. If set, the request packet MUST contain an SMB2_CREATE_REQUEST_LEASE create context. This value is not valid for the SMB 2.002 dialect.
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

/*!
 * Share Access Flags
 */
enum ShareAccessFlags : uint32_t
{
    READ_LE     = cpu_to_le32(0x00000001),       //!< When set, indicates that other opens are allowed to read this file while this open is present.
    WRITE_LE    = cpu_to_le32(0x00000002),       //!< When set, indicates that other opens are allowed to write this file while this open is present
    DELETE_LE   = cpu_to_le32(0x00000004),       //!< When set, indicates that other opens are allowed to delete or rename this file while this open is present
    ALL_LE      = cpu_to_le32(0x00000007)        //!< Combine
};

/*!
 * CreateDisposition Flags
 */
enum class CreateDisposition : uint32_t
{
    SUPERSEDE    = cpu_to_le32(0x00000000),      //!< If the file already exists, supersede it. Otherwise, create the file.
    OPEN         = cpu_to_le32(0x00000001),      //!< If the file already exists, return success; otherwise, fail the operation.
    CREATE       = cpu_to_le32(0x00000002),      //!< If the file already exists, fail the operation; otherwise, create the file.
    OPEN_IF      = cpu_to_le32(0x00000003),      //!< Open the file if it already exists; otherwise, create the file.
    OVERWRITE    = cpu_to_le32(0x00000004),      //!< Overwrite the file if it already exists; otherwise, fail the operation.
    OVERWRITE_IF = cpu_to_le32(0x00000005)       //!< Overwrite the file if it already exists; otherwise, create the file.
};

/*!
 * Create options Flags
 */
enum CreateOptionsFlags : uint32_t
{
    DIRECTORY_FILE_LE             = cpu_to_le32(0x00000001), //!< The file being created or opened is a directory file.
    WRITE_THROUGH_LE              = cpu_to_le32(0x00000002), //!< The server MUST propagate writes to this open to persistent storage before returning success to the client on write operations.
    SEQUENTIAL_ONLY_LE            = cpu_to_le32(0x00000004), //!< This indicates that the application intends to read or write at sequential offsets using this handle, so the server SHOULD optimize for sequential access
    NO_INTERMEDIATE_BUFFERRING_LE = cpu_to_le32(0x00000008), //!< The server or underlying object store SHOULD NOT cache data at intermediate layers and SHOULD allow it to flow through to persistent storage.
    SYNCHRONOUS_IO_ALERT_LE       = cpu_to_le32(0x00000010), //!< This bit SHOULD be set to 0 and MUST be ignored by the server.<34>
    SYNCHRONOUS_IO_NON_ALERT_LE   = cpu_to_le32(0x00000020), //!< This bit SHOULD be set to 0 and MUST be ignored by the server.<35>
    NON_DIRECTORY_FILE_LE         = cpu_to_le32(0x00000040), //!< If the name of the file being created or opened matches with an existing directory file, the server MUST fail the request with STATUS_FILE_IS_A_DIRECTORY.
    COMPLETE_IF_OPLOCKED_LE       = cpu_to_le32(0x00000100), //!< This bit SHOULD be set to 0 and MUST be ignored by the server
    NO_EA_KNOWLEDGE_LE            = cpu_to_le32(0x00000200), //!< The caller does not understand how to handle extended attributes.
    RANDOM_ACCESS_LE              = cpu_to_le32(0x00000800), //!< This indicates that the application intends to read or write at random offsets using this handle, so the server SHOULD optimize for random access.
    DELETE_ON_CLOSE_LE            = cpu_to_le32(0x00001000), //!< The file MUST be automatically deleted when the last open request on this file is closed.
    OPEN_BY_FILE_ID_LE            = cpu_to_le32(0x00002000), //!< This bit SHOULD be set to 0 and the server MUST fail the request with a STATUS_NOT_SUPPORTED error if this bit is set.<37>
    OPEN_FOR_BACKUP_INTENT_LE     = cpu_to_le32(0x00004000), //!< The file is being opened for backup intent. That is, it is being opened or created for the purposes of either a backup or a restore operation
    NO_COMPRESSION_LE             = cpu_to_le32(0x00008000), //!< The file cannot be compressed.
    RESERVE_OPFILTER_LE           = cpu_to_le32(0x00100000), //!< This bit SHOULD be set to 0 and the server MUST fail the request with a STATUS_NOT_SUPPORTED error if this bit is set.<38>
    OPEN_REPARSE_POINT_LE         = cpu_to_le32(0x00200000), //!< If the file or directory being opened is a reparse point, open the reparse point itself rather than the target that the reparse point references.
    OPEN_NO_RECALL_LE             = cpu_to_le32(0x00400000), //!< In an HSM (Hierarchical Storage Management) environment, this flag means the file SHOULD NOT be recalled from tertiary storage such as tape. The recall can take several minutes. The caller can specify this flag to avoid those delays.
    OPEN_FOR_FREE_SPACE_QUERY_LE  = cpu_to_le32(0x00800000)  //!< Open file to query for free space. The client SHOULD set this to 0 and the server MUST ignore it.<39>
};

/*!
 * CreateDisposition Flags
 */
enum class CreateActions : uint32_t
{
    SUPERSEDED        = cpu_to_le32(0x00000000), //!< An existing file was deleted and a new file was created in its place.
    OPENED            = cpu_to_le32(0x00000001), //!< An existing file was opened.
    CREATED           = cpu_to_le32(0x00000002), //!< A new file was created.
    FILE_OVERWRITTEN  = cpu_to_le32(0x00000003), //!< An existing file was overwritten.
};

/*!
 * Impersonation Levels
 */
enum class ImpersonationLevels : uint32_t
{
    ANONYMOUS      = cpu_to_le32(0x00000000),    //!< The application-requested impersonation level is Anonymous.
    IDENTIFICATION = cpu_to_le32(0x00000001),    //!< The application-requested impersonation level is Identification.
    IMPERSONATION  = cpu_to_le32(0x00000002),    //!< The application-requested impersonation level is Impersonation.
    DELEGATE       = cpu_to_le32(0x00000003)     //!< The application-requested impersonation level is Delegate.
};

//FIXME: To be deleted?
/*!
 * Create Context Values
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

/*!
 * \brief The createRequest struct
 * The SMB2 CREATE Request packet is sent by a client to request either
 * creation of or access to a file. In case of a named pipe or printer,
 * the server MUST create a new file.
 */
struct CreateRequest {
    uint16_t structureSize;                      //!< The client MUST set this field to 57, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent.
    uint8_t   SecurityFlags;                     //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it.
    OplockLevels   RequestedOplockLevel;         //!< The requested oplock level.
    ImpersonationLevels ImpersonationLevel;      //!< This field specifies the impersonation level requested by the application that is issuing the create request
    uint64_t SmbCreateFlags;                     //!< This field MUST NOT be used and MUST be reserved. The client SHOULD set this field to zero, and the server MUST ignore it on receipt.
    uint64_t Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The client sets this to any value, and the server MUST ignore it on receipt.
    DesiredAccessFlags desiredAccess;            //!< The level of access that is required
    FileAttributes attributes;                   //!< This field MUST be a combination of the values
    ShareAccessFlags shareAccess;                //!< Specifies the sharing mode for the open
    CreateDisposition createDisposition;         //!< Defines the action the server MUST take if the file that is specified in the name field already exists.
    CreateOptionsFlags createOptions;            //!< Specifies the options to be applied when creating or opening the file. Combinations of the bit positions are valid, unless otherwise noted.
    uint16_t NameOffset;                         //!< The offset, in bytes, from the beginning of the SMB2 header to the 8-byte aligned file name
    uint16_t NameLength;                         //!< The length of the file name, in bytes.
    uint32_t CreateContextsOffset;               //!< The offset, in bytes, from the beginning of the SMB2 header to the first 8-byte aligned SMB2_CREATE_CONTEXT structure in the request
    uint32_t CreateContextsLength;               //!< The length, in bytes, of the list of SMB2_CREATE_CONTEXT structures sent in this request.
    uint8_t   Buffer[1];                         //!< A variable-length buffer that contains the Unicode file name and create context list, as defined by NameOffset, NameLength, CreateContextsOffset, and CreateContextsLength.
}  __attribute__ ((__packed__));

/*!
 * \brief The CreateResponse struct
 * The SMB2 CREATE Response packet is sent by the server to notify
 * the client of the status of its SMB2 CREATE Request.
 */
struct CreateResponse {
    uint16_t structureSize;                       //!< Must be 89
    OplockLevels oplockLevel;                     //!< The oplock level that is granted to the client for this open.
    uint8_t flag;                                 //!< If the server implements the SMB 3.x dialect family, this field MUST be constructed using the 0x01 value. Otherwise, this field MUST NOT be used and MUST be reserved.
    CreateActions CreateAction;                   //!< The action taken in establishing the open
    uint64_t CreationTime;                        //!< The time when the file was created
    uint64_t LastAccessTime;                      //!< The time the file was last accessed
    uint64_t LastWriteTime;                       //!< The time when data was last written to the file
    uint64_t ChangeTime;                          //!< The time when the file was last modified
    uint64_t AllocationSize;                      //!< The size, in bytes, of the data that is allocated to the file.
    uint64_t EndofFile;                           //!< The size, in bytes, of the file.
    FileAttributes attributes;                    //!< The attributes of the file
    uint32_t Reserved2;                           //!< This field MUST NOT be used and MUST be reserved. The server SHOULD set this to 0, and the client MUST ignore it on receipt.<51>
    uint64_t  PersistentFileId;                   //!< The identifier of the open to a file or pipe that was established. Opaque endianness
    uint64_t  VolatileFileId;                     //!<
    uint32_t CreateContextsOffset;                //!< The offset, in bytes, from the beginning of the SMB2 header to the first 8-byte aligned SMB2_CREATE_CONTEXT response that is contained in this response.
    uint32_t CreateContextsLength;                //!<  The length, in bytes, of the list of SMB2_CREATE_CONTEXT response structures that are contained in this response.
    uint8_t   Buffer[1];                          //!<  A variable-length buffer that contains the list of create contexts that are contained in this response, as described by CreateContextsOffset and CreateContextsLength.
}  __attribute__ ((__packed__));

/*!
 * A Flags field indicates how to process the operation.
 * This field MUST be constructed using the following value
 */
enum class CloseFlags : uint16_t {
    POSTQUERY_ATTRIB         = cpu_to_le16(0x0001)
};

/*!
 * \brief The closeRequest struct. The SMB2 CLOSE Request packet is used
 *  by the client to close an instance of a file that was opened previously
 *  with a successful SMB2 CREATE Request. This request is composed of an
 *  SMB2 header.
 */
struct CloseRequest {
    uint16_t structureSize;                      //!< The client MUST set this field to 24, indicating the size of the request structure, not including the header.
    CloseFlags Flags;                            //!< If set, the server MUST set the attribute fields in the response to valid values. If not set, the client MUST NOT use the values that are returned in the response.
    uint32_t Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
    uint64_t  PersistentFileId;                  //!< The identifier of the open to a file or named pipe that is being close
    uint64_t  VolatileFileId;                    //!< The identifier of the open to a file or named pipe that is being close
}  __attribute__ ((__packed__));

/*!
 * \brief The closeResponse struct. The SMB2 CLOSE Response packet is sent
 *  by the server to indicate that an SMB2 CLOSE Request was processed
 *  successfully. This response is composed of an SMB2 header
 */
struct CloseResponse {
    uint16_t structureSize;                      //!< The server MUST set this field to 60, indicating the size of the response structure, not including the header.
    CloseFlags Flags;                            //!< A Flags field indicates how to process the operation
    uint32_t Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
    uint64_t CreationTime;                       //!< The time when the file was created
    uint64_t LastAccessTime;                     //!< The time when the file was last accessed
    uint64_t LastWriteTime;                      //!< The time when data was last written to the file
    uint64_t ChangeTime;                         //!< The time when the file was last modified
    uint64_t AllocationSize;                     //!< The size, in bytes, of the data that is allocated to the file
    uint64_t EndOfFile;                          //!< The size, in bytes, of the file
    uint32_t Attributes;                         //!< The attributes of the file.
}  __attribute__ ((__packed__));

/*!
 * \brief The echoRequest struct. The SMB2 ECHO Request packet is sent
 * by a client to determine whether a server is processing requests.
 */
struct EchoRequest {
    uint16_t structureSize;                      //!< The client MUST set this to 4, indicating the size of the request structure, not including the header.
    uint16_t  Reserved;                          //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
}  __attribute__ ((__packed__));

/*!
 * \brief The echoResponse struct.The SMB2 ECHO Response packet is sent
 * by the server to confirm that an SMB2 ECHO Request was successfully processed
 */
struct EchoResponse {
    uint16_t structureSize;                      //!< The server MUST set this to 4, indicating the size of the response structure, not including the header.
    uint16_t  Reserved;                          //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
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
