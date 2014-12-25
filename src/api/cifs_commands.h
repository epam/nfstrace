//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Definition of CIFSv2 commands
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
struct TreeConnectResponse
{
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
struct TreeDisconnectRequest
{
    uint16_t structureSize;                      //!< The client MUST set this field to 4, indicating the size of the request structure, not including the header.
    uint16_t Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
}  __attribute__ ((__packed__));

/*!
 * \brief The TreeDisconnectResponse struct
 * The SMB2 TREE_DISCONNECT Response packet is sent by the server to confirm
 * that an SMB2 TREE_DISCONNECT Request was successfully processed.
 */
struct TreeDisconnectResponse
{
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
    READ_DATA_LE              = (0x00000001),
    WRITE_DATA_LE             = (0x00000002),
    APPEND_DATA_LE            = (0x00000004),
    READ_EA_LE                = (0x00000008),
    WRITE_EA_LE               = (0x00000010),
    EXECUTE_LE                = (0x00000020),
    READ_ATTRIBUTES_LE        = (0x00000080),
    WRITE_ATTRIBUTES_LE       = (0x00000100),
    DELETE_LE                 = (0x00010000),
    READ_CONTROL_LE           = (0x00020000),
    WRITE_DAC_LE              = (0x00040000),
    WRITE_OWNER_LE            = (0x00080000),
    SYNCHRONIZE_LE            = (0x00100000),
    ACCESS_SYSTEM_SECURITY_LE = (0x01000000),
    MAXIMAL_ACCESS_LE         = (0x02000000),
    GENERIC_ALL_LE            = (0x10000000),
    GENERIC_EXECUTE_LE        = (0x20000000),
    GENERIC_WRITE_LE          = (0x40000000),
    GENERIC_READ_LE           = (0x80000000)
};

/*!
 * Share Access Flags
 */
enum ShareAccessFlags : uint32_t
{
    READ_LE     = (0x00000001),       //!< When set, indicates that other opens are allowed to read this file while this open is present.
    WRITE_LE    = (0x00000002),       //!< When set, indicates that other opens are allowed to write this file while this open is present
    DELETE_LE   = (0x00000004),       //!< When set, indicates that other opens are allowed to delete or rename this file while this open is present
    ALL_LE      = (0x00000007)        //!< Combine
};

/*!
 * CreateDisposition Flags
 */
enum class CreateDisposition : uint32_t
{
    SUPERSEDE    = (0x00000000),      //!< If the file already exists, supersede it. Otherwise, create the file.
    OPEN         = (0x00000001),      //!< If the file already exists, return success; otherwise, fail the operation.
    CREATE       = (0x00000002),      //!< If the file already exists, fail the operation; otherwise, create the file.
    OPEN_IF      = (0x00000003),      //!< Open the file if it already exists; otherwise, create the file.
    OVERWRITE    = (0x00000004),      //!< Overwrite the file if it already exists; otherwise, fail the operation.
    OVERWRITE_IF = (0x00000005)       //!< Overwrite the file if it already exists; otherwise, create the file.
};

/*!
 * Create options Flags
 */
enum CreateOptionsFlags : uint32_t
{
    DIRECTORY_FILE_LE             = (0x00000001), //!< The file being created or opened is a directory file.
    WRITE_THROUGH_LE              = (0x00000002), //!< The server MUST propagate writes to this open to persistent storage before returning success to the client on write operations.
    SEQUENTIAL_ONLY_LE            = (0x00000004), //!< This indicates that the application intends to read or write at sequential offsets using this handle, so the server SHOULD optimize for sequential access
    NO_INTERMEDIATE_BUFFERRING_LE = (0x00000008), //!< The server or underlying object store SHOULD NOT cache data at intermediate layers and SHOULD allow it to flow through to persistent storage.
    SYNCHRONOUS_IO_ALERT_LE       = (0x00000010), //!< This bit SHOULD be set to 0 and MUST be ignored by the server.<34>
    SYNCHRONOUS_IO_NON_ALERT_LE   = (0x00000020), //!< This bit SHOULD be set to 0 and MUST be ignored by the server.<35>
    NON_DIRECTORY_FILE_LE         = (0x00000040), //!< If the name of the file being created or opened matches with an existing directory file, the server MUST fail the request with STATUS_FILE_IS_A_DIRECTORY.
    COMPLETE_IF_OPLOCKED_LE       = (0x00000100), //!< This bit SHOULD be set to 0 and MUST be ignored by the server
    NO_EA_KNOWLEDGE_LE            = (0x00000200), //!< The caller does not understand how to handle extended attributes.
    RANDOM_ACCESS_LE              = (0x00000800), //!< This indicates that the application intends to read or write at random offsets using this handle, so the server SHOULD optimize for random access.
    DELETE_ON_CLOSE_LE            = (0x00001000), //!< The file MUST be automatically deleted when the last open request on this file is closed.
    OPEN_BY_FILE_ID_LE            = (0x00002000), //!< This bit SHOULD be set to 0 and the server MUST fail the request with a STATUS_NOT_SUPPORTED error if this bit is set.<37>
    OPEN_FOR_BACKUP_INTENT_LE     = (0x00004000), //!< The file is being opened for backup intent. That is, it is being opened or created for the purposes of either a backup or a restore operation
    NO_COMPRESSION_LE             = (0x00008000), //!< The file cannot be compressed.
    RESERVE_OPFILTER_LE           = (0x00100000), //!< This bit SHOULD be set to 0 and the server MUST fail the request with a STATUS_NOT_SUPPORTED error if this bit is set.<38>
    OPEN_REPARSE_POINT_LE         = (0x00200000), //!< If the file or directory being opened is a reparse point, open the reparse point itself rather than the target that the reparse point references.
    OPEN_NO_RECALL_LE             = (0x00400000), //!< In an HSM (Hierarchical Storage Management) environment, this flag means the file SHOULD NOT be recalled from tertiary storage such as tape. The recall can take several minutes. The caller can specify this flag to avoid those delays.
    OPEN_FOR_FREE_SPACE_QUERY_LE  = (0x00800000)  //!< Open file to query for free space. The client SHOULD set this to 0 and the server MUST ignore it.<39>
};

/*!
 * CreateDisposition Flags
 */
enum class CreateActions : uint32_t
{
    SUPERSEDED        = (0x00000000), //!< An existing file was deleted and a new file was created in its place.
    OPENED            = (0x00000001), //!< An existing file was opened.
    CREATED           = (0x00000002), //!< A new file was created.
    FILE_OVERWRITTEN  = (0x00000003), //!< An existing file was overwritten.
};

/*!
 * Impersonation Levels
 */
enum class ImpersonationLevels : uint32_t
{
    ANONYMOUS      = (0x00000000),    //!< The application-requested impersonation level is Anonymous.
    IDENTIFICATION = (0x00000001),    //!< The application-requested impersonation level is Identification.
    IMPERSONATION  = (0x00000002),    //!< The application-requested impersonation level is Impersonation.
    DELEGATE       = (0x00000003)     //!< The application-requested impersonation level is Delegate.
};

/*!
 * \brief The createRequest struct
 * The SMB2 CREATE Request packet is sent by a client to request either
 * creation of or access to a file. In case of a named pipe or printer,
 * the server MUST create a new file.
 */
struct CreateRequest
{
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
struct CreateResponse
{
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
enum class CloseFlags : uint16_t
{
    POSTQUERY_ATTRIB = (0x0001)
};

/*!
 * \brief The closeRequest struct. The SMB2 CLOSE Request packet is used
 *  by the client to close an instance of a file that was opened previously
 *  with a successful SMB2 CREATE Request. This request is composed of an
 *  SMB2 header.
 */
struct CloseRequest
{
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
struct CloseResponse
{
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
struct EchoRequest
{
    uint16_t structureSize;                      //!< The client MUST set this to 4, indicating the size of the request structure, not including the header.
    uint16_t  Reserved;                          //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
}  __attribute__ ((__packed__));

/*!
 * \brief The echoResponse struct.The SMB2 ECHO Response packet is sent
 * by the server to confirm that an SMB2 ECHO Request was successfully processed
 */
struct EchoResponse
{
    uint16_t structureSize;                      //!< The server MUST set this to 4, indicating the size of the response structure, not including the header.
    uint16_t  Reserved;                          //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
}  __attribute__ ((__packed__));

/*! Possible InfoType values
 */
enum class InfoTypes : uint8_t
{
    FILE       = 0x01,                           //!< The file information is requested.
    FILESYSTEM = 0x02,                           //!< The underlying object store information is requested.
    SECURITY   = 0x03,                           //!< The security information is requested.
    QUOTA      = 0x04                            //!< The underlying object store quota information is requested.
};

/*!
 * PDU infolevel structure definitions
 * BB consider moving to a different header
 * partial list of QUERY INFO levels
 */
enum class QueryInfoLevels : uint8_t
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

/*!
 * Provides additional information to the server.
 * If security information is being queried, this value contains a 4-byte bit
 * field of flags indicating what security attributes MUST be returned.
 */
enum class AdditionInfo : uint32_t
{
    OWNER_SECURITY_INFORMATION     = 0x00000001, //!< The client is querying the owner from the security descriptor of the file or named pipe.
    GROUP_SECURITY_INFORMATION     = 0x00000002, //!< The client is querying the group from the security descriptor of the file or named pipe.
    DACL_SECURITY_INFORMATION      = 0x00000004, //!< The client is querying the discretionary access control list from the security descriptor of the file or named pipe.
    SACL_SECURITY_INFORMATION      = 0x00000008, //!< The client is querying the system access control list from the security descriptor of the file or named pipe.
    LABEL_SECURITY_INFORMATION     = 0x00000010, //!< The client is querying the integrity label from the security descriptor of the file or named pipe.
    ATTRIBUTE_SECURITY_INFORMATION = 0x00000020, //!< The client is querying the resource attribute from the security descriptor of the file or named pipe.
    SCOPE_SECURITY_INFORMATION     = 0x00000040, //!< The client is querying the central access policy of the resource from the security descriptor of the file or named pipe.
    BACKUP_SECURITY_INFORMATION    = 0x00010000  //!< The client is querying the security descriptor information used for backup operation.
};

/*!
 * The flags MUST be set to a combination of zero or more of these bit values
 * for a FileFullEaInformation query.
 */
enum FileFullEaInformation : uint32_t
{
    SL_RESTART_SCAN        = 0x00000001,         //!< Restart the scan for EAs from the beginning.
    SL_RETURN_SINGLE_ENTRY = 0x00000002,         //!< Return a single EA entry in the response buffer.
    SL_INDEX_SPECIFIED     = 0x00000004          //!< The caller has specified an EA index.
};

/*!
 * \brief The QueryInfoRequest struct
 * The SMB2 QUERY_INFO Request (section 2.2.37) packet is sent by a client
 * to request information on a file, named pipe, or underlying volume.
 */
struct QueryInfoRequest
{
    uint16_t  structureSize;                     //!< Must be 41
    InfoTypes infoType;                          //!< The type of information queried
    QueryInfoLevels FileInfoClass;               //!< Class of info
    uint32_t  OutputBufferLength;                //!< The maximum number of bytes of information the server can send in the response.
    uint16_t  InputBufferOffset;                 //!< The offset, in bytes, from the beginning of the SMB2 header to the input buffer.
    uint16_t  Reserved;                          //!< This field MUST NOT be used and MUST be reserved.
    uint32_t  InputBufferLength;                 //!< The length of the input buffer
    AdditionInfo AdditionalInformation;          //!< Provides additional information to the server.
    FileFullEaInformation  Flags;                //!< The flags MUST be set to a combination of zero or more of these bit values for a FileFullEaInformation query.
    uint64_t  PersistentFileId;                  //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    uint64_t  VolatileFileId;                    //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    uint8_t   Buffer[1];                         //!< A variable-length buffer containing the input buffer for the request, as described by the InputBufferOffset and InputBufferLength fields.
}  __attribute__ ((__packed__));

/*!
 * \brief The query_infoResponse struct
 * The SMB2 QUERY_INFO Response packet is sent by the server
 * in response to an SMB2 QUERY_INFO Request packet.
 */
struct QueryInfoResponse
{
    uint16_t structureSize;                      //!< Must be 9
    uint16_t OutputBufferOffset;                 //!< The offset, in bytes, from the beginning of the SMB2 header to the information being returned.
    uint32_t OutputBufferLength;                 //!< The length, in bytes, of the information being returned.
    uint8_t   Buffer[1];                         //!< A variable-length buffer that contains the information that is returned in the response, as described by the OutputBufferOffset and OutputBufferLength fields
}  __attribute__ ((__packed__));

/*!
 */
enum class OpFlags : uint8_t
{
    SMB2_RESTART_SCANS       = 0x01,             //!< The server MUST restart the enumeration from the beginning, but the search pattern is not changed.
    SMB2_RETURN_SINGLE_ENTRY = 0x02,             //!< The server MUST only return the first entry of the search results.
    SMB2_INDEX_SPECIFIED     = 0x04,             //!< The server SHOULD<64> return entries beginning at the byte number specified by FileIndex.
    SMB2_REOPEN              = 0x10              //!< The server MUST restart the enumeration from the beginning, and the search pattern MUST be changed to the provided value. This often involves silently closing and reopening the directory on the server side.
};

/*!
 * \brief The QueryDirRequest struct
 * The SMB2 QUERY_DIRECTORY Request packet is sent by the client
 * to obtain a directory enumeration on a directory open.
 */
struct QueryDirRequest
{
    uint16_t structureSize;                      //!< Must be 33
    QueryInfoLevels infoType;                    //!< The file information class describing the format that data MUST be returned in.
    OpFlags  flags;                              //!< Flags indicating how the query directory operation MUST be processed
    uint32_t FileIndex;                          //!< The byte offset within the directory, indicating the position at which to resume the enumeration
    uint64_t PersistentFileId;                   //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    uint64_t VolatileFileId;                     //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    uint16_t FileNameOffset;                     //!< The offset, in bytes, from the beginning of the SMB2 header to the search pattern to be used for the enumeration
    uint16_t FileNameLength;                     //!< The length, in bytes, of the search pattern. This field MUST be 0 if no search pattern is provided
    uint32_t OutputBufferLength;                 //!< The maximum number of bytes the server is allowed to return in the SMB2 QUERY_DIRECTORY Response.
    uint8_t  Buffer[1];                          //!< A variable-length buffer containing the Unicode search pattern for the request, as described by the FileNameOffset and FileNameLength fields
}  __attribute__ ((__packed__));

/*!
 * \brief The QueryDirResponse struct
 * The SMB2 QUERY_DIRECTORY Response packet is sent by a server in
 * response to an SMB2 QUERY_DIRECTORY Reques
 */
struct QueryDirResponse
{
    uint16_t structureSize;                      //!< Must be 9
    uint16_t OutputBufferOffset;                 //!< The offset, in bytes, from the beginning of the SMB2 header to the directory enumeration data being returned.
    uint32_t OutputBufferLength;                 //!< The length, in bytes, of the directory enumeration being returned.
    uint8_t  Buffer[1];                          //!< A variable-length buffer containing the directory enumeration being returned in the response, as described by the OutputBufferOffset and OutputBufferLength
}  __attribute__ ((__packed__));

/*!
 * \brief The FlushRequest struct
 * The SMB2 FLUSH Request packet is sent by a client to
 * request that a server flush all cached file information
 * for a specified open of a file to the persistent store that backs the file
 */
struct FlushRequest
{
    uint16_t structureSize;                      //!< Must be 24
    uint16_t reserved1;                          //!< This field MUST NOT be used and MUST be reserved. The client may set this to 0, and the server MUST ignore it on receipt.
    uint32_t reserved2;                          //!< This field MUST NOT be used and MUST be reserved. The client may set this to 0, and the server MUST ignore it on receipt.
    uint64_t PersistentFileId;                   //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    uint64_t VolatileFileId;                     //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
}  __attribute__ ((__packed__));

/*!
 * \brief The FlushResponse struct
 * The SMB2 FLUSH Request packet is sent by a client to
 * request that a server flush all cached file information
 * for a specified open of a file to the persistent store that backs the file
 */
struct FlushResponse
{
    uint16_t structureSize;                      //!< Must be 4
    uint16_t reserved1;                          //!< This field MUST NOT be used and MUST be reserved. The server may set this to 0, and the client MUST ignore it on receipt.
}  __attribute__ ((__packed__));

/*!
 * For the SMB 2.002, 2.1 and 3.0 dialects,
 * this field MUST NOT be used and MUST be reserved.
 * The client MUST set this field to 0, and the server MUST
 * ignore it on receipt. Used by the SMB 3.02 dialect.
 */
enum class BufferingFlags : uint8_t
{
    NONE                          = 0x00,        //!< Default for SMB 2.002, 2.1 and 3.0 dialects
    SMB2_READFLAG_READ_UNBUFFERED = 0x01,        //!< The server or underlying object store SHOULD NOT cache the read data at intermediate layers.
};

/*!
 * For SMB 2.002 and 2.1 dialects, this field MUST NOT be used and MUST be reserved.
 * The client MUST set this field to 0, and the server MUST ignore it on receipt.
 */
enum class Channels : uint32_t
{
    SMB2_CHANNEL_NONE               = 0x00000000,//!< No channel information is present in the request. The ReadChannelInfoOffset and ReadChannelInfoLength fields MUST be set to 0 by the client and MUST be ignored by the server.
    SMB2_CHANNEL_RDMA_V1            = 0x00000001,//!< One or more SMB_DIRECT_BUFFER_DESCRIPTOR_V1 structures as specified in [MS-SMBD] section 2.2.3.1 are present in the channel information specified by ReadChannelInfoOffset and ReadChannelInfoLength fields.
    SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x00000002,//!< This value is valid only for the SMB 3.02 dialect. One or more SMB_DIRECT_BUFFER_DESCRIPTOR_V1 structures, as specified in [MS-SMBD] section 2.2.3.1, are present in the channel information specified by the ReadChannelInfoOffset and ReadChannelInfoLength fields. The server is requested to perform remote invalidation when responding to the request as specified in [MS-SMBD] section 3.1.4.2.
};

/*!
 * \brief The ReadRequest structure
 * The SMB2 READ Request packet is sent by the client
 * to request a read operation on the file that is specified by the FileId
 */
struct ReadRequest
{
    uint16_t structureSize;                      //!< Must be 49
    uint8_t  padding;                            //!< The requested offset from the start of the SMB2 header, in bytes, at which to place the data read in the SMB2 READ Response
    BufferingFlags flags;                        //!< For the SMB 2.002, 2.1 and 3.0 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. Used by SMB 3.02 dialect
    uint32_t length;                             //!< The length, in bytes, of the data to read from the specified file or pipe. The length of the data being read may be zero bytes.
    uint64_t offset;                             //!< The offset, in bytes, into the file from which the data MUST be read
    uint64_t persistentFileId;                   //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    uint64_t volatileFileId;                     //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    uint32_t minimumCount;                       //!< The minimum number of bytes to be read for this operation to be successful
    Channels channel;                            //!< For SMB 2.002 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt.
    uint32_t RemainingBytes;                     //!< The number of subsequent bytes that the client intends to read from the file after this operation completes. This value is provided to facilitate read-ahead caching, and is not binding on the server.
    uint32_t ReadChannelInfoOffset;              //!< For the SMB 2.002 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, it contains the offset, in bytes, from the beginning of the SMB2 header to the channel data as specified by the Channel field of the request.
    uint32_t ReadChannelInfoLength;              //!< For the SMB 2.002 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, it contains the length, in bytes, of the channel data as specified by the Channel field of the request.
    uint8_t  Buffer[1];                          //!< A variable-length buffer that contains the read channel information, as described by ReadChannelInfoOffset and ReadChannelInfoLength. Unused at present. The client MUST set one byte of this field to 0, and the server MUST ignore it on receipt.
}  __attribute__ ((__packed__));

/*!
 * \brief The ReadResponse structure
 * The SMB2 READ Response packet is sent in response
 * to an SMB2 READ Request packet
 */
struct ReadResponse
{
    uint16_t structureSize;                      //!< Must be 17
    uint8_t  DataOffset;                         //!< The offset, in bytes, from the beginning of the header to the data read being returned in this response
    uint8_t  Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
    uint32_t DataLength;                         //!< The length, in bytes, of the data read being returned in this response.
    uint32_t DataRemaining;                      //!< The length, in bytes, of the data being sent on the Channel specified in the request
    uint32_t Reserved2;                          //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
    uint8_t  Buffer[1];                          //!< A variable-length buffer that contains the data read for the response, as described by DataOffset and DataLength. The minimum length is 1 byte. If 0 bytes are returned from the underlying object store, the server MUST send a failure response with status equal to STATUS_END_OF_FILE.
}  __attribute__ ((__packed__));

/*!
 * A Flags field indicates how to process the operation.
 * This field MUST be constructed using zero or more of possible values
 */
enum class WriteFlags : uint32_t
{
    SMB2_WRITEFLAG_WRITE_THROUGH    = 0x00000001,//!< The write data should be written to persistent storage before the response is sent regardless of how the file was opened. This value is not valid for the SMB 2.002 dialect.
    SMB2_WRITEFLAG_WRITE_UNBUFFERED = 0x00000002,//!< The server or underlying object store SHOULD NOT cache the write data at intermediate layers and SHOULD allow it to flow through to persistent storage. This bit is only valid for the SMB 3.02 dialect.
};

/*!
 * \brief The WriteRequest structure
 * The SMB2 WRITE Request packet is sent by the client
 * to write data to the file or named pipe on the server.
 */
struct WriteRequest
{
    uint16_t structureSize;                      //!< The client MUST set this field to 49, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent.
    uint16_t dataOffset;                         //!< The offset, in bytes, from the beginning of the SMB2 header to the data being written.
    uint32_t Length;                             //!< The length of the data being written, in bytes. The length of the data being written may be zero bytes.
    uint64_t Offset;                             //!< he offset, in bytes, of where to write the data in the destination file. If the write is being executed on a pipe, the Offset MUST be set to 0 by the client and MUST be ignored by the server.
    uint64_t persistentFileId;                   //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    uint64_t volatileFileId;                     //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    Channels Channel;                            //!< For the SMB 2.002 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, this field MUST contain exactly one of possible values
    uint32_t RemainingBytes;                     //!< The number of subsequent bytes the client intends to write to the file after this operation completes. This value is provided to facilitate write caching and is not binding on the server
    uint16_t WriteChannelInfoOffset;             //!< For the SMB 2.002 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, it contains the offset, in bytes, from the beginning of the SMB2 header to the channel data as described by the Channel field of the request.
    uint16_t WriteChannelInfoLength;             //!< For the SMB 2.002 and SMB 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, it contains the offset, in bytes, from the beginning of the SMB2 header to the channel data as described by the Channel field of the request.
    WriteFlags Flags;                            //!< A Flags field indicates how to process the operation. This field MUST be constructed using zero or more of possible values
    uint8_t  Buffer[1];                          //!< A variable-length buffer that contains the data to write and the write channel information, as described by DataOffset, Length, WriteChannelInfoOffset, and WriteChannelInfoLength.
}  __attribute__ ((__packed__));

/*!
 * \brief The WriteResponse structure
 * The SMB2 WRITE Response packet is sent in response to an
 * SMB2 WRITE Request packet
 */
struct WriteResponse
{
//FIXME: size must be 17, but actual structure size = 16. Why?
    uint16_t structureSize;                      //!< The server MUST set this field to 17, the actual size of the response structure notwithstanding.
    uint16_t reserved1;                          //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
    uint32_t Count;                              //!< The number of bytes written.
    uint32_t Remaining;                          //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
    uint16_t WriteChannelInfoOffset;             //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
    uint16_t WriteChannelInfoLength;             //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
}  __attribute__ ((__packed__));

/*!
 * The description of how the range is being locked or
 * unlocked and how to process the operation
 */
enum class LockFlags : uint32_t
{
    SMB2_LOCKFLAG_SHARED_LOCK      = 0x00000001, //!< The range MUST be locked shared, allowing other opens to read from or take a shared lock on the range. All opens MUST NOT be allowed to write within the range. Other locks can be requested and taken on this range.
    SMB2_LOCKFLAG_EXCLUSIVE_LOCK   = 0x00000002, //!< The range MUST be locked exclusive, not allowing other opens to read, write, or lock within the range.
    SMB2_LOCKFLAG_UNLOCK           = 0x00000004, //!< The range MUST be unlocked from a previous lock taken on this range. The unlock range MUST be identical to the lock range. Sub-ranges cannot be unlocked.
    SMB2_LOCKFLAG_FAIL_IMMEDIATELY = 0x00000010, //!< The lock operation MUST fail immediately if it conflicts with an existing lock, instead of waiting for the range to become available.
};

/*!
 * \brief The Lock structure
 * The SMB2_LOCK_ELEMENT Structure packet is used by the SMB2 LOCK
 * Request packet to indicate segments of files that
 * should be locked or unlocked.
 */
struct Lock
{
    uint64_t Offset;                             //!<  The starting offset, in bytes, in the destination file from where the range being locked or unlocked starts.
    uint64_t Length;                             //!< The length, in bytes, of the range being locked or unlocked.
    LockFlags Flags;                             //!< The description of how the range is being locked or unlocked and how to process the operation
    uint32_t Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
} __attribute__ ((__packed__));

/*!
 * \brief The LockRequest structure
 */
struct LockRequest
{
    uint16_t structureSize;                      //!< The client MUST set this to 48
    uint16_t LockCount;                          //!< TMUST be set to the number of SMB2_LOCK_ELEMENT structures that are contained in the Locks[] array. The lock count MUST be greater than or equal to 1.
    uint32_t LockSequence;                       //!< The client MUST set this to 48, indicating the size of an SMB2 LOCK Request with a single SMB2_LOCK_ELEMENT structure. This value is set regardless of the number of locks that are sent.
    uint64_t persistentFileId;                   //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    uint64_t volatileFileId;                     //!< An SMB2_FILEID identifier of the file or named pipe on which to perform the query.
    Lock     locks[1];                           //!< An array of LockCount (SMB2_LOCK_ELEMENT) structures that define the ranges to be locked or unlocked.
}  __attribute__ ((__packed__));

/*!
 * \brief The LockResponse structure
 */
struct LockResponse
{
    uint16_t structureSize;                      //!< The server MUST set this to 4
    uint16_t Reserved;                           //!< This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt.
}  __attribute__ ((__packed__));

} // namespace SMBv2
} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//_SMBv2_COMMANDS_H
//------------------------------------------------------------------------------
