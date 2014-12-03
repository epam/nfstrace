//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Helpers for parsing CIFS structures.
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
#ifndef CIFS_HEADER_H
#define CIFS_HEADER_H
//------------------------------------------------------------------------------
#include <cstdint>

#include "protocols/netbios/netbios.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace CIFSv1
{

/*! Flags of message
 */
enum class Flags : uint8_t
{
    LOCK_AND_READ_OK              = 0x01, //!< This bit is set (1) in the SMB_COM_NEGOTIATE (0x72) Response (section 2.2.4.52.2) if the server supports SMB_COM_LOCK_AND_READ (0x13) (section 2.2.4.20) and SMB_COM_WRITE_AND_UNLOCK (0x14) (section 2.2.4.21) commands.
    BUF_AVAIL                     = 0x02, //!< Obsolete. When set (on an SMB request being sent to the server), the client guarantees that there is a receive buffer posted such that a send without acknowledgment can be used by the server to respond to the client's request. This behavior is specific to an obsolete transport. This bit MUST be set to zero by the client and MUST be ignored by the server.
    Reserved                      = 0x04, //!< This flag MUST be set to zero by the client and MUST be ignored by the server.
    CASE_INSENSITIVE              = 0x08, //!< Obsolete. If this bit is set then all pathnames in the SMB SHOULD be treated as case-insensitive.<26>
    CANONICALIZED_PATHS           = 0x10, //!< Obsolescent. When set in session setup, this bit indicates that all paths sent to the server are already in canonical format. That is, all file and directory names are composed of valid file name characters in all upper-case, and that the path segments are separated by backslash characters ('\').
    OPLOCK                        = 0x20, //!< Obsolescent. This bit has meaning only in the deprecatedSMB_COM_OPEN (0x02) Request (section 2.2.4.3.1), SMB_COM_CREATE (0x03) Request (section 2.2.4.4.1), and SMB_COM_CREATE_NEW (0x0F) Request (section 2.2.4.16.1) messages, where it is used to indicate that the client is requesting an Exclusive OpLock. It SHOULD be set to zero by the client, and ignored by the server, in all other SMB requests. If the server grants this OpLock request, then this bit SHOULD remain set in the corresponding response SMB to indicate to the client that the OpLock request was granted.
    OPBATCH                       = 0x40, //!< Obsolescent. This bit has meaning only in the deprecated SMB_COM_OPEN (0x02) Request (section 2.2.4.3.1), SMB_COM_CREATE (0x03) Request (section 2.2.4.4.1), and SMB_COM_CREATE_NEW (0x0F) Request (section 2.2.4.16.1) messages, where it is used to indicate that the client is requesting a Batch OpLock. It SHOULD be set to zero by the client, and ignored by the server, in all other SMB requests. If the server grants this OpLock request, then this bit SHOULD remain set in the corresponding response SMB to indicate to the client that the OpLock request was granted. If the SMB_FLAGS_OPLOCK bit is clear (0), then the SMB_FLAGS_OPBATCH bit is ignored.
    REPLY                         = 0x80, //!< When on, this message is being sent from the server in response to a client request. The Command field usually contains the same value in a protocol request from the client to the server as in the matching response from the server to the client. This bit unambiguously distinguishes the message as a server response.
};

/*! CIFS commands
 */
enum class Commands : uint8_t
{
    CREATE_DIRECTORY       =  0x00, //!< Create a new directory.
    DELETE_DIRECTORY       =  0x01, //!< Delete an empty directory.
    OPEN                   =  0x02, //!< Open a file.
    CREATE                 =  0x03, //!< Create or open a file.
    CLOSE                  =  0x04, //!< Close a file.
    FLUSH                  =  0x05, //!< Flush data for a file
    DELETE                 =  0x06, //!< Delete a file.
    RENAME                 =  0x07, //!< Rename a file or set of files.
    QUERY_INFORMATION      =  0x08, //!< Get file attributes.
    SET_INFORMATION        =  0x09, //!< Set file attributes.
    READ                   =  0x0A, //!< Read from a file.
    WRITE                  =  0x0B, //!< Write to a file.
    LOCK_BYTE_RANGE        =  0x0C, //!< Request a byte-range lock on a file.
    UNLOCK_BYTE_RANGE      =  0x0D, //!< Release a byte-range lock on a file.
    CREATE_TEMPORARY       =  0x0E, //!< Create a temporary file.
    CREATE_NEW             =  0x0F, //!< Create and open a new file.
    CHECK_DIRECTORY        =  0x10, //!< Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation.
    PROCESS_EXIT           =  0x11, //!< Indicate process exit.
    SEEK                   =  0x12, //!< Set the current file pointer within a file.
    LOCK_AND_READ          =  0x13, //!< Lock and read a byte-range within a file.
    WRITE_AND_UNLOCK       =  0x14, //!< Write and unlock a byte-range within a file.
    READ_RAW               =  0x1A, //!< Read a block in raw mode.
    READ_MPX               =  0x1B, //!< Multiplexed block read. Listed as SMBreadmpx in some documentation.
    READ_MPX_SECONDARY     =  0x1C, //!< Multiplexed block read
    WRITE_RAW              =  0x1D, //!< Write a block in raw mode.
    WRITE_MPX              =  0x1E, //!< Multiplexed block write.
    WRITE_MPX_SECONDARY    =  0x1F, //!< Multiplexed block write
    WRITE_COMPLETE         =  0x20, //!< Raw block write
    QUERY_SERVER           =  0x21, //!< Reserved
    SET_INFORMATION2       =  0x22, //!< Set an extended set of file attributes.
    QUERY_INFORMATION2     =  0x23, //!< Get an extended set of file attributes.
    LOCKING_ANDX           =  0x24, //!< Lock multiple byte ranges; AndX chaining.
    TRANSACTION            =  0x25, //!< Transaction.
    TRANSACTION_SECONDARY  =  0x26, //!< Transaction secondary request.
    IOCTL                  =  0x27, //!< Pass an I/O Control function request to the server.
    IOCTL_SECONDARY        =  0x28, //!< IOCTL secondary request.
    COPY                   =  0x29, //!< Copy a file or directory.
    MOVE                   =  0x2A, //!< Move a file or directory.
    ECHO                   =  0x2B, //!< Echo request (ping).
    WRITE_AND_CLOSE        =  0x2C, //!< Write to and close a file.
    OPEN_ANDX              =  0x2D, //!< Extended file open with AndX chaining.
    READ_ANDX              =  0x2E, //!< Extended file read with AndX chaining.
    WRITE_ANDX             =  0x2F, //!< Extended file write with AndX chaining.
    NEW_FILE_SIZE          =  0x30, //!< Reserved
    CLOSE_AND_TREE_DISC    =  0x31, //!< Close an open file and tree disconnect.
    TRANSACTION2           =  0x32, //!< Transaction 2 format request/response.
    TRANSACTION2_SECONDARY =  0x33, //!< Transaction 2 secondary request.
    FIND_CLOSE2            =  0x34, //!< Close an active search.
    FIND_NOTIFY_CLOSE      =  0x35, //!< Notification of the closure of an active search.
    TREE_CONNECT           =  0x70, //!< Tree connect.
    TREE_DISCONNECT        =  0x71, //!< Tree disconnect.
    NEGOTIATE              =  0x72, //!< Negotiate protocol dialect.
    SESSION_SETUP_ANDX     =  0x73, //!< Session Setup with AndX chaining.
    LOGOFF_ANDX            =  0x74, //!< User logoff with AndX chaining.
    TREE_CONNECT_ANDX      =  0x75, //!< Tree connect with AndX chaining.
    SECURITY_PACKAGE_ANDX  =  0x7E, //!< Negotiate security packages with AndX chaining.
    QUERY_INFORMATION_DISK =  0x80, //!< Retrieve file system information from the server.
    SEARCH                 =  0x81, //!< Directory wildcard search.
    FIND                   =  0x82, //!< Start or continue an extended wildcard directory search.
    FIND_UNIQUE            =  0x83, //!< Perform a one-time extended wildcard directory search.
    FIND_CLOSE             =  0x84, //!< End an extended wildcard directory search.
    NT_TRANSACT            =  0xA0, //!< NT format transaction request/response.
    NT_TRANSACT_SECONDARY  =  0xA1, //!< NT format transaction secondary request.
    NT_CREATE_ANDX         =  0xA2, //!< Create or open a file or a directory.
    NT_CANCEL              =  0xA4, //!< Cancel a request currently pending at the server.
    NT_RENAME              =  0xA5, //!< File rename with extended semantics.
    OPEN_PRINT_FILE        =  0xC0, //!< Create a print queue spool file.
    WRITE_PRINT_FILE       =  0xC1, //!< Write to a print queue spool file.
    CLOSE_PRINT_FILE       =  0xC2, //!< Close a print queue spool file.
    GET_PRINT_QUEUE        =  0xC3, //!< Request print queue information.
    READ_BULK              =  0xD8, //!< Reserved
    WRITE_BULK             =  0xD9, //!< Reserved
    WRITE_BULK_DATA        =  0xDA, //!< Reserved
    INVALID                =  0xFE, //!< As the name suggests
    NO_ANDX_COMMAND        =  0xFF  //!<  Also known as the NIL command. It identifies the end of an AndX Chain
};

/*! SMB protocol codes
 */
enum class ProtocolCodes : uint8_t
{
    SMB2 = 0xFE,     //!< SMB v2.0-2.1
    SMB1 = 0xFF      //!< SMB v.1.0
};

/*! \class First part of CIFS header
 */
struct MessageHeaderHead
{
    ProtocolCodes protocol_code;//!< Protocol version - 0xFF or 0xF3
    int8_t protocol[3];//!< Protocol name (SMB)
} __attribute__ ((__packed__));

/*! Security field for CIFS header
 */
struct SecurityField
{
    int8_t key[4];//!< Somethink about security
    int16_t CID;//!< A connection identifier (CID).
    int16_t sequenceNumber;//!< A number used to identify the sequence of a message over connectionless transports.
};

/*! \class Raw CIFS message header
 */
struct RawMessageHeader
{
    union {
        MessageHeaderHead head;//!< Head of header
        uint32_t head_code;//!< For fast checking
    };
    Commands cmd_code;//!< Code of SMB command
    int32_t status;//!< Used to communicate error messages from the server to the client.
    Flags flags;//!< 1-bit flags describing various features in effect for the message.
    uint8_t flags2[2];//!< A 16-bit field of 1-bit flags that represent various features in effect for the message. Unspecified bits are reserved and MUST be zero.

    int16_t PIDHigh;//!< If set to a nonzero value, this field represents the high-order bytes of a process identifier (PID). It is combined with the PIDLow field below to form a full PID.
    union  // Depends on command
    {
        int8_t securityFeatures[8];//!< Somethink about security
        SecurityField sec;//!< Security field structure
    };
    int16_t _;//!< Reserved

    int16_t TID;//!< A tree identifier
    int16_t PIDLow;//!< The lower 16-bits of the PID

    int16_t UID;//!< A user identifier
    int16_t MID;//!< A multiplex identifier
} __attribute__ ((__packed__));

/*! High level user friendly message structure
 */
struct MessageHeader : public RawMessageHeader
{
    /*! Check flag
     * \param flag - flag to be check
     * \return True, if flag set, and False in other case
     */
    bool isFlag(const Flags flag) const;
};

/*! Check is data valid CIFS message's header and return header or nullptr
 * \param data - raw packet data
 * \return pointer to input data which is casted to header structure or nullptr (if it is not valid header)
 */
const MessageHeader* get_header(const uint8_t* data);

/*! Constructs new command for API from raw message
 * \param request - Call's header
 * \param response - Reply's header
 * \return Command structure
 */
template <typename Cmd, typename Data>
inline const Cmd command(Data& request, Data& response)
{
    Cmd cmd;
    if (const MessageHeader* header = get_header(request->data))
    {
        cmd.session = header->sec.CID;
    }
    // Set time stamps
    cmd.ctimestamp = request->timestamp;
    cmd.rtimestamp = response->timestamp;

    return cmd;
}

} // CIFS

} // protocols
} // NST
//------------------------------------------------------------------------------
#endif // CIFS_HEADER_H
//------------------------------------------------------------------------------
