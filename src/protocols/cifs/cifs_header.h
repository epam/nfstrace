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
#include <sys/types.h>

#include "protocols/netbios/netbios_header.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace CIFS
{

/*! CIFS commands
 */
enum class Commands : u_int8_t {
    SMB_COM_CREATE_DIRECTORY       =  0x00, //!< Create a new directory.
    SMB_COM_DELETE_DIRECTORY       =  0x01, //!< Delete an empty directory.
    SMB_COM_OPEN                   =  0x02, //!< Open a file.
    SMB_COM_CREATE                 =  0x03, //!< Create or open a file.
    SMB_COM_CLOSE                  =  0x04, //!< Close a file.
    SMB_COM_FLUSH                  =  0x05, //!< Flush data for a file
    SMB_COM_DELETE                 =  0x06, //!< Delete a file.
    SMB_COM_RENAME                 =  0x07, //!< Rename a file or set of files.
    SMB_COM_QUERY_INFORMATION      =  0x08, //!< Get file attributes.
    SMB_COM_SET_INFORMATION        =  0x09, //!< Set file attributes.
    SMB_COM_READ                   =  0x0A, //!< Read from a file.
    SMB_COM_WRITE                  =  0x0B, //!< Write to a file.
    SMB_COM_LOCK_BYTE_RANGE        =  0x0C, //!< Request a byte-range lock on a file.
    SMB_COM_UNLOCK_BYTE_RANGE      =  0x0D, //!< Release a byte-range lock on a file.
    SMB_COM_CREATE_TEMPORARY       =  0x0E, //!< Create a temporary file.
    SMB_COM_CREATE_NEW             =  0x0F, //!< Create and open a new file.
    SMB_COM_CHECK_DIRECTORY        =  0x10, //!< Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation.
    SMB_COM_PROCESS_EXIT           =  0x11, //!< Indicate process exit.
    SMB_COM_SEEK                   =  0x12, //!< Set the current file pointer within a file.
    SMB_COM_LOCK_AND_READ          =  0x13, //!< Lock and read a byte-range within a file.
    SMB_COM_WRITE_AND_UNLOCK       =  0x14, //!< Write and unlock a byte-range within a file.
    SMB_COM_READ_RAW               =  0x1A, //!< Read a block in raw mode.
    SMB_COM_READ_MPX               =  0x1B, //!< Multiplexed block read. Listed as SMBreadmpx in some documentation.
    SMB_COM_READ_MPX_SECONDARY     =  0x1C, //!< Multiplexed block read
    SMB_COM_WRITE_RAW              =  0x1D, //!< Write a block in raw mode.
    SMB_COM_WRITE_MPX              =  0x1E, //!< Multiplexed block write.
    SMB_COM_WRITE_MPX_SECONDARY    =  0x1F, //!< Multiplexed block write
    SMB_COM_WRITE_COMPLETE         =  0x20, //!< Raw block write
    SMB_COM_QUERY_SERVER           =  0x21, //!< Reserved
    SMB_COM_SET_INFORMATION2       =  0x22, //!< Set an extended set of file attributes.
    SMB_COM_QUERY_INFORMATION2     =  0x23, //!< Get an extended set of file attributes.
    SMB_COM_LOCKING_ANDX           =  0x24, //!< Lock multiple byte ranges; AndX chaining.
    SMB_COM_TRANSACTION            =  0x25, //!< Transaction.
    SMB_COM_TRANSACTION_SECONDARY  =  0x26, //!< Transaction secondary request.
    SMB_COM_IOCTL                  =  0x27, //!< Pass an I/O Control function request to the server.
    SMB_COM_IOCTL_SECONDARY        =  0x28, //!< IOCTL secondary request.
    SMB_COM_COPY                   =  0x29, //!< Copy a file or directory.
    SMB_COM_MOVE                   =  0x2A, //!< Move a file or directory.
    SMB_COM_ECHO                   =  0x2B, //!< Echo request (ping).
    SMB_COM_WRITE_AND_CLOSE        =  0x2C, //!< Write to and close a file.
    SMB_COM_OPEN_ANDX              =  0x2D, //!< Extended file open with AndX chaining.
    SMB_COM_READ_ANDX              =  0x2E, //!< Extended file read with AndX chaining.
    SMB_COM_WRITE_ANDX             =  0x2F, //!< Extended file write with AndX chaining.
    SMB_COM_NEW_FILE_SIZE          =  0x30, //!< Reserved
    SMB_COM_CLOSE_AND_TREE_DISC    =  0x31, //!< Close an open file and tree disconnect.
    SMB_COM_TRANSACTION2           =  0x32, //!< Transaction 2 format request/response.
    SMB_COM_TRANSACTION2_SECONDARY =  0x33, //!< Transaction 2 secondary request.
    SMB_COM_FIND_CLOSE2            =  0x34, //!< Close an active search.
    SMB_COM_FIND_NOTIFY_CLOSE      =  0x35, //!< Notification of the closure of an active search.
    SMB_COM_TREE_CONNECT           =  0x70, //!< Tree connect.
    SMB_COM_TREE_DISCONNECT        =  0x71, //!< Tree disconnect.
    SMB_COM_NEGOTIATE              =  0x72, //!< Negotiate protocol dialect.
    SMB_COM_SESSION_SETUP_ANDX     =  0x73, //!< Session Setup with AndX chaining.
    SMB_COM_LOGOFF_ANDX            =  0x74, //!< User logoff with AndX chaining.
    SMB_COM_TREE_CONNECT_ANDX      =  0x75, //!< Tree connect with AndX chaining.
    SMB_COM_SECURITY_PACKAGE_ANDX  =  0x7E, //!< Negotiate security packages with AndX chaining.
    SMB_COM_QUERY_INFORMATION_DISK =  0x80, //!< Retrieve file system information from the server.
    SMB_COM_SEARCH                 =  0x81, //!< Directory wildcard search.
    SMB_COM_FIND                   =  0x82, //!< Start or continue an extended wildcard directory search.
    SMB_COM_FIND_UNIQUE            =  0x83, //!< Perform a one-time extended wildcard directory search.
    SMB_COM_FIND_CLOSE             =  0x84, //!< End an extended wildcard directory search.
    SMB_COM_NT_TRANSACT            =  0xA0, //!< NT format transaction request/response.
    SMB_COM_NT_TRANSACT_SECONDARY  =  0xA1, //!< NT format transaction secondary request.
    SMB_COM_NT_CREATE_ANDX         =  0xA2, //!< Create or open a file or a directory.
    SMB_COM_NT_CANCEL              =  0xA4, //!< Cancel a request currently pending at the server.
    SMB_COM_NT_RENAME              =  0xA5, //!< File rename with extended semantics.
    SMB_COM_OPEN_PRINT_FILE        =  0xC0, //!< Create a print queue spool file.
    SMB_COM_WRITE_PRINT_FILE       =  0xC1, //!< Write to a print queue spool file.
    SMB_COM_CLOSE_PRINT_FILE       =  0xC2, //!< Close a print queue spool file.
    SMB_COM_GET_PRINT_QUEUE        =  0xC3, //!< Request print queue information.
    SMB_COM_READ_BULK              =  0xD8, //!< Reserved
    SMB_COM_WRITE_BULK             =  0xD9, //!< Reserved
    SMB_COM_WRITE_BULK_DATA        =  0xDA, //!< Reserved
    SMB_COM_INVALID                =  0xFE, //!< As the name suggests
    SMB_COM_NO_ANDX_COMMAND        =  0xFF //!<  Also known as the NIL command. It identifies the end of an AndX Chain
};

/*! SMB protocol codes
 */
enum class ProtocolCodes : u_int8_t {
    SMB2 = 0xF3,     //!< SMB v2.0-2.1
    SMB1 = 0xFF      //!< SMB v.1.0
};

#pragma pack(push,1)

/*! \class CIFS message header
 */
struct MessageHeader {
    ProtocolCodes protocol_code;//!< Always 0xFF or 0xF3
    int8_t protocol[3];//!< Protocol name (SMB)
    Commands cmd_code;//!< Code of SMB command
    int8_t other[27];//FIXME: SMB header to be precised!

    /*! Returns command description. Performance may be affected!
     * \return description of the command
     */
    std::string commandDescription() const;
};

#pragma pack(pop)

/*! Check is data valid CIFS message's header and return header or nullptr
 * \param data - raw packet data
 * \return pointer to input data which is casted to header structure or nullptr (if it is not valid header)
 */
const MessageHeader *get_header(const u_int8_t* data);

}

}
}

#endif // CIFS_HEADER_H
