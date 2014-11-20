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
#include <cstring>
#include <map>
#include <string>

#include "protocols/cifs/cifs_header.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::CIFS;
using namespace std;

static const char * const smbProtocolName = "SMB";

const MessageHeader *NST::protocols::CIFS::get_header(const u_int8_t* data)
{
   const MessageHeader* header {reinterpret_cast<const MessageHeader*>(data)};
   if (std::memcmp(header->protocol, smbProtocolName, sizeof(header->protocol)) == 0) {
       if (header->protocol_code == ProtocolCodes::SMB1) {
           return header;
       }
   }
   return nullptr;
}

std::string MessageHeader::commandDescription() const
{
    static map<Commands, string> cmdNames;
    if (cmdNames.empty()) {
        cmdNames[Commands::SMB_COM_CREATE_DIRECTORY] = "SMB_COM_CREATE_DIRECTORY: Create a new directory.";
        cmdNames[Commands::SMB_COM_DELETE_DIRECTORY] = "SMB_COM_DELETE_DIRECTORY: Delete an empty directory.";
        cmdNames[Commands::SMB_COM_OPEN] = "SMB_COM_OPEN: Open a file.";
        cmdNames[Commands::SMB_COM_CREATE] = "SMB_COM_CREATE: Create or open a file.";
        cmdNames[Commands::SMB_COM_CLOSE] = "SMB_COM_CLOSE: Close a file.";
        cmdNames[Commands::SMB_COM_FLUSH] = "SMB_COM_FLUSH: Flush data for a file";
        cmdNames[Commands::SMB_COM_DELETE] = "SMB_COM_DELETE: Delete a file.";
        cmdNames[Commands::SMB_COM_RENAME] = "SMB_COM_RENAME: Rename a file or set of files.";
        cmdNames[Commands::SMB_COM_QUERY_INFORMATION] = "SMB_COM_QUERY_INFORMATION: Get file attributes.";
        cmdNames[Commands::SMB_COM_SET_INFORMATION] = "SMB_COM_SET_INFORMATION: Set file attributes.";
        cmdNames[Commands::SMB_COM_READ] = "SMB_COM_READ: Read from a file.";
        cmdNames[Commands::SMB_COM_WRITE] = "SMB_COM_WRITE: Write to a file.";
        cmdNames[Commands::SMB_COM_LOCK_BYTE_RANGE] = "SMB_COM_LOCK_BYTE_RANGE: Request a byte-range lock on a file.";
        cmdNames[Commands::SMB_COM_UNLOCK_BYTE_RANGE] = "SMB_COM_UNLOCK_BYTE_RANGE: Release a byte-range lock on a file.";
        cmdNames[Commands::SMB_COM_CREATE_TEMPORARY] = "SMB_COM_CREATE_TEMPORARY: Create a temporary file.";
        cmdNames[Commands::SMB_COM_CREATE_NEW] = "SMB_COM_CREATE_NEW: Create and open a new file.";
        cmdNames[Commands::SMB_COM_CHECK_DIRECTORY] = "SMB_COM_CHECK_DIRECTORY: Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation.";
        cmdNames[Commands::SMB_COM_PROCESS_EXIT] = "SMB_COM_PROCESS_EXIT: Indicate process exit.";
        cmdNames[Commands::SMB_COM_SEEK] = "SMB_COM_SEEK: Set the current file pointer within a file.";
        cmdNames[Commands::SMB_COM_LOCK_AND_READ] = "SMB_COM_LOCK_AND_READ: Lock and read a byte-range within a file.";
        cmdNames[Commands::SMB_COM_WRITE_AND_UNLOCK] = "SMB_COM_WRITE_AND_UNLOCK: Write and unlock a byte-range within a file.";
        cmdNames[Commands::SMB_COM_READ_RAW] = "SMB_COM_READ_RAW: Read a block in raw mode.";
        cmdNames[Commands::SMB_COM_READ_MPX] = "SMB_COM_READ_MPX: Multiplexed block read. Listed as SMBreadmpx in some documentation.";
        cmdNames[Commands::SMB_COM_READ_MPX_SECONDARY] = "SMB_COM_READ_MPX_SECONDARY: Multiplexed block read";
        cmdNames[Commands::SMB_COM_WRITE_RAW] = "SMB_COM_WRITE_RAW: Write a block in raw mode.";
        cmdNames[Commands::SMB_COM_WRITE_MPX] = "SMB_COM_WRITE_MPX: Multiplexed block write.";
        cmdNames[Commands::SMB_COM_WRITE_MPX_SECONDARY] = "SMB_COM_WRITE_MPX_SECONDARY: Multiplexed block write";
        cmdNames[Commands::SMB_COM_WRITE_COMPLETE] = "SMB_COM_WRITE_COMPLETE: Raw block write";
        cmdNames[Commands::SMB_COM_QUERY_SERVER] = "SMB_COM_QUERY_SERVER: Reserved";
        cmdNames[Commands::SMB_COM_SET_INFORMATION2] = "SMB_COM_SET_INFORMATION2: Set an extended set of file attributes.";
        cmdNames[Commands::SMB_COM_QUERY_INFORMATION2] = "SMB_COM_QUERY_INFORMATION2: Get an extended set of file attributes.";
        cmdNames[Commands::SMB_COM_LOCKING_ANDX] = "SMB_COM_LOCKING_ANDX: Lock multiple byte ranges; AndX chaining.";
        cmdNames[Commands::SMB_COM_TRANSACTION] = "SMB_COM_TRANSACTION: Transaction.";
        cmdNames[Commands::SMB_COM_TRANSACTION_SECONDARY] = "SMB_COM_TRANSACTION_SECONDARY: Transaction secondary request.";
        cmdNames[Commands::SMB_COM_IOCTL] = "SMB_COM_IOCTL: Pass an I/O Control function request to the server.";
        cmdNames[Commands::SMB_COM_IOCTL_SECONDARY] = "SMB_COM_IOCTL_SECONDARY: IOCTL secondary request.";
        cmdNames[Commands::SMB_COM_COPY] = "SMB_COM_COPY: Copy a file or directory.";
        cmdNames[Commands::SMB_COM_MOVE] = "SMB_COM_MOVE: Move a file or directory.";
        cmdNames[Commands::SMB_COM_ECHO] = "SMB_COM_ECHO: Echo request (ping).";
        cmdNames[Commands::SMB_COM_WRITE_AND_CLOSE] = "SMB_COM_WRITE_AND_CLOSE: Write to and close a file.";
        cmdNames[Commands::SMB_COM_OPEN_ANDX] = "SMB_COM_OPEN_ANDX: Extended file open with AndX chaining.";
        cmdNames[Commands::SMB_COM_READ_ANDX] = "SMB_COM_READ_ANDX: Extended file read with AndX chaining.";
        cmdNames[Commands::SMB_COM_WRITE_ANDX] = "SMB_COM_WRITE_ANDX: Extended file write with AndX chaining.";
        cmdNames[Commands::SMB_COM_NEW_FILE_SIZE] = "SMB_COM_NEW_FILE_SIZE: Reserved";
        cmdNames[Commands::SMB_COM_CLOSE_AND_TREE_DISC] = "SMB_COM_CLOSE_AND_TREE_DISC: Close an open file and tree disconnect.";
        cmdNames[Commands::SMB_COM_TRANSACTION2] = "SMB_COM_TRANSACTION2: Transaction 2 format request/response.";
        cmdNames[Commands::SMB_COM_TRANSACTION2_SECONDARY] = "SMB_COM_TRANSACTION2_SECONDARY: Transaction 2 secondary request.";
        cmdNames[Commands::SMB_COM_FIND_CLOSE2] = "SMB_COM_FIND_CLOSE2: Close an active search.";
        cmdNames[Commands::SMB_COM_FIND_NOTIFY_CLOSE] = "SMB_COM_FIND_NOTIFY_CLOSE: Notification of the closure of an active search.";
        cmdNames[Commands::SMB_COM_TREE_CONNECT] = "SMB_COM_TREE_CONNECT: Tree connect.";
        cmdNames[Commands::SMB_COM_TREE_DISCONNECT] = "SMB_COM_TREE_DISCONNECT: Tree disconnect.";
        cmdNames[Commands::SMB_COM_NEGOTIATE] = "SMB_COM_NEGOTIATE: Negotiate protocol dialect.";
        cmdNames[Commands::SMB_COM_SESSION_SETUP_ANDX] = "SMB_COM_SESSION_SETUP_ANDX: Session Setup with AndX chaining.";
        cmdNames[Commands::SMB_COM_LOGOFF_ANDX] = "SMB_COM_LOGOFF_ANDX: User logoff with AndX chaining.";
        cmdNames[Commands::SMB_COM_TREE_CONNECT_ANDX] = "SMB_COM_TREE_CONNECT_ANDX: Tree connect with AndX chaining.";
        cmdNames[Commands::SMB_COM_SECURITY_PACKAGE_ANDX] = "SMB_COM_SECURITY_PACKAGE_ANDX: Negotiate security packages with AndX chaining.";
        cmdNames[Commands::SMB_COM_QUERY_INFORMATION_DISK] = "SMB_COM_QUERY_INFORMATION_DISK: Retrieve file system information from the server.";
        cmdNames[Commands::SMB_COM_SEARCH] = "SMB_COM_SEARCH: Directory wildcard search.";
        cmdNames[Commands::SMB_COM_FIND] = "SMB_COM_FIND: Start or continue an extended wildcard directory search.";
        cmdNames[Commands::SMB_COM_FIND_UNIQUE] = "SMB_COM_FIND_UNIQUE: Perform a one-time extended wildcard directory search.";
        cmdNames[Commands::SMB_COM_FIND_CLOSE] = "SMB_COM_FIND_CLOSE: End an extended wildcard directory search.";
        cmdNames[Commands::SMB_COM_NT_TRANSACT] = "SMB_COM_NT_TRANSACT: NT format transaction request/response.";
        cmdNames[Commands::SMB_COM_NT_TRANSACT_SECONDARY] = "SMB_COM_NT_TRANSACT_SECONDARY: NT format transaction secondary request.";
        cmdNames[Commands::SMB_COM_NT_CREATE_ANDX] = "SMB_COM_NT_CREATE_ANDX: Create or open a file or a directory.";
        cmdNames[Commands::SMB_COM_NT_CANCEL] = "SMB_COM_NT_CANCEL: Cancel a request currently pending at the server.";
        cmdNames[Commands::SMB_COM_NT_RENAME] = "SMB_COM_NT_RENAME: File rename with extended semantics.";
        cmdNames[Commands::SMB_COM_OPEN_PRINT_FILE] = "SMB_COM_OPEN_PRINT_FILE: Create a print queue spool file.";
        cmdNames[Commands::SMB_COM_WRITE_PRINT_FILE] = "SMB_COM_WRITE_PRINT_FILE: Write to a print queue spool file.";
        cmdNames[Commands::SMB_COM_CLOSE_PRINT_FILE] = "SMB_COM_CLOSE_PRINT_FILE: Close a print queue spool file.";
        cmdNames[Commands::SMB_COM_GET_PRINT_QUEUE] = "SMB_COM_GET_PRINT_QUEUE: Request print queue information.";
        cmdNames[Commands::SMB_COM_READ_BULK] = "SMB_COM_READ_BULK: Reserved";
        cmdNames[Commands::SMB_COM_WRITE_BULK] = "SMB_COM_WRITE_BULK: Reserved";
        cmdNames[Commands::SMB_COM_WRITE_BULK_DATA] = "SMB_COM_WRITE_BULK_DATA: Reserved";
        cmdNames[Commands::SMB_COM_INVALID] = "SMB_COM_INVALID: As the name suggests";
        cmdNames[Commands::SMB_COM_NO_ANDX_COMMAND] = "SMB_COM_NO_ANDX_COMMAND: Also known as the NIL command. It identifies the end of an AndX Chain";
    }
    return cmdNames[cmd_code];
}
