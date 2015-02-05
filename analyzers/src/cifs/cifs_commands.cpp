//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: CIFS commands
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
#include <map>

#include "cifs_commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------

const std::string NST::breakdown::SMBv1Commands::commandName(int cmd_code)
{
    static std::map<Commands, const char*> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[Commands::CREATE_DIRECTORY]       = "CREATE_DIRECTORY";
        cmdNames[Commands::DELETE_DIRECTORY]       = "DELETE_DIRECTORY";
        cmdNames[Commands::OPEN]                   = "OPEN";
        cmdNames[Commands::CREATE]                 = "CREATE";
        cmdNames[Commands::CLOSE]                  = "CLOSE";
        cmdNames[Commands::FLUSH]                  = "FLUSH";
        cmdNames[Commands::DELETE]                 = "DELETE";
        cmdNames[Commands::RENAME]                 = "RENAME";
        cmdNames[Commands::QUERY_INFORMATION]      = "QUERY_INFORMATION";
        cmdNames[Commands::SET_INFORMATION]        = "SET_INFORMATION";
        cmdNames[Commands::READ]                   = "READ";
        cmdNames[Commands::WRITE]                  = "WRITE";
        cmdNames[Commands::LOCK_BYTE_RANGE]        = "LOCK_BYTE_RANGE";
        cmdNames[Commands::UNLOCK_BYTE_RANGE]      = "UNLOCK_BYTE_RANGE";
        cmdNames[Commands::CREATE_TEMPORARY]       = "CREATE_TEMPORARY";
        cmdNames[Commands::CREATE_NEW]             = "CREATE_NEW";
        cmdNames[Commands::CHECK_DIRECTORY]        = "CHECK_DIRECTORY";
        cmdNames[Commands::PROCESS_EXIT]           = "PROCESS_EXIT";
        cmdNames[Commands::SEEK]                   = "SEEK";
        cmdNames[Commands::LOCK_AND_READ]          = "LOCK_AND_READ";
        cmdNames[Commands::WRITE_AND_UNLOCK]       = "WRITE_AND_UNLOCK";
        cmdNames[Commands::READ_RAW]               = "READ_RAW";
        cmdNames[Commands::READ_MPX]               = "READ_MPX";
        cmdNames[Commands::READ_MPX_SECONDARY]     = "READ_MPX_SECONDARY";
        cmdNames[Commands::WRITE_RAW]              = "WRITE_RAW";
        cmdNames[Commands::WRITE_MPX]              = "WRITE_MPX";
        cmdNames[Commands::WRITE_MPX_SECONDARY]    = "WRITE_MPX_SECONDARY";
        cmdNames[Commands::WRITE_COMPLETE]         = "WRITE_COMPLETE";
        cmdNames[Commands::QUERY_SERVER]           = "QUERY_SERVER";
        cmdNames[Commands::SET_INFORMATION2]       = "SET_INFORMATION2";
        cmdNames[Commands::QUERY_INFORMATION2]     = "QUERY_INFORMATION2";
        cmdNames[Commands::LOCKING_ANDX]           = "LOCKING_ANDX";
        cmdNames[Commands::TRANSACTION]            = "TRANSACTION";
        cmdNames[Commands::TRANSACTION_SECONDARY]  = "TRANSACTION_SECONDARY";
        cmdNames[Commands::IOCTL]                  = "IOCTL";
        cmdNames[Commands::IOCTL_SECONDARY]        = "IOCTL_SECONDARY";
        cmdNames[Commands::COPY]                   = "COPY";
        cmdNames[Commands::MOVE]                   = "MOVE";
        cmdNames[Commands::ECHO]                   = "ECHO";
        cmdNames[Commands::WRITE_AND_CLOSE]        = "WRITE_AND_CLOSE";
        cmdNames[Commands::OPEN_ANDX]              = "OPEN_ANDX";
        cmdNames[Commands::READ_ANDX]              = "READ_ANDX";
        cmdNames[Commands::WRITE_ANDX]             = "WRITE_ANDX";
        cmdNames[Commands::NEW_FILE_SIZE]          = "NEW_FILE_SIZE";
        cmdNames[Commands::CLOSE_AND_TREE_DISC]    = "CLOSE_AND_TREE_DISC";
        cmdNames[Commands::TRANSACTION2]           = "TRANSACTION2";
        cmdNames[Commands::TRANSACTION2_SECONDARY] = "TRANSACTION2_SECONDARY";
        cmdNames[Commands::FIND_CLOSE2]            = "FIND_CLOSE2";
        cmdNames[Commands::FIND_NOTIFY_CLOSE]      = "FIND_NOTIFY_CLOSE";
        cmdNames[Commands::TREE_CONNECT]           = "TREE_CONNECT";
        cmdNames[Commands::TREE_DISCONNECT]        = "TREE_DISCONNECT";
        cmdNames[Commands::NEGOTIATE]              = "NEGOTIATE";
        cmdNames[Commands::SESSION_SETUP_ANDX]     = "SESSION_SETUP_ANDX";
        cmdNames[Commands::LOGOFF_ANDX]            = "LOGOFF_ANDX";
        cmdNames[Commands::TREE_CONNECT_ANDX]      = "TREE_CONNECT_ANDX";
        cmdNames[Commands::SECURITY_PACKAGE_ANDX]  = "SECURITY_PACKAGE_ANDX";
        cmdNames[Commands::QUERY_INFORMATION_DISK] = "QUERY_INFORMATION_DISK";
        cmdNames[Commands::SEARCH]                 = "SEARCH";
        cmdNames[Commands::FIND]                   = "FIND";
        cmdNames[Commands::FIND_UNIQUE]            = "FIND_UNIQUE";
        cmdNames[Commands::FIND_CLOSE]             = "FIND_CLOSE";
        cmdNames[Commands::NT_TRANSACT]            = "NT_TRANSACT";
        cmdNames[Commands::NT_TRANSACT_SECONDARY]  = "NT_TRANSACT_SECONDARY";
        cmdNames[Commands::NT_CREATE_ANDX]         = "NT_CREATE_ANDX";
        cmdNames[Commands::NT_CANCEL]              = "NT_CANCEL";
        cmdNames[Commands::NT_RENAME]              = "NT_RENAME";
        cmdNames[Commands::OPEN_PRINT_FILE]        = "OPEN_PRINT_FILE";
        cmdNames[Commands::WRITE_PRINT_FILE]       = "WRITE_PRINT_FILE";
        cmdNames[Commands::CLOSE_PRINT_FILE]       = "CLOSE_PRINT_FILE";
        cmdNames[Commands::GET_PRINT_QUEUE]        = "GET_PRINT_QUEUE";
        cmdNames[Commands::READ_BULK]              = "READ_BULK";
        cmdNames[Commands::WRITE_BULK]             = "WRITE_BULK";
        cmdNames[Commands::WRITE_BULK_DATA]        = "WRITE_BULK_DATA";
        cmdNames[Commands::INVALID]                = "INVALID";
        cmdNames[Commands::NO_ANDX_COMMAND]        = "NO_ANDX_COMMAND";
    }
    return cmdNames[static_cast<Commands>(cmd_code)];
}

const std::string NST::breakdown::SMBv1Commands::commandDescription(int cmd_code)
{
    static std::map<Commands, const char*> cmdNames;
    if (cmdNames.empty())
    {
        cmdNames[Commands::CREATE_DIRECTORY]       = "SMB_COM_CREATE_DIRECTORY: Create a new directory.";
        cmdNames[Commands::DELETE_DIRECTORY]       = "SMB_COM_DELETE_DIRECTORY: Delete an empty directory.";
        cmdNames[Commands::OPEN]                   = "SMB_COM_OPEN: Open a file.";
        cmdNames[Commands::CREATE]                 = "SMB_COM_CREATE: Create or open a file.";
        cmdNames[Commands::CLOSE]                  = "SMB_COM_CLOSE: Close a file.";
        cmdNames[Commands::FLUSH]                  = "SMB_COM_FLUSH: Flush data for a file";
        cmdNames[Commands::DELETE]                 = "SMB_COM_DELETE: Delete a file.";
        cmdNames[Commands::RENAME]                 = "SMB_COM_RENAME: Rename a file or set of files.";
        cmdNames[Commands::QUERY_INFORMATION]      = "SMB_COM_QUERY_INFORMATION: Get file attributes.";
        cmdNames[Commands::SET_INFORMATION]        = "SMB_COM_SET_INFORMATION: Set file attributes.";
        cmdNames[Commands::READ]                   = "SMB_COM_READ: Read from a file.";
        cmdNames[Commands::WRITE]                  = "SMB_COM_WRITE: Write to a file.";
        cmdNames[Commands::LOCK_BYTE_RANGE]        = "SMB_COM_LOCK_BYTE_RANGE: Request a byte-range lock on a file.";
        cmdNames[Commands::UNLOCK_BYTE_RANGE]      = "SMB_COM_UNLOCK_BYTE_RANGE: Release a byte-range lock on a file.";
        cmdNames[Commands::CREATE_TEMPORARY]       = "SMB_COM_CREATE_TEMPORARY: Create a temporary file.";
        cmdNames[Commands::CREATE_NEW]             = "SMB_COM_CREATE_NEW: Create and open a new file.";
        cmdNames[Commands::CHECK_DIRECTORY]        = "SMB_COM_CHECK_DIRECTORY: Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation.";
        cmdNames[Commands::PROCESS_EXIT]           = "SMB_COM_PROCESS_EXIT: Indicate process exit.";
        cmdNames[Commands::SEEK]                   = "SMB_COM_SEEK: Set the current file pointer within a file.";
        cmdNames[Commands::LOCK_AND_READ]          = "SMB_COM_LOCK_AND_READ: Lock and read a byte-range within a file.";
        cmdNames[Commands::WRITE_AND_UNLOCK]       = "SMB_COM_WRITE_AND_UNLOCK: Write and unlock a byte-range within a file.";
        cmdNames[Commands::READ_RAW]               = "SMB_COM_READ_RAW: Read a block in raw mode.";
        cmdNames[Commands::READ_MPX]               = "SMB_COM_READ_MPX: Multiplexed block read. Listed as SMBreadmpx in some documentation.";
        cmdNames[Commands::READ_MPX_SECONDARY]     = "SMB_COM_READ_MPX_SECONDARY: Multiplexed block read";
        cmdNames[Commands::WRITE_RAW]              = "SMB_COM_WRITE_RAW: Write a block in raw mode.";
        cmdNames[Commands::WRITE_MPX]              = "SMB_COM_WRITE_MPX: Multiplexed block write.";
        cmdNames[Commands::WRITE_MPX_SECONDARY]    = "SMB_COM_WRITE_MPX_SECONDARY: Multiplexed block write";
        cmdNames[Commands::WRITE_COMPLETE]         = "SMB_COM_WRITE_COMPLETE: Raw block write";
        cmdNames[Commands::QUERY_SERVER]           = "SMB_COM_QUERY_SERVER: Reserved";
        cmdNames[Commands::SET_INFORMATION2]       = "SMB_COM_SET_INFORMATION2: Set an extended set of file attributes.";
        cmdNames[Commands::QUERY_INFORMATION2]     = "SMB_COM_QUERY_INFORMATION2: Get an extended set of file attributes.";
        cmdNames[Commands::LOCKING_ANDX]           = "SMB_COM_LOCKING_ANDX: Lock multiple byte ranges; AndX chaining.";
        cmdNames[Commands::TRANSACTION]            = "SMB_COM_TRANSACTION: Transaction.";
        cmdNames[Commands::TRANSACTION_SECONDARY]  = "SMB_COM_TRANSACTION_SECONDARY: Transaction secondary request.";
        cmdNames[Commands::IOCTL]                  = "SMB_COM_IOCTL: Pass an I/O Control function request to the server.";
        cmdNames[Commands::IOCTL_SECONDARY]        = "SMB_COM_IOCTL_SECONDARY: IOCTL secondary request.";
        cmdNames[Commands::COPY]                   = "SMB_COM_COPY: Copy a file or directory.";
        cmdNames[Commands::MOVE]                   = "SMB_COM_MOVE: Move a file or directory.";
        cmdNames[Commands::ECHO]                   = "SMB_COM_ECHO: Echo request (ping).";
        cmdNames[Commands::WRITE_AND_CLOSE]        = "SMB_COM_WRITE_AND_CLOSE: Write to and close a file.";
        cmdNames[Commands::OPEN_ANDX]              = "SMB_COM_OPEN_ANDX: Extended file open with AndX chaining.";
        cmdNames[Commands::READ_ANDX]              = "SMB_COM_READ_ANDX: Extended file read with AndX chaining.";
        cmdNames[Commands::WRITE_ANDX]             = "SMB_COM_WRITE_ANDX: Extended file write with AndX chaining.";
        cmdNames[Commands::NEW_FILE_SIZE]          = "SMB_COM_NEW_FILE_SIZE: Reserved";
        cmdNames[Commands::CLOSE_AND_TREE_DISC]    = "SMB_COM_CLOSE_AND_TREE_DISC: Close an open file and tree disconnect.";
        cmdNames[Commands::TRANSACTION2]           = "SMB_COM_TRANSACTION2: Transaction 2 format request/response.";
        cmdNames[Commands::TRANSACTION2_SECONDARY] = "SMB_COM_TRANSACTION2_SECONDARY: Transaction 2 secondary request.";
        cmdNames[Commands::FIND_CLOSE2]            = "SMB_COM_FIND_CLOSE2: Close an active search.";
        cmdNames[Commands::FIND_NOTIFY_CLOSE]      = "SMB_COM_FIND_NOTIFY_CLOSE: Notification of the closure of an active search.";
        cmdNames[Commands::TREE_CONNECT]           = "SMB_COM_TREE_CONNECT: Tree connect.";
        cmdNames[Commands::TREE_DISCONNECT]        = "SMB_COM_TREE_DISCONNECT: Tree disconnect.";
        cmdNames[Commands::NEGOTIATE]              = "SMB_COM_NEGOTIATE: Negotiate protocol dialect.";
        cmdNames[Commands::SESSION_SETUP_ANDX]     = "SMB_COM_SESSION_SETUP_ANDX: Session Setup with AndX chaining.";
        cmdNames[Commands::LOGOFF_ANDX]            = "SMB_COM_LOGOFF_ANDX: User logoff with AndX chaining.";
        cmdNames[Commands::TREE_CONNECT_ANDX]      = "SMB_COM_TREE_CONNECT_ANDX: Tree connect with AndX chaining.";
        cmdNames[Commands::SECURITY_PACKAGE_ANDX]  = "SMB_COM_SECURITY_PACKAGE_ANDX: Negotiate security packages with AndX chaining.";
        cmdNames[Commands::QUERY_INFORMATION_DISK] = "SMB_COM_QUERY_INFORMATION_DISK: Retrieve file system information from the server.";
        cmdNames[Commands::SEARCH]                 = "SMB_COM_SEARCH: Directory wildcard search.";
        cmdNames[Commands::FIND]                   = "SMB_COM_FIND: Start or continue an extended wildcard directory search.";
        cmdNames[Commands::FIND_UNIQUE]            = "SMB_COM_FIND_UNIQUE: Perform a one-time extended wildcard directory search.";
        cmdNames[Commands::FIND_CLOSE]             = "SMB_COM_FIND_CLOSE: End an extended wildcard directory search.";
        cmdNames[Commands::NT_TRANSACT]            = "SMB_COM_NT_TRANSACT: NT format transaction request/response.";
        cmdNames[Commands::NT_TRANSACT_SECONDARY]  = "SMB_COM_NT_TRANSACT_SECONDARY: NT format transaction secondary request.";
        cmdNames[Commands::NT_CREATE_ANDX]         = "SMB_COM_NT_CREATE_ANDX: Create or open a file or a directory.";
        cmdNames[Commands::NT_CANCEL]              = "SMB_COM_NT_CANCEL: Cancel a request currently pending at the server.";
        cmdNames[Commands::NT_RENAME]              = "SMB_COM_NT_RENAME: File rename with extended semantics.";
        cmdNames[Commands::OPEN_PRINT_FILE]        = "SMB_COM_OPEN_PRINT_FILE: Create a print queue spool file.";
        cmdNames[Commands::WRITE_PRINT_FILE]       = "SMB_COM_WRITE_PRINT_FILE: Write to a print queue spool file.";
        cmdNames[Commands::CLOSE_PRINT_FILE]       = "SMB_COM_CLOSE_PRINT_FILE: Close a print queue spool file.";
        cmdNames[Commands::GET_PRINT_QUEUE]        = "SMB_COM_GET_PRINT_QUEUE: Request print queue information.";
        cmdNames[Commands::READ_BULK]              = "SMB_COM_READ_BULK: Reserved";
        cmdNames[Commands::WRITE_BULK]             = "SMB_COM_WRITE_BULK: Reserved";
        cmdNames[Commands::WRITE_BULK_DATA]        = "SMB_COM_WRITE_BULK_DATA: Reserved";
        cmdNames[Commands::INVALID]                = "SMB_COM_INVALID: As the name suggests";
        cmdNames[Commands::NO_ANDX_COMMAND]        = "SMB_COM_NO_ANDX_COMMAND: Also known as the NIL command. It identifies the end of an AndX Chain";
    }
    return cmdNames[static_cast<Commands>(cmd_code)];
}
//------------------------------------------------------------------------------
