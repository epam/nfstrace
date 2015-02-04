//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: CIFS structures.
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
#ifndef CIFS_COMMANDS_H
#define CIFS_COMMANDS_H
//------------------------------------------------------------------------------
#include <string>
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
//------------------------------------------------------------------------------
/*! CIFS v1 commands list
 */
//TODO: remove it?
enum class SMBv1Commands
{
    SMB_COM_CREATE_DIRECTORY,       //!< Create a new directory.
    SMB_COM_DELETE_DIRECTORY,       //!< Delete an empty directory.
    SMB_COM_OPEN,                   //!< Open a file.
    SMB_COM_CREATE,                 //!< Create or open a file.
    SMB_COM_CLOSE,                  //!< Close a file.
    SMB_COM_FLUSH,                  //!< Flush data for a file
    SMB_COM_DELETE,                 //!< Delete a file.
    SMB_COM_RENAME,                 //!< Rename a file or set of files.
    SMB_COM_QUERY_INFORMATION,      //!< Get file attributes.
    SMB_COM_SET_INFORMATION,        //!< Set file attributes.
    SMB_COM_READ,                   //!< Read from a file.
    SMB_COM_WRITE,                  //!< Write to a file.
    SMB_COM_LOCK_BYTE_RANGE,        //!< Request a byte-range lock on a file.
    SMB_COM_UNLOCK_BYTE_RANGE,      //!< Release a byte-range lock on a file.
    SMB_COM_CREATE_TEMPORARY,       //!< Create a temporary file.
    SMB_COM_CREATE_NEW,             //!< Create and open a new file.
    SMB_COM_CHECK_DIRECTORY,        //!< Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation.
    SMB_COM_PROCESS_EXIT,           //!< Indicate process exit.
    SMB_COM_SEEK,                   //!< Set the current file pointer within a file.
    SMB_COM_LOCK_AND_READ,          //!< Lock and read a byte-range within a file.
    SMB_COM_WRITE_AND_UNLOCK,       //!< Write and unlock a byte-range within a file.
    SMB_COM_READ_RAW,               //!< Read a block in raw mode.
    SMB_COM_READ_MPX,               //!< Multiplexed block read. Listed as SMBreadmpx in some documentation.
    SMB_COM_READ_MPX_SECONDARY,     //!< Multiplexed block read
    SMB_COM_WRITE_RAW,              //!< Write a block in raw mode.
    SMB_COM_WRITE_MPX,              //!< Multiplexed block write.
    SMB_COM_WRITE_MPX_SECONDARY,    //!< Multiplexed block write
    SMB_COM_WRITE_COMPLETE,         //!< Raw block write
    SMB_COM_QUERY_SERVER,           //!< Reserved
    SMB_COM_SET_INFORMATION2,       //!< Set an extended set of file attributes.
    SMB_COM_QUERY_INFORMATION2,     //!< Get an extended set of file attributes.
    SMB_COM_LOCKING_ANDX,           //!< Lock multiple byte ranges; AndX chaining.
    SMB_COM_TRANSACTION,            //!< Transaction.
    SMB_COM_TRANSACTION_SECONDARY,  //!< Transaction secondary request.
    SMB_COM_IOCTL,                  //!< Pass an I/O Control function request to the server.
    SMB_COM_IOCTL_SECONDARY,        //!< IOCTL secondary request.
    SMB_COM_COPY,                   //!< Copy a file or directory.
    SMB_COM_MOVE,                   //!< Move a file or directory.
    SMB_COM_ECHO,                   //!< Echo request (ping).
    SMB_COM_WRITE_AND_CLOSE,        //!< Write to and close a file.
    SMB_COM_OPEN_ANDX,              //!< Extended file open with AndX chaining.
    SMB_COM_READ_ANDX,              //!< Extended file read with AndX chaining.
    SMB_COM_WRITE_ANDX,             //!< Extended file write with AndX chaining.
    SMB_COM_NEW_FILE_SIZE,          //!< Reserved
    SMB_COM_CLOSE_AND_TREE_DISC,    //!< Close an open file and tree disconnect.
    SMB_COM_TRANSACTION2,           //!< Transaction 2 format request/response.
    SMB_COM_TRANSACTION2_SECONDARY, //!< Transaction 2 secondary request.
    SMB_COM_FIND_CLOSE2,            //!< Close an active search.
    SMB_COM_FIND_NOTIFY_CLOSE,      //!< Notification of the closure of an active search.
    SMB_COM_TREE_CONNECT,           //!< Tree connect.
    SMB_COM_TREE_DISCONNECT,        //!< Tree disconnect.
    SMB_COM_NEGOTIATE,              //!< Negotiate protocol dialect.
    SMB_COM_SESSION_SETUP_ANDX,     //!< Session Setup with AndX chaining.
    SMB_COM_LOGOFF_ANDX,            //!< User logoff with AndX chaining.
    SMB_COM_TREE_CONNECT_ANDX,      //!< Tree connect with AndX chaining.
    SMB_COM_SECURITY_PACKAGE_ANDX,  //!< Negotiate security packages with AndX chaining.
    SMB_COM_QUERY_INFORMATION_DISK, //!< Retrieve file system information from the server.
    SMB_COM_SEARCH,                 //!< Directory wildcard search.
    SMB_COM_FIND,                   //!< Start or continue an extended wildcard directory search.
    SMB_COM_FIND_UNIQUE,            //!< Perform a one-time extended wildcard directory search.
    SMB_COM_FIND_CLOSE,             //!< End an extended wildcard directory search.
    SMB_COM_NT_TRANSACT,            //!< NT format transaction request/response.
    SMB_COM_NT_TRANSACT_SECONDARY,  //!< NT format transaction secondary request.
    SMB_COM_NT_CREATE_ANDX,         //!< Create or open a file or a directory.
    SMB_COM_NT_CANCEL,              //!< Cancel a request currently pending at the server.
    SMB_COM_NT_RENAME,              //!< File rename with extended semantics.
    SMB_COM_OPEN_PRINT_FILE,        //!< Create a print queue spool file.
    SMB_COM_WRITE_PRINT_FILE,       //!< Write to a print queue spool file.
    SMB_COM_CLOSE_PRINT_FILE,       //!< Close a print queue spool file.
    SMB_COM_GET_PRINT_QUEUE,        //!< Request print queue information.
    SMB_COM_READ_BULK,              //!< Reserved
    SMB_COM_WRITE_BULK,             //!< Reserved
    SMB_COM_WRITE_BULK_DATA,        //!< Reserved
    SMB_COM_INVALID,                //!< As the name suggests
    SMB_COM_NO_ANDX_COMMAND,        //!<  Also known as the NIL command. It identifies the end of an AndX Chain
    CMD_COUNT
};

/*!
 * \brief commandDescription returns description of the command
 * \param cmd_code command code
 * \return description
 */
const std::string commandDescription(SMBv1Commands cmd_code);

/*!
 * \brief commandName returns name of the command
 * \param cmd_code command code
 * \return name
 */
const std::string commandName(SMBv1Commands cmd_code);
//------------------------------------------------------------------------------
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // CIFS_COMMANDS_H
//------------------------------------------------------------------------------

