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
struct CommandRepresenter
{
    /*!
     * \brief commandDescription returns description of the command
     * \param cmd_code command code
     * \return description
     */
    virtual const std::string commandDescription(int cmd_code) = 0;

    /*!
     * \brief commandName returns name of the command
     * \param cmd_code command code
     * \return name
     */
    virtual const std::string commandName(int cmd_code) = 0;

    /*!
     * \brief commandName returns name of the command
     * \param cmd_code command code
     * \return name
     */
    virtual size_t commandsCount() = 0;

    virtual ~CommandRepresenter() = 0;
};

/*! CIFS v1 commands list
 */
struct SMBv1Commands : public CommandRepresenter
{
    enum Commands
    {
        CREATE_DIRECTORY,       //!< Create a new directory.
        DELETE_DIRECTORY,       //!< Delete an empty directory.
        OPEN,                   //!< Open a file.
        CREATE,                 //!< Create or open a file.
        CLOSE,                  //!< Close a file.
        FLUSH,                  //!< Flush data for a file
        DELETE,                 //!< Delete a file.
        RENAME,                 //!< Rename a file or set of files.
        QUERY_INFORMATION,      //!< Get file attributes.
        SET_INFORMATION,        //!< Set file attributes.
        READ,                   //!< Read from a file.
        WRITE,                  //!< Write to a file.
        LOCK_BYTE_RANGE,        //!< Request a byte-range lock on a file.
        UNLOCK_BYTE_RANGE,      //!< Release a byte-range lock on a file.
        CREATE_TEMPORARY,       //!< Create a temporary file.
        CREATE_NEW,             //!< Create and open a new file.
        CHECK_DIRECTORY,        //!< Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation.
        PROCESS_EXIT,           //!< Indicate process exit.
        SEEK,                   //!< Set the current file pointer within a file.
        LOCK_AND_READ,          //!< Lock and read a byte-range within a file.
        WRITE_AND_UNLOCK,       //!< Write and unlock a byte-range within a file.
        READ_RAW,               //!< Read a block in raw mode.
        READ_MPX,               //!< Multiplexed block read. Listed as SMBreadmpx in some documentation.
        READ_MPX_SECONDARY,     //!< Multiplexed block read
        WRITE_RAW,              //!< Write a block in raw mode.
        WRITE_MPX,              //!< Multiplexed block write.
        WRITE_MPX_SECONDARY,    //!< Multiplexed block write
        WRITE_COMPLETE,         //!< Raw block write
        QUERY_SERVER,           //!< Reserved
        SET_INFORMATION2,       //!< Set an extended set of file attributes.
        QUERY_INFORMATION2,     //!< Get an extended set of file attributes.
        LOCKING_ANDX,           //!< Lock multiple byte ranges; AndX chaining.
        TRANSACTION,            //!< Transaction.
        TRANSACTION_SECONDARY,  //!< Transaction secondary request.
        IOCTL,                  //!< Pass an I/O Control function request to the server.
        IOCTL_SECONDARY,        //!< IOCTL secondary request.
        COPY,                   //!< Copy a file or directory.
        MOVE,                   //!< Move a file or directory.
        ECHO,                   //!< Echo request (ping).
        WRITE_AND_CLOSE,        //!< Write to and close a file.
        OPEN_ANDX,              //!< Extended file open with AndX chaining.
        READ_ANDX,              //!< Extended file read with AndX chaining.
        WRITE_ANDX,             //!< Extended file write with AndX chaining.
        NEW_FILE_SIZE,          //!< Reserved
        CLOSE_AND_TREE_DISC,    //!< Close an open file and tree disconnect.
        TRANSACTION2,           //!< Transaction 2 format request/response.
        TRANSACTION2_SECONDARY, //!< Transaction 2 secondary request.
        FIND_CLOSE2,            //!< Close an active search.
        FIND_NOTIFY_CLOSE,      //!< Notification of the closure of an active search.
        TREE_CONNECT,           //!< Tree connect.
        TREE_DISCONNECT,        //!< Tree disconnect.
        NEGOTIATE,              //!< Negotiate protocol dialect.
        SESSION_SETUP_ANDX,     //!< Session Setup with AndX chaining.
        LOGOFF_ANDX,            //!< User logoff with AndX chaining.
        TREE_CONNECT_ANDX,      //!< Tree connect with AndX chaining.
        SECURITY_PACKAGE_ANDX,  //!< Negotiate security packages with AndX chaining.
        QUERY_INFORMATION_DISK, //!< Retrieve file system information from the server.
        SEARCH,                 //!< Directory wildcard search.
        FIND,                   //!< Start or continue an extended wildcard directory search.
        FIND_UNIQUE,            //!< Perform a one-time extended wildcard directory search.
        FIND_CLOSE,             //!< End an extended wildcard directory search.
        NT_TRANSACT,            //!< NT format transaction request/response.
        NT_TRANSACT_SECONDARY,  //!< NT format transaction secondary request.
        NT_CREATE_ANDX,         //!< Create or open a file or a directory.
        NT_CANCEL,              //!< Cancel a request currently pending at the server.
        NT_RENAME,              //!< File rename with extended semantics.
        OPEN_PRINT_FILE,        //!< Create a print queue spool file.
        WRITE_PRINT_FILE,       //!< Write to a print queue spool file.
        CLOSE_PRINT_FILE,       //!< Close a print queue spool file.
        GET_PRINT_QUEUE,        //!< Request print queue information.
        READ_BULK,              //!< Reserved
        WRITE_BULK,             //!< Reserved
        WRITE_BULK_DATA,        //!< Reserved
        INVALID,                //!< As the name suggests
        NO_ANDX_COMMAND,        //!<  Also known as the NIL command. It identifies the end of an AndX Chain
        CMD_COUNT
    };

    /*!
    * \brief commandDescription returns description of the command
    * \param cmd_code command code
    * \return description
    */
    const std::string commandDescription(int cmd_code);

    /*!
    * \brief commandName returns name of the command
    * \param cmd_code command code
    * \return name
    */
    const std::string commandName(int cmd_code);

    size_t commandsCount();
};
//------------------------------------------------------------------------------
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // CIFS_COMMANDS_H
//------------------------------------------------------------------------------

