//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Definition of CIFS types and commands
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
#ifndef CIFS_TYPES_H
#define CIFS_TYPES_H
//------------------------------------------------------------------------------
#include <sys/time.h>

#include "cifs_commands.h"
#include "procedure.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

/*! SMB 1 version
 */
namespace SMBv1
{


/*! CIFS v1 commands list
 */
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

static const int commandsCount = 255;

using Session = u_int16_t;//!< Session IDentifier

/*! Represents one SMB command
 */
template <
    typename Request,
    typename Response
    >
class Command : public Procedure<int>
{
public:
    using RequestType = Request;
    using ResponseType = Response;
    const RequestType* parg;//!< Arguments of specified command
    const ResponseType* pres;//!< Results of specified command
};

using CreateDirectoryArgumentType = struct {};                                                                                   //!< CreateDirectory arguments
using CreateDirectoryResultType = struct {};                                                                                     //!< CreateDirectory results
using CreateDirectoryCommand = SMBv1::Command< CreateDirectoryArgumentType, CreateDirectoryResultType>;                          //!< CreateDirectory command

using DeleteDirectoryArgumentType = struct {};                                                                                   //!< DeleteDirectory arguments
using DeleteDirectoryResultType = struct {};                                                                                     //!< DeleteDirectory results
using DeleteDirectoryCommand = SMBv1::Command< DeleteDirectoryArgumentType, DeleteDirectoryResultType>;                          //!< DeleteDirectory command

using OpenArgumentType = struct {};                                                                                              //!< Open arguments
using OpenResultType = struct {};                                                                                                //!< Open results
using OpenCommand = SMBv1::Command< OpenArgumentType, OpenResultType>;                                                           //!< Open command

using CreateArgumentType = struct {};                                                                                            //!< Create arguments
using CreateResultType = struct {};                                                                                              //!< Create results
using CreateCommand = SMBv1::Command< CreateArgumentType, CreateResultType>;                                                     //!< Create command

using CloseArgumentType = struct {};                                                                                             //!< Close arguments
using CloseResultType = struct {};                                                                                               //!< Close results
using CloseCommand = SMBv1::Command< CloseArgumentType, CloseResultType>;                                                        //!< Close command

using FlushArgumentType = struct {};                                                                                             //!< Flush arguments
using FlushResultType = struct {};                                                                                               //!< Flush results
using FlushCommand = SMBv1::Command< FlushArgumentType, FlushResultType>;                                                        //!< Flush command

using DeleteArgumentType = struct {};                                                                                            //!< Delete arguments
using DeleteResultType = struct {};                                                                                              //!< Delete results
using DeleteCommand = SMBv1::Command< DeleteArgumentType, DeleteResultType>;                                                     //!< Delete command

using RenameArgumentType = struct {};                                                                                            //!< Rename arguments
using RenameResultType = struct {};                                                                                              //!< Rename results
using RenameCommand = SMBv1::Command< RenameArgumentType, RenameResultType>;                                                     //!< Rename command

using QueryInformationArgumentType = struct {};                                                                                  //!< QueryInformation arguments
using QueryInformationResultType = struct {};                                                                                    //!< QueryInformation results
using QueryInformationCommand = SMBv1::Command< QueryInformationArgumentType, QueryInformationResultType>;                       //!< QueryInformation command. This transaction is used to get information about a specific file or directory. There are several information levels that can be queried.

using SetInformationArgumentType = struct {};                                                                                    //!< Set Information arguments
using SetInformationResultType = struct {};                                                                                      //!< Set Information results
using SetInformationCommand = SMBv1::Command< SetInformationArgumentType, SetInformationResultType>;                             //!< Set Information command. This transaction is used to set the standard and extended attribute information of a specific file or directory on the server.

using ReadArgumentType = struct {};                                                                                              //!< Read arguments
using ReadResultType = struct {};                                                                                                //!< Read results
using ReadCommand = SMBv1::Command< ReadArgumentType, ReadResultType>;                                                           //!< Read command

using WriteArgumentType = struct {};                                                                                             //!< Write arguments
using WriteResultType = struct {};                                                                                               //!< Write results
using WriteCommand = SMBv1::Command< WriteArgumentType, WriteResultType>;                                                        //!< Write command

using LockByteRangeArgumentType = struct {};                                                                                     //!< Lock Byte Range arguments
using LockByteRangeResultType = struct {};                                                                                       //!< Lock Byte Range results
using LockByteRangeCommand = SMBv1::Command< LockByteRangeArgumentType, LockByteRangeResultType>;                                //!< Lock Byte Range command. This command is used to explicitly lock a contiguous range of bytes in an open regular file.

using UnlockByteRangeArgumentType = struct {};                                                                                   //!< UnLock Byte Range arguments
using UnlockByteRangeResultType = struct {};                                                                                     //!< UnLock Byte Range results
using UnlockByteRangeCommand = SMBv1::Command< UnlockByteRangeArgumentType, UnlockByteRangeResultType>;                          //!< UnLock Byte Range command

using CreateTemporaryArgumentType = struct {};                                                                                   //!< Create Temporary file arguments
using CreateTemporaryResultType = struct {};                                                                                     //!< Create Temporary file results
using CreateTemporaryCommand = SMBv1::Command< CreateTemporaryArgumentType, CreateTemporaryResultType>;                          //!< Create Temporary file command. This command is used to create a file for temporary use by the client.

using CreateNewArgumentType = struct {};                                                                                         //!< Create a new file arguments
using CreateNewResultType = struct {};                                                                                           //!< Create a new file results
using CreateNewCommand = SMBv1::Command< CreateNewArgumentType, CreateNewResultType>;                                            //!< Create a new file command. This command is used to create a new file. It MUST NOT truncate or overwrite an existing file.

using CheckDirectoryArgumentType = struct {};                                                                                    //!< CheckDirectory arguments
using CheckDirectoryResultType = struct {};                                                                                      //!< CheckDirectory results
using CheckDirectoryCommand = SMBv1::Command< CheckDirectoryArgumentType, CheckDirectoryResultType>;                             //!< CheckDirectory command. This command is used to verify that a specified path resolves to a valid directory on the server.

using ProcessExitArgumentType = struct {};                                                                                       //!< Process Exit arguments
using ProcessExitResultType = struct {};                                                                                         //!< Process Exit results
using ProcessExitCommand = SMBv1::Command< ProcessExitArgumentType, ProcessExitResultType>;                                      //!< Process Exit command.An SMB_COM_PROCESS_EXIT request is sent by the client to indicate the catastrophic failure of a client process.

using SeekArgumentType = struct {};                                                                                              //!< Seek arguments
using SeekResultType = struct {};                                                                                                //!< Seek results
using SeekCommand = SMBv1::Command< SeekArgumentType, SeekResultType>;                                                           //!< Seek command

using LockAndReadArgumentType = struct {};                                                                                       //!< Lock And Read arguments
using LockAndReadResultType = struct {};                                                                                         //!< Lock And Read results
using LockAndReadCommand = SMBv1::Command< LockAndReadArgumentType, LockAndReadResultType>;                                      //!< Lock And Read command

using WriteAndUnlockArgumentType = struct {};                                                                                    //!< Write And Unlock arguments
using WriteAndUnlockResultType = struct {};                                                                                      //!< Write And Unlock results
using WriteAndUnlockCommand = SMBv1::Command< WriteAndUnlockArgumentType, WriteAndUnlockResultType>;                             //!< Write And Unlock command

using ReadRawArgumentType = struct {};                                                                                           //!< Read raw command's arguments
using ReadRawResultType = struct {};                                                                                             //!< Read raw command's results
using ReadRawCommand = SMBv1::Command< ReadRawArgumentType, ReadRawResultType>;                                                  //!< Read raw command

using ReadMpxArgumentType = struct {};                                                                                           //!< Read Mpx command's arguments
using ReadMpxResultType = struct {};                                                                                             //!< Read Mpx command's results
using ReadMpxCommand = SMBv1::Command< ReadMpxArgumentType, ReadMpxResultType>;                                                  //!< Read Mpx command. This is a specialized read command intended to maximize the performance of reading large blocks of data from a regular file while allowing for other operations to take place between the client and the server.

using ReadMpxSecondaryArgumentType = struct {};                                                                                  //!< Read Read Mpx Secondary command's arguments
using ReadMpxSecondaryResultType = struct {};                                                                                    //!< Read Read Mpx Secondary command's results
using ReadMpxSecondaryCommand = SMBv1::Command< ReadMpxSecondaryArgumentType, ReadMpxSecondaryResultType>;                       //!< Read Read Mpx Secondary command

using WriteRawArgumentType = struct {};                                                                                          //!< Write Raw command's arguments
using WriteRawResultType = struct {};                                                                                            //!< Write Raw command's results
using WriteRawCommand = SMBv1::Command< WriteRawArgumentType, WriteRawResultType>;                                               //!< Write Raw command. The command permits a client to send a large unformatted data (raw byte) message over the SMB transport without requiring the usual SMB request format

using WriteMpxArgumentType = struct {};                                                                                          //!< Write Mpx command's arguments
using WriteMpxResultType = struct {};                                                                                            //!< Write Mpx command's results
using WriteMpxCommand = SMBv1::Command< WriteMpxArgumentType, WriteMpxResultType>;                                               //!< Write Mpx command

using WriteMpxSecondaryArgumentType = struct {};                                                                                 //!< Write Mpx 2 command's arguments
using WriteMpxSecondaryResultType = struct {};                                                                                   //!< Write Mpx 2 command's results
using WriteMpxSecondaryCommand = SMBv1::Command< WriteMpxSecondaryArgumentType, WriteMpxSecondaryResultType>;                    //!< Write Mpx 2 command

using WriteCompleteArgumentType = struct {};                                                                                     //!< Write Complete command's arguments
using WriteCompleteResultType = struct {};                                                                                       //!< Write Complete command's results
using WriteCompleteCommand = SMBv1::Command< WriteCompleteArgumentType, WriteCompleteResultType>;                                //!< Write Complete command

using QueryServerArgumentType = struct {};                                                                                       //!< Query Server (reserved) command's arguments
using QueryServerResultType = struct {};                                                                                         //!< Query Server (reserved) command's results
using QueryServerCommand = SMBv1::Command< QueryServerArgumentType, QueryServerResultType>;                                      //!< Query Server (reserved) command

using SetInformation2ArgumentType = struct {};                                                                                   //!< Set Information 2 command's arguments
using SetInformation2ResultType = struct {};                                                                                     //!< Set Information 2 command's results
using SetInformation2Command = SMBv1::Command< SetInformation2ArgumentType, SetInformation2ResultType>;                          //!< Set Information 2 command

using QueryInformation2ArgumentType = struct {};                                                                                 //!< Query Information 2 command's arguments
using QueryInformation2ResultType = struct {};                                                                                   //!< Query Information 2 command's results
using QueryInformation2Command = SMBv1::Command< QueryInformation2ArgumentType, QueryInformation2ResultType>;                    //!< Query Information 2 command

using LockingAndxArgumentType = struct {};                                                                                       //!< Lock some bytes of the file command's arguments
using LockingAndxResultType = struct {};                                                                                         //!< Lock some bytes of the file command's results
using LockingAndxCommand = SMBv1::Command< LockingAndxArgumentType, LockingAndxResultType>;                                      //!< Lock some bytes of the file command

using TransactionArgumentType = struct {};                                                                                       //!< Transaction command's arguments
using TransactionResultType = struct {};                                                                                         //!< Transaction command's results
using TransactionCommand = SMBv1::Command< TransactionArgumentType, TransactionResultType>;                                      //!< Transaction command.These commands operate on mailslots and named pipes, which are interprocess communication endpoints within the CIFS file system

using TransactionSecondaryArgumentType = struct {};                                                                              //!< Transaction 2 command's arguments
using TransactionSecondaryResultType = struct {};                                                                                //!< Transaction 2 command's results
using TransactionSecondaryCommand = SMBv1::Command< TransactionSecondaryArgumentType, TransactionSecondaryResultType>;           //!< Transaction 2 command

using IoctlArgumentType = struct {};                                                                                             //!< Ioctl command's arguments
using IoctlResultType = struct {};                                                                                               //!< Ioctl command's results
using IoctlCommand = SMBv1::Command< IoctlArgumentType, IoctlResultType>;                                                        //!< Ioctl command

using IoctlSecondaryArgumentType = struct {};                                                                                    //!< Ioctl 2 command's arguments
using IoctlSecondaryResultType = struct {};                                                                                      //!< Ioctl 2 command's results
using IoctlSecondaryCommand = SMBv1::Command< IoctlSecondaryArgumentType, IoctlSecondaryResultType>;                             //!< Ioctl 2 command

using CopyArgumentType = struct {};                                                                                              //!< Copy command's arguments
using CopyResultType = struct {};                                                                                                //!< Copy command's results
using CopyCommand = SMBv1::Command< CopyArgumentType, CopyResultType>;                                                           //!< Copy command

using MoveArgumentType = struct {};                                                                                              //!< Move command's arguments
using MoveResultType = struct {};                                                                                                //!< Move command's results
using MoveCommand = SMBv1::Command< MoveArgumentType, MoveResultType>;                                                           //!< Move command

using EchoArgumentType = struct {};                                                                                              //!< Echo command's arguments
using EchoResultType = struct {};                                                                                                //!< Echo command's results
using EchoCommand = SMBv1::Command< EchoArgumentType, EchoResultType>;                                                           //!< Echo command

using WriteAndCloseArgumentType = struct {};                                                                                     //!< Write And Close command's arguments
using WriteAndCloseResultType = struct {};                                                                                       //!< Write And Close command's results
using WriteAndCloseCommand = SMBv1::Command< WriteAndCloseArgumentType, WriteAndCloseResultType>;                                //!< Write And Close command

using OpenAndxArgumentType = struct {};                                                                                          //!< Open 2 command's arguments
using OpenAndxResultType = struct {};                                                                                            //!< Open 2 command's results
using OpenAndxCommand = SMBv1::Command< OpenAndxArgumentType, OpenAndxResultType>;                                               //!< Open 2 command

using ReadAndxArgumentType = struct {};                                                                                          //!< Read 2 command's arguments
using ReadAndxResultType = struct {};                                                                                            //!< Read 2 command's results
using ReadAndxCommand = SMBv1::Command< ReadAndxArgumentType, ReadAndxResultType>;                                               //!< Read 2 command

using WriteAndxArgumentType = struct {};                                                                                         //!< Write 2 command's arguments
using WriteAndxResultType = struct {};                                                                                           //!< Write 2 command's results
using WriteAndxCommand = SMBv1::Command< WriteAndxArgumentType, WriteAndxResultType>;                                            //!< Write 2 command

using NewFileSizeArgumentType = struct {};                                                                                       //!< New File Size command's arguments
using NewFileSizeResultType = struct {};                                                                                         //!< New File Size command's results
using NewFileSizeCommand = SMBv1::Command< NewFileSizeArgumentType, NewFileSizeResultType>;                                      //!< New File Size command. Reserved but not implemented

using CloseAndTreeDiscArgumentType = struct {};                                                                                  //!< Reserved command's arguments
using CloseAndTreeDiscResultType = struct {};                                                                                    //!< Reserved command's results
using CloseAndTreeDiscCommand = SMBv1::Command< CloseAndTreeDiscArgumentType, CloseAndTreeDiscResultType>;                       //!< Reserved command

using Transaction2ArgumentType = struct {};                                                                                      //!< Transaction 2 command's arguments
using Transaction2ResultType = struct {};                                                                                        //!< Transaction 2 command's results
using Transaction2Command = SMBv1::Command< Transaction2ArgumentType, Transaction2ResultType>;                                   //!< Transaction 2 command

using Transaction2SecondaryArgumentType = struct {};                                                                             //!< Transaction 3 command's arguments
using Transaction2SecondaryResultType = struct {};                                                                               //!< Transaction 3 command's results
using Transaction2SecondaryCommand = SMBv1::Command< Transaction2SecondaryArgumentType, Transaction2SecondaryResultType>;        //!< Transaction 3 command

using FindClose2ArgumentType = struct {};                                                                                        //!< Search handle close command's arguments
using FindClose2ResultType = struct {};                                                                                          //!< Search handle close command's results
using FindClose2Command = SMBv1::Command< FindClose2ArgumentType, FindClose2ResultType>;                                         //!< Search handle close command

using FindNotifyCloseArgumentType = struct {};                                                                                   //!< Search handle close command's arguments
using FindNotifyCloseResultType = struct {};                                                                                     //!< Search handle close command's results
using FindNotifyCloseCommand = SMBv1::Command< FindNotifyCloseArgumentType, FindNotifyCloseResultType>;                          //!< Search handle close command

using TreeConnectArgumentType = struct {};                                                                                       //!< establish a client connection to a server share command's arguments
using TreeConnectResultType = struct {};                                                                                         //!< establish a client connection to a server share command's results
using TreeConnectCommand = SMBv1::Command< TreeConnectArgumentType, TreeConnectResultType>;                                      //!< establish a client connection to a server share command

using TreeDisconnectArgumentType = struct {};                                                                                    //!< Disconnect command's arguments
using TreeDisconnectResultType = struct {};                                                                                      //!< Disconnect command's results
using TreeDisconnectCommand = SMBv1::Command< TreeDisconnectArgumentType, TreeDisconnectResultType>;                             //!< Disconnect command

using NegotiateArgumentType = struct {};                                                                                         //!< Negotiate command's arguments
using NegotiateResultType = struct {};                                                                                           //!< Negotiate command's results
using NegotiateCommand = SMBv1::Command< NegotiateArgumentType, NegotiateResultType>;                                            //!< Negotiate command

using SessionSetupAndxArgumentType = struct {};                                                                                  //!< Session setup command's arguments
using SessionSetupAndxResultType = struct {};                                                                                    //!< Session setup command's results
using SessionSetupAndxCommand = SMBv1::Command< SessionSetupAndxArgumentType, SessionSetupAndxResultType>;                       //!< Session setup command

using LogoffAndxArgumentType = struct {};                                                                                        //!< Log off command's arguments
using LogoffAndxResultType = struct {};                                                                                          //!< Log off command's results
using LogoffAndxCommand = SMBv1::Command< LogoffAndxArgumentType, LogoffAndxResultType>;                                         //!< Log off command

using TreeConnectAndxArgumentType = struct {};                                                                                   //!< Tree Connect command's arguments
using TreeConnectAndxResultType = struct {};                                                                                     //!< Tree Connect command's results
using TreeConnectAndxCommand = SMBv1::Command< TreeConnectAndxArgumentType, TreeConnectAndxResultType>;                          //!< Tree Connect command

using SecurityPackageAndxArgumentType = struct {};                                                                               //!< Security Package command's arguments
using SecurityPackageAndxResultType = struct {};                                                                                 //!< Security Package command's results
using SecurityPackageAndxCommand = SMBv1::Command< SecurityPackageAndxArgumentType, SecurityPackageAndxResultType>;              //!< Security Package command

using QueryInformationDiskArgumentType = struct {};                                                                              //!< Query Disk Information command's arguments
using QueryInformationDiskResultType = struct {};                                                                                //!< Query Disk Information command's results
using QueryInformationDiskCommand = SMBv1::Command< QueryInformationDiskArgumentType, QueryInformationDiskResultType>;           //!< Query Disk Information command

using SearchArgumentType = struct {};                                                                                            //!< Search command's arguments
using SearchResultType = struct {};                                                                                              //!< Search command's results
using SearchCommand = SMBv1::Command< SearchArgumentType, SearchResultType>;                                                     //!< Search command

using FindArgumentType = struct {};                                                                                              //!< Find command's arguments
using FindResultType = struct {};                                                                                                //!< Find command's results
using FindCommand = SMBv1::Command< FindArgumentType, FindResultType>;                                                           //!< Find command

using FindUniqueArgumentType = struct {};                                                                                        //!< Find unique command's arguments
using FindUniqueResultType = struct {};                                                                                          //!< Find unique command's results
using FindUniqueCommand = SMBv1::Command< FindUniqueArgumentType, FindUniqueResultType>;                                         //!< Find unique command

using FindCloseArgumentType = struct {};                                                                                         //!< Find close command's arguments
using FindCloseResultType = struct {};                                                                                           //!< Find close command's results
using FindCloseCommand = SMBv1::Command< FindCloseArgumentType, FindCloseResultType>;                                            //!< Find close command

using NtTransactArgumentType = struct {};                                                                                        //!< Transact command's arguments
using NtTransactResultType = struct {};                                                                                          //!< Transact command's results
using NtTransactCommand = SMBv1::Command< NtTransactArgumentType, NtTransactResultType>;                                         //!< Transact command

using NtTransactSecondaryArgumentType = struct {};                                                                               //!< Transact 2 command's arguments
using NtTransactSecondaryResultType = struct {};                                                                                 //!< Transact 2 command's results
using NtTransactSecondaryCommand = SMBv1::Command< NtTransactSecondaryArgumentType, NtTransactSecondaryResultType>;              //!< Transact 2 command

using NtCreateAndxArgumentType = struct {};                                                                                      //!< Create command's arguments
using NtCreateAndxResultType = struct {};                                                                                        //!< Create command's results
using NtCreateAndxCommand = SMBv1::Command< NtCreateAndxArgumentType, NtCreateAndxResultType>;                                   //!< Create command

using NtCancelArgumentType = struct {};                                                                                          //!< Cancel command's arguments
using NtCancelResultType = struct {};                                                                                            //!< Cancel command's results
using NtCancelCommand = SMBv1::Command< NtCancelArgumentType, NtCancelResultType>;                                               //!< Cancel command

using NtRenameArgumentType = struct {};                                                                                          //!< Rename command's arguments
using NtRenameResultType = struct {};                                                                                            //!< Rename command's results
using NtRenameCommand = SMBv1::Command< NtRenameArgumentType, NtRenameResultType>;                                               //!< Rename command

using OpenPrintFileArgumentType = struct {};                                                                                     //!< Open Print File command's arguments
using OpenPrintFileResultType = struct {};                                                                                       //!< Open Print File command's results
using OpenPrintFileCommand = SMBv1::Command< OpenPrintFileArgumentType, OpenPrintFileResultType>;                                //!< Open Print File command

using WritePrintFileArgumentType = struct {};                                                                                    //!< Write Print File command's arguments
using WritePrintFileResultType = struct {};                                                                                      //!< Write Print File command's results
using WritePrintFileCommand = SMBv1::Command< WritePrintFileArgumentType, WritePrintFileResultType>;                             //!< Write Print File command

using ClosePrintFileArgumentType = struct {};                                                                                    //!< Close Print File command's arguments
using ClosePrintFileResultType = struct {};                                                                                      //!< Close Print File command's results
using ClosePrintFileCommand = SMBv1::Command< ClosePrintFileArgumentType, ClosePrintFileResultType>;                             //!< Close Print File command

using GetPrintQueueArgumentType = struct {};                                                                                     //!< Get Print Queue command's arguments
using GetPrintQueueResultType = struct {};                                                                                       //!< Get Print Queue command's results
using GetPrintQueueCommand = SMBv1::Command< GetPrintQueueArgumentType, GetPrintQueueResultType>;                                //!< Get Print Queue command

using ReadBulkArgumentType = struct {};                                                                                          //!< Read Bulk command's arguments
using ReadBulkResultType = struct {};                                                                                            //!< Read Bulk command's results
using ReadBulkCommand = SMBv1::Command< ReadBulkArgumentType, ReadBulkResultType>;                                               //!< Read Bulk command

using WriteBulkArgumentType = struct {};                                                                                         //!< Write Bulk command's arguments
using WriteBulkResultType = struct {};                                                                                           //!< Write Bulk command's results
using WriteBulkCommand = SMBv1::Command< WriteBulkArgumentType, WriteBulkResultType>;                                            //!< Write Bulk command

using WriteBulkDataArgumentType = struct {};                                                                                     //!< Write Bulk command's arguments
using WriteBulkDataResultType = struct {};                                                                                       //!< Write Bulk command's results
using WriteBulkDataCommand = SMBv1::Command< WriteBulkDataArgumentType, WriteBulkDataResultType>;                                //!< Write Bulk command

using InvalidArgumentType = struct {};                                                                                           //!< Invalid command's arguments
using InvalidResultType = struct {};                                                                                             //!< Invalid command's results
using InvalidCommand = SMBv1::Command< InvalidArgumentType, InvalidResultType>;                                                  //!< Invalid command

using NoAndxCmdArgumentType = struct {};                                                                                         //!< No command's arguments
using NoAndxCmdResultType = struct {};                                                                                           //!< No command's results
using NoAndxCommand = SMBv1::Command< NoAndxCmdArgumentType, NoAndxCmdResultType>;                                               //!< No command

}//SMBv1

/*! SMB 2 version
 */
namespace SMBv2
{

using CloseFileCommand = SMBv1::Command<CloseRequest, CloseResponse>;                                 //!< Close file command
using NegotiateCommand = SMBv1::Command<NegotiateRequest, NegotiateResponse>;                         //!< Negotiate command
using SessionSetupCommand = SMBv1::Command<SessionSetupRequest, SessionSetupResponse>;                //!< Session setup command
using EchoCommand = SMBv1::Command<EchoRequest, EchoResponse>;                                        //!< Echo command
using LogOffCommand = SMBv1::Command<LogOffRequest, LogOffResponse>;                                  //!< Log off command
using TreeConnectCommand = SMBv1::Command<TreeConnectRequest, TreeConnectResponse>;                   //!< Tree connect command
using TreeDisconnectCommand = SMBv1::Command<TreeDisconnectRequest, TreeDisconnectResponse>;          //!< Tree disconnect command
using CreateCommand = SMBv1::Command<CreateRequest, CreateResponse>;                                  //!< Create command
using QueryInfoCommand = SMBv1::Command<QueryInfoRequest, QueryInfoResponse>;                         //!< Query Info command
using QueryDirCommand = SMBv1::Command<QueryDirRequest, QueryDirResponse>;                            //!< Query directory command
using FlushCommand = SMBv1::Command<FlushRequest, FlushResponse>;                                     //!< Flush command
using ReadCommand = SMBv1::Command<ReadRequest, ReadResponse>;                                        //!< Read command
using WriteCommand = SMBv1::Command<WriteRequest, WriteResponse>;                                     //!< Write command
using LockCommand = SMBv1::Command<LockRequest, LockResponse>;                                        //!< Lock command
using CancelResponce = struct {};                                                                     //!< Cancel command's results
using CancelCommand = SMBv1::Command<CancelRequest, CancelResponce>;                                  //!< Cancel command
using ChangeNotifyCommand = SMBv1::Command<ChangeNotifyRequest, ChangeNotifyResponse>;                //!< Change Notify command
using BreakOpLockCommand = SMBv1::Command<OplockAcknowledgment, OplockResponse>;                      //!< Break opportunistic lock command
using IoctlCommand = SMBv1::Command<IoCtlRequest, IoCtlResponse>;                                     //!< Ioctl command
using SetInfoCommand = SMBv1::Command<SetInfoRequest, SetInfoResponse>;                               //!< Set Info command

} // namespace SMBv2
} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//CIFS_TYPES_H
//------------------------------------------------------------------------------
