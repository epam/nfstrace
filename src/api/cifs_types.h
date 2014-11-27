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
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

/*! SMB 1 version
 */
namespace SMBv1
{

static const int commandsCount = 255;

using Session = u_int16_t;//!< Session IDentifier

/*! Represents one SMB command
 */
template <
    typename ArgumentType,
    typename ResultType
    >
class Command
{
public:
    Session session;//!< session ID
   ArgumentType parg;//!< Arguments of specified command
    ResultType pres;//!< Results of specified command
};


using EchoRequestArgumentType = int;                                                                                             //!< Echo request'a arguments
using EchoRequestResultType = int;                                                                                               //!< Echo request's results
using EchoRequestCommand = Command<EchoRequestArgumentType, EchoRequestResultType>;                                              //!< Echo request command

using CloseFileArgumentType = int;                                                                                               //!< Close file command's arguments
using CloseFileResultType = int;                                                                                                 //!< Close file command's results
using CloseFileCommand = Command<CloseFileArgumentType, CloseFileResultType>;                                                    //!< Close file command

using CreateDirectoryArgumentType = int;                                                                                         //!< CreateDirectory arguments
using CreateDirectoryResultType = int;                                                                                           //!< CreateDirectory results
using CreateDirectoryCommand = SMBv1::Command< CreateDirectoryArgumentType, CreateDirectoryResultType>;                          //!< CreateDirectory command

using DeleteDirectoryArgumentType = int;                                                                                         //!< DeleteDirectory arguments
using DeleteDirectoryResultType = int;                                                                                           //!< DeleteDirectory results
using DeleteDirectoryCommand = SMBv1::Command< DeleteDirectoryArgumentType, DeleteDirectoryResultType>;                          //!< DeleteDirectory command

using OpenArgumentType = int;                                                                                                    //!< Echo arguments
using OpenResultType = int;                                                                                                      //!< Echo results
using OpenCommand = SMBv1::Command< OpenArgumentType, OpenResultType>;                                                           //!< Echo command

using CreateArgumentType = int;                                                                                                  //!< Create arguments
using CreateResultType = int;                                                                                                    //!< Create results
using CreateCommand = SMBv1::Command< CreateArgumentType, CreateResultType>;                                                     //!< Create command

using CloseArgumentType = int;                                                                                                   //!< Close arguments
using CloseResultType = int;                                                                                                     //!< Close results
using CloseCommand = SMBv1::Command< CloseArgumentType, CloseResultType>;                                                        //!< Close command

using FlushArgumentType = int;                                                                                                   //!< Flush arguments
using FlushResultType = int;                                                                                                     //!< Flush results
using FlushCommand = SMBv1::Command< FlushArgumentType, FlushResultType>;                                                        //!< Flush command

using DeleteArgumentType = int;                                                                                                  //!< Delete arguments
using DeleteResultType = int;                                                                                                    //!< Delete results
using DeleteCommand = SMBv1::Command< DeleteArgumentType, DeleteResultType>;                                                     //!< Delete command

using RenameArgumentType = int;                                                                                                  //!< Rename arguments
using RenameResultType = int;                                                                                                    //!< Rename results
using RenameCommand = SMBv1::Command< RenameArgumentType, RenameResultType>;                                                     //!< Rename command

using QueryInformationArgumentType = int;                                                                                        //!< QueryInformation arguments
using QueryInformationResultType = int;                                                                                          //!< QueryInformation results
using QueryInformationCommand = SMBv1::Command< QueryInformationArgumentType, QueryInformationResultType>;                       //!< QueryInformation command. This transaction is used to get information about a specific file or directory. There are several information levels that can be queried.

using SetInformationArgumentType = int;                                                                                          //!< Set Information arguments
using SetInformationResultType = int;                                                                                            //!< Set Information results
using SetInformationCommand = SMBv1::Command< SetInformationArgumentType, SetInformationResultType>;                             //!< Set Information command. This transaction is used to set the standard and extended attribute information of a specific file or directory on the server.

using ReadArgumentType = int;                                                                                                    //!< Read arguments
using ReadResultType = int;                                                                                                      //!< Read results
using ReadCommand = SMBv1::Command< ReadArgumentType, ReadResultType>;                                                           //!< Read command

using WriteArgumentType = int;                                                                                                   //!< Write arguments
using WriteResultType = int;                                                                                                     //!< Write results
using WriteCommand = SMBv1::Command< WriteArgumentType, WriteResultType>;                                                        //!< Write command

using LockByteRangeArgumentType = int;                                                                                           //!< Lock Byte Range arguments
using LockByteRangeResultType = int;                                                                                             //!< Lock Byte Range results
using LockByteRangeCommand = SMBv1::Command< LockByteRangeArgumentType, LockByteRangeResultType>;                                //!< Lock Byte Range command. This command is used to explicitly lock a contiguous range of bytes in an open regular file.

using UnlockByteRangeArgumentType = int;                                                                                         //!< UnLock Byte Range arguments
using UnlockByteRangeResultType = int;                                                                                           //!< UnLock Byte Range results
using UnlockByteRangeCommand = SMBv1::Command< UnlockByteRangeArgumentType, UnlockByteRangeResultType>;                          //!< UnLock Byte Range command

using CreateTemporaryArgumentType = int;                                                                                         //!< Create Temporary file arguments
using CreateTemporaryResultType = int;                                                                                           //!< Create Temporary file results
using CreateTemporaryCommand = SMBv1::Command< CreateTemporaryArgumentType, CreateTemporaryResultType>;                          //!< Create Temporary file command. This command is used to create a file for temporary use by the client.

using CreateNewArgumentType = int;                                                                                               //!< Create a new file arguments
using CreateNewResultType = int;                                                                                                 //!< Create a new file results
using CreateNewCommand = SMBv1::Command< CreateNewArgumentType, CreateNewResultType>;                                            //!< Create a new file command. This command is used to create a new file. It MUST NOT truncate or overwrite an existing file.

using CheckDirectoryArgumentType = int;                                                                                          //!< CheckDirectory arguments
using CheckDirectoryResultType = int;                                                                                            //!< CheckDirectory results
using CheckDirectoryCommand = SMBv1::Command< CheckDirectoryArgumentType, CheckDirectoryResultType>;                             //!< CheckDirectory command. This command is used to verify that a specified path resolves to a valid directory on the server.

using ProcessExitArgumentType = int;                                                                                             //!< Process Exit arguments
using ProcessExitResultType = int;                                                                                               //!< Process Exit results
using ProcessExitCommand = SMBv1::Command< ProcessExitArgumentType, ProcessExitResultType>;                                      //!< Process Exit command.An SMB_COM_PROCESS_EXIT request is sent by the client to indicate the catastrophic failure of a client process.

using SeekArgumentType = int;                                                                                                    //!< Seek arguments
using SeekResultType = int;                                                                                                      //!< Seek results
using SeekCommand = SMBv1::Command< SeekArgumentType, SeekResultType>;                                                           //!< Seek command

using LockAndReadArgumentType = int;                                                                                             //!< Lock And Read arguments
using LockAndReadResultType = int;                                                                                               //!< Lock And Read results
using LockAndReadCommand = SMBv1::Command< LockAndReadArgumentType, LockAndReadResultType>;                                      //!< Lock And Read command

using WriteAndUnlockArgumentType = int;                                                                                          //!< Write And Unlock arguments
using WriteAndUnlockResultType = int;                                                                                            //!< Write And Unlock results
using WriteAndUnlockCommand = SMBv1::Command< WriteAndUnlockArgumentType, WriteAndUnlockResultType>;                             //!< Write And Unlock command

using ReadRawArgumentType = int;                                                                                                 //!< Read raw command's arguments
using ReadRawResultType = int;                                                                                                   //!< Read raw command's results
using ReadRawCommand = SMBv1::Command< ReadRawArgumentType, ReadRawResultType>;                                                  //!< Read raw command

using ReadMpxArgumentType = int;                                                                                                 //!< Read Mpx command's arguments
using ReadMpxResultType = int;                                                                                                   //!< Read Mpx command's results
using ReadMpxCommand = SMBv1::Command< ReadMpxArgumentType, ReadMpxResultType>;                                                  //!< Read Mpx command. This is a specialized read command intended to maximize the performance of reading large blocks of data from a regular file while allowing for other operations to take place between the client and the server.

using ReadMpxSecondaryArgumentType = int;                                                                                        //!< Read Read Mpx Secondary command's arguments
using ReadMpxSecondaryResultType = int;                                                                                          //!< Read Read Mpx Secondary command's results
using ReadMpxSecondaryCommand = SMBv1::Command< ReadMpxSecondaryArgumentType, ReadMpxSecondaryResultType>;                       //!< Read Read Mpx Secondary command

using WriteRawArgumentType = int;                                                                                                //!< Write Raw command's arguments
using WriteRawResultType = int;                                                                                                  //!< Write Raw command's results
using WriteRawCommand = SMBv1::Command< WriteRawArgumentType, WriteRawResultType>;                                               //!< Write Raw command. The command permits a client to send a large unformatted data (raw byte) message over the SMB transport without requiring the usual SMB request format

using WriteMpxArgumentType = int;                                                                                                //!< Write Mpx command's arguments
using WriteMpxResultType = int;                                                                                                  //!< Write Mpx command's results
using WriteMpxCommand = SMBv1::Command< WriteMpxArgumentType, WriteMpxResultType>;                                               //!< Write Mpx command

using WriteMpxSecondaryArgumentType = int;                                                                                       //!< Write Mpx 2 command's arguments
using WriteMpxSecondaryResultType = int;                                                                                         //!< Write Mpx 2 command's results
using WriteMpxSecondaryCommand = SMBv1::Command< WriteMpxSecondaryArgumentType, WriteMpxSecondaryResultType>;                    //!< Write Mpx 2 command

using WriteCompleteArgumentType = int;                                                                                           //!< Write Complete command's arguments
using WriteCompleteResultType = int;                                                                                             //!< Write Complete command's results
using WriteCompleteCommand = SMBv1::Command< WriteCompleteArgumentType, WriteCompleteResultType>;                                //!< Write Complete command

using QueryServerArgumentType = int;                                                                                             //!< Query Server (reserved) command's arguments
using QueryServerResultType = int;                                                                                               //!< Query Server (reserved) command's results
using QueryServerCommand = SMBv1::Command< QueryServerArgumentType, QueryServerResultType>;                                      //!< Query Server (reserved) command

using SetInformation2ArgumentType = int;                                                                                         //!< Set Information 2 command's arguments
using SetInformation2ResultType = int;                                                                                           //!< Set Information 2 command's results
using SetInformation2Command = SMBv1::Command< SetInformation2ArgumentType, SetInformation2ResultType>;                          //!< Set Information 2 command

using QueryInformation2ArgumentType = int;                                                                                       //!< Query Information 2 command's arguments
using QueryInformation2ResultType = int;                                                                                         //!< Query Information 2 command's results
using QueryInformation2Command = SMBv1::Command< QueryInformation2ArgumentType, QueryInformation2ResultType>;                    //!< Query Information 2 command

using LockingAndxArgumentType = int;                                                                                             //!< Lock some bytes of the file command's arguments
using LockingAndxResultType = int;                                                                                               //!< Lock some bytes of the file command's results
using LockingAndxCommand = SMBv1::Command< LockingAndxArgumentType, LockingAndxResultType>;                                      //!< Lock some bytes of the file command

using TransactionArgumentType = int;                                                                                             //!< Transaction command's arguments
using TransactionResultType = int;                                                                                               //!< Transaction command's results
using TransactionCommand = SMBv1::Command< TransactionArgumentType, TransactionResultType>;                                      //!< Transaction command.These commands operate on mailslots and named pipes, which are interprocess communication endpoints within the CIFS file system

using TransactionSecondaryArgumentType = int;                                                                                    //!< Transaction 2 command's arguments
using TransactionSecondaryResultType = int;                                                                                      //!< Transaction 2 command's results
using TransactionSecondaryCommand = SMBv1::Command< TransactionSecondaryArgumentType, TransactionSecondaryResultType>;           //!< Transaction 2 command

using IoctlArgumentType = int;                                                                                                   //!< Ioctl command's arguments
using IoctlResultType = int;                                                                                                     //!< Ioctl command's results
using IoctlCommand = SMBv1::Command< IoctlArgumentType, IoctlResultType>;                                                        //!< Ioctl command

using IoctlSecondaryArgumentType = int;                                                                                          //!< Ioctl 2 command's arguments
using IoctlSecondaryResultType = int;                                                                                            //!< Ioctl 2 command's results
using IoctlSecondaryCommand = SMBv1::Command< IoctlSecondaryArgumentType, IoctlSecondaryResultType>;                             //!< Ioctl 2 command

using CopyArgumentType = int;                                                                                                    //!< Copy command's arguments
using CopyResultType = int;                                                                                                      //!< Copy command's results
using CopyCommand = SMBv1::Command< CopyArgumentType, CopyResultType>;                                                           //!< Copy command

using MoveArgumentType = int;                                                                                                    //!< Move command's arguments
using MoveResultType = int;                                                                                                      //!< Move command's results
using MoveCommand = SMBv1::Command< MoveArgumentType, MoveResultType>;                                                           //!< Move command

using EchoArgumentType = int;                                                                                                    //!< Echo command's arguments
using EchoResultType = int;                                                                                                      //!< Echo command's results
using EchoCommand = SMBv1::Command< EchoArgumentType, EchoResultType>;                                                           //!< Echo command

using WriteAndCloseArgumentType = int;                                                                                           //!< Write And Close command's arguments
using WriteAndCloseResultType = int;                                                                                             //!< Write And Close command's results
using WriteAndCloseCommand = SMBv1::Command< WriteAndCloseArgumentType, WriteAndCloseResultType>;                                //!< Write And Close command

using OpenAndxArgumentType = int;                                                                                                //!< Open 2 command's arguments
using OpenAndxResultType = int;                                                                                                  //!< Open 2 command's results
using OpenAndxCommand = SMBv1::Command< OpenAndxArgumentType, OpenAndxResultType>;                                               //!< Open 2 command

using ReadAndxArgumentType = int;                                                                                                //!< Read 2 command's arguments
using ReadAndxResultType = int;                                                                                                  //!< Read 2 command's results
using ReadAndxCommand = SMBv1::Command< ReadAndxArgumentType, ReadAndxResultType>;                                               //!< Read 2 command

using WriteAndxArgumentType = int;                                                                                               //!< Write 2 command's arguments
using WriteAndxResultType = int;                                                                                                 //!< Write 2 command's results
using WriteAndxCommand = SMBv1::Command< WriteAndxArgumentType, WriteAndxResultType>;                                            //!< Write 2 command

using NewFileSizeArgumentType = int;                                                                                             //!< New File Size command's arguments
using NewFileSizeResultType = int;                                                                                               //!< New File Size command's results
using NewFileSizeCommand = SMBv1::Command< NewFileSizeArgumentType, NewFileSizeResultType>;                                      //!< New File Size command. Reserved but not implemented

using CloseAndTreeDiscArgumentType = int;                                                                                        //!< Reserved command's arguments
using CloseAndTreeDiscResultType = int;                                                                                          //!< Reserved command's results
using CloseAndTreeDiscCommand = SMBv1::Command< CloseAndTreeDiscArgumentType, CloseAndTreeDiscResultType>;                       //!< Reserved command

using Transaction2ArgumentType = int;                                                                                            //!< Transaction 2 command's arguments
using Transaction2ResultType = int;                                                                                              //!< Transaction 2 command's results
using Transaction2Command = SMBv1::Command< Transaction2ArgumentType, Transaction2ResultType>;                                   //!< Transaction 2 command

using Transaction2SecondaryArgumentType = int;                                                                                   //!< Transaction 3 command's arguments
using Transaction2SecondaryResultType = int;                                                                                     //!< Transaction 3 command's results
using Transaction2SecondaryCommand = SMBv1::Command< Transaction2SecondaryArgumentType, Transaction2SecondaryResultType>;        //!< Transaction 3 command

using FindClose2ArgumentType = int;                                                                                              //!< Search handle close command's arguments
using FindClose2ResultType = int;                                                                                                //!< Search handle close command's results
using FindClose2Command = SMBv1::Command< FindClose2ArgumentType, FindClose2ResultType>;                                         //!< Search handle close command

using FindNotifyCloseArgumentType = int;                                                                                         //!< Search handle close command's arguments
using FindNotifyCloseResultType = int;                                                                                           //!< Search handle close command's results
using FindNotifyCloseCommand = SMBv1::Command< FindNotifyCloseArgumentType, FindNotifyCloseResultType>;                          //!< Search handle close command

using TreeConnectArgumentType = int;                                                                                             //!< establish a client connection to a server share command's arguments
using TreeConnectResultType = int;                                                                                               //!< establish a client connection to a server share command's results
using TreeConnectCommand = SMBv1::Command< TreeConnectArgumentType, TreeConnectResultType>;                                      //!< establish a client connection to a server share command

using TreeDisconnectArgumentType = int;                                                                                          //!< Disconnect command's arguments
using TreeDisconnectResultType = int;                                                                                            //!< Disconnect command's results
using TreeDisconnectCommand = SMBv1::Command< TreeDisconnectArgumentType, TreeDisconnectResultType>;                             //!< Disconnect command

using NegotiateArgumentType = int;                                                                                               //!< Negotiate command's arguments
using NegotiateResultType = int;                                                                                                 //!< Negotiate command's results
using NegotiateCommand = SMBv1::Command< NegotiateArgumentType, NegotiateResultType>;                                            //!< Negotiate command

using SessionSetupAndxArgumentType = int;                                                                                        //!< Session setup command's arguments
using SessionSetupAndxResultType = int;                                                                                          //!< Session setup command's results
using SessionSetupAndxCommand = SMBv1::Command< SessionSetupAndxArgumentType, SessionSetupAndxResultType>;                       //!< Session setup command

using LogoffAndxArgumentType = int;                                                                                              //!< Log off command's arguments
using LogoffAndxResultType = int;                                                                                                //!< Log off command's results
using LogoffAndxCommand = SMBv1::Command< LogoffAndxArgumentType, LogoffAndxResultType>;                                         //!< Log off command

using TreeConnectAndxArgumentType = int;                                                                                         //!< Tree Connect command's arguments
using TreeConnectAndxResultType = int;                                                                                           //!< Tree Connect command's results
using TreeConnectAndxCommand = SMBv1::Command< TreeConnectAndxArgumentType, TreeConnectAndxResultType>;                          //!< Tree Connect command

using SecurityPackageAndxArgumentType = int;                                                                                     //!< Security Package command's arguments
using SecurityPackageAndxResultType = int;                                                                                       //!< Security Package command's results
using SecurityPackageAndxCommand = SMBv1::Command< SecurityPackageAndxArgumentType, SecurityPackageAndxResultType>;              //!< Security Package command

using QueryInformationDiskArgumentType = int;                                                                                    //!< Query Disk Information command's arguments
using QueryInformationDiskResultType = int;                                                                                      //!< Query Disk Information command's results
using QueryInformationDiskCommand = SMBv1::Command< QueryInformationDiskArgumentType, QueryInformationDiskResultType>;           //!< Query Disk Information command

using SearchArgumentType = int;                                                                                                  //!< Search command's arguments
using SearchResultType = int;                                                                                                    //!< Search command's results
using SearchCommand = SMBv1::Command< SearchArgumentType, SearchResultType>;                                                     //!< Search command

using FindArgumentType = int;                                                                                                    //!< Find command's arguments
using FindResultType = int;                                                                                                      //!< Find command's results
using FindCommand = SMBv1::Command< FindArgumentType, FindResultType>;                                                           //!< Find command

using FindUniqueArgumentType = int;                                                                                              //!< Find unique command's arguments
using FindUniqueResultType = int;                                                                                                //!< Find unique command's results
using FindUniqueCommand = SMBv1::Command< FindUniqueArgumentType, FindUniqueResultType>;                                         //!< Find unique command

using FindCloseArgumentType = int;                                                                                               //!< Find close command's arguments
using FindCloseResultType = int;                                                                                                 //!< Find close command's results
using FindCloseCommand = SMBv1::Command< FindCloseArgumentType, FindCloseResultType>;                                            //!< Find close command

using NtTransactArgumentType = int;                                                                                              //!< Transact command's arguments
using NtTransactResultType = int;                                                                                                //!< Transact command's results
using NtTransactCommand = SMBv1::Command< NtTransactArgumentType, NtTransactResultType>;                                         //!< Transact command

using NtTransactSecondaryArgumentType = int;                                                                                     //!< Transact 2 command's arguments
using NtTransactSecondaryResultType = int;                                                                                       //!< Transact 2 command's results
using NtTransactSecondaryCommand = SMBv1::Command< NtTransactSecondaryArgumentType, NtTransactSecondaryResultType>;              //!< Transact 2 command

using NtCreateAndxArgumentType = int;                                                                                            //!< Create command's arguments
using NtCreateAndxResultType = int;                                                                                              //!< Create command's results
using NtCreateAndxCommand = SMBv1::Command< NtCreateAndxArgumentType, NtCreateAndxResultType>;                                   //!< Create command

using NtCancelArgumentType = int;                                                                                                //!< Cancel command's arguments
using NtCancelResultType = int;                                                                                                  //!< Cancel command's results
using NtCancelCommand = SMBv1::Command< NtCancelArgumentType, NtCancelResultType>;                                               //!< Cancel command

using NtRenameArgumentType = int;                                                                                                //!< Rename command's arguments
using NtRenameResultType = int;                                                                                                  //!< Rename command's results
using NtRenameCommand = SMBv1::Command< NtRenameArgumentType, NtRenameResultType>;                                               //!< Rename command

using OpenPrintFileArgumentType = int;                                                                                           //!< Open Print File command's arguments
using OpenPrintFileResultType = int;                                                                                             //!< Open Print File command's results
using OpenPrintFileCommand = SMBv1::Command< OpenPrintFileArgumentType, OpenPrintFileResultType>;                                //!< Open Print File command

using WritePrintFileArgumentType = int;                                                                                          //!< Write Print File command's arguments
using WritePrintFileResultType = int;                                                                                            //!< Write Print File command's results
using WritePrintFileCommand = SMBv1::Command< WritePrintFileArgumentType, WritePrintFileResultType>;                             //!< Write Print File command

using ClosePrintFileArgumentType = int;                                                                                          //!< Close Print File command's arguments
using ClosePrintFileResultType = int;                                                                                            //!< Close Print File command's results
using ClosePrintFileCommand = SMBv1::Command< ClosePrintFileArgumentType, ClosePrintFileResultType>;                             //!< Close Print File command

using GetPrintQueueArgumentType = int;                                                                                           //!< Get Print Queue command's arguments
using GetPrintQueueResultType = int;                                                                                             //!< Get Print Queue command's results
using GetPrintQueueCommand = SMBv1::Command< GetPrintQueueArgumentType, GetPrintQueueResultType>;                                //!< Get Print Queue command

using ReadBulkArgumentType = int;                                                                                                //!< Read Bulk command's arguments
using ReadBulkResultType = int;                                                                                                  //!< Read Bulk command's results
using ReadBulkCommand = SMBv1::Command< ReadBulkArgumentType, ReadBulkResultType>;                                               //!< Read Bulk command

using WriteBulkArgumentType = int;                                                                                               //!< Write Bulk command's arguments
using WriteBulkResultType = int;                                                                                                 //!< Write Bulk command's results
using WriteBulkCommand = SMBv1::Command< WriteBulkArgumentType, WriteBulkResultType>;                                            //!< Write Bulk command

using WriteBulkDataArgumentType = int;                                                                                           //!< Write Bulk command's arguments
using WriteBulkDataResultType = int;                                                                                             //!< Write Bulk command's results
using WriteBulkDataCommand = SMBv1::Command< WriteBulkDataArgumentType, WriteBulkDataResultType>;                                //!< Write Bulk command

using InvalidArgumentType = int;                                                                                                 //!< Invalid command's arguments
using InvalidResultType = int;                                                                                                   //!< Invalid command's results
using InvalidCommand = SMBv1::Command< InvalidArgumentType, InvalidResultType>;                                                  //!< Invalid command

using NoAndxCmdArgumentType = int;                                                                                               //!< No command's arguments
using NoAndxCmdResultType = int;                                                                                                 //!< No command's results
using NoAndxCommand = SMBv1::Command< NoAndxCmdArgumentType, NoAndxCmdResultType>;                                               //!< No command

}

/*! SMB 2 version
 */
namespace SMBv2
{

using CloseFileArgumentType = int;                                                                    //!< Close file command's arguments
using CloseFileResultType = int;                                                                      //!< Close file command's results
using CloseFileCommand = SMBv1::Command<CloseFileArgumentType, CloseFileResultType>;                  //!< Close file command

using NegotiateArgumentType = int;                                                                    //!< Close file command's arguments
using NegotiateResultType = int;                                                                      //!< Close file command's results
using NegotiateCommand = SMBv1::Command<NegotiateArgumentType, NegotiateResultType>;                  //!< Negotiate command

using SessionSetupArgumentType = int;                                                                 //!< Session setup command's arguments
using SessionSetupResultType = int;                                                                   //!< Session setup command's results
using SessionSetupCommand = SMBv1::Command<SessionSetupArgumentType, SessionSetupResultType>;         //!< Session setup command

using LogOffArgumentType = int;                                                                       //!< Log off command's arguments
using LogOffResultType = int;                                                                         //!< Log off command's results
using LogOffCommand = SMBv1::Command<LogOffArgumentType, LogOffResultType>;                           //!< Log off command

using TreeConnectArgumentType = int;                                                                  //!< Tree connect command's arguments
using TreeConnectResultType = int;                                                                    //!< Tree connect command's results
using TreeConnectCommand = SMBv1::Command<TreeConnectArgumentType, TreeConnectResultType>;            //!< Tree connect command

using TreeDisconnectArgumentType = int;                                                               //!< Tree disconnect command's arguments
using TreeDisconnectResultType = int;                                                                 //!< Tree disconnect command's results
using TreeDisconnectCommand = SMBv1::Command<TreeDisconnectArgumentType, TreeDisconnectResultType>;   //!< Tree disconnect command

using CreateArgumentType = int;                                                                       //!< Create command's arguments
using CreateResultType = int;                                                                         //!< Create command's results
using CreateCommand = SMBv1::Command<CreateArgumentType, CreateResultType>;                           //!< Create command

using FlushArgumentType = int;                                                                        //!< Flush command's arguments
using FlushResultType = int;                                                                          //!< Flush command's results
using FlushCommand = SMBv1::Command<FlushArgumentType, FlushResultType>;                              //!< Flush command

using ReadArgumentType = int;                                                                         //!< Read command's arguments
using ReadResultType = int;                                                                           //!< Read command's results
using ReadCommand = SMBv1::Command<ReadArgumentType, ReadResultType>;                                 //!< Read command

using WriteArgumentType = int;                                                                        //!< Write command's arguments
using WriteResultType = int;                                                                          //!< Write command's results
using WriteCommand = SMBv1::Command<WriteArgumentType, WriteResultType>;                              //!< Write command

using LockArgumentType = int;                                                                         //!< Lock command's arguments
using LockResultType = int;                                                                           //!< Lock command's results
using LockCommand = SMBv1::Command<LockArgumentType, LockResultType>;                                 //!< Lock command

using IoctlArgumentType = int;                                                                        //!< Ioctl command's arguments
using IoctlResultType = int;                                                                          //!< Ioctl command's results
using IoctlCommand = SMBv1::Command<IoctlArgumentType, IoctlResultType>;                              //!< Ioctl command

using CancelArgumentType = int;                                                                       //!< Cancel command's arguments
using CancelResultType = int;                                                                         //!< Cancel command's results
using CancelCommand = SMBv1::Command<CancelArgumentType, CancelResultType>;                           //!< Cancel command

using EchoArgumentType = int;                                                                         //!< Echo command's arguments
using EchoResultType = int;                                                                           //!< Echo command's results
using EchoCommand = SMBv1::Command<EchoArgumentType, EchoResultType>;                                 //!< Echo command

using QueryDirArgumentType = int;                                                                     //!< Query directory command's arguments
using QueryDirResultType = int;                                                                       //!< Query directory command's results
using QueryDirCommand = SMBv1::Command<QueryDirArgumentType, QueryDirResultType>;                     //!< Query directory command

using ChangeNotifyArgumentType = int;                                                                 //!< Change Notify command's arguments
using ChangeNotifyResultType = int;                                                                   //!< Change Notify command's results
using ChangeNotifyCommand = SMBv1::Command<ChangeNotifyArgumentType, ChangeNotifyResultType>;         //!< Change Notify command

using QueryInfoArgumentType = int;                                                                    //!< Query Info command's arguments
using QueryInfoResultType = int;                                                                      //!< Query Info command's results
using QueryInfoCommand = SMBv1::Command<QueryInfoArgumentType, QueryInfoResultType>;                  //!< Query Info command

using SetInfoArgumentType = int;                                                                      //!< Set Info command's arguments
using SetInfoResultType = int;                                                                        //!< Set Info command's results
using SetInfoCommand = SMBv1::Command<SetInfoArgumentType, SetInfoResultType>;                        //!< Set Info command

using BreakOpLockArgumentType = int;                                                                  //!< Break opportunistic lock command's arguments
using BreakOpLockResultType = int;                                                                    //!< Break opportunistic lock command's results
using BreakOpLockCommand = SMBv1::Command<BreakOpLockArgumentType, BreakOpLockResultType>;            //!< Break opportunistic lock command

}

}
}
#endif // CIFS_TYPES_H
