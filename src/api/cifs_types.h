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
#include "cifs2_commands.h"
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

using CreateDirectoryCommand = SMBv1::Command< CreateDirectoryArgumentType, CreateDirectoryResultType>;                          //!< CreateDirectory command
using DeleteDirectoryCommand = SMBv1::Command< DeleteDirectoryArgumentType, DeleteDirectoryResultType>;                          //!< DeleteDirectory command
using OpenCommand = SMBv1::Command< OpenArgumentType, OpenResultType>;                                                           //!< Open command
using CreateCommand = SMBv1::Command< CreateArgumentType, CreateResultType>;                                                     //!< Create command
using CloseCommand = SMBv1::Command< CloseArgumentType, CloseResultType>;                                                        //!< Close command
using FlushCommand = SMBv1::Command< FlushArgumentType, FlushResultType>;                                                        //!< Flush command
using DeleteCommand = SMBv1::Command< DeleteArgumentType, DeleteResultType>;                                                     //!< Delete command
using RenameCommand = SMBv1::Command< RenameArgumentType, RenameResultType>;                                                     //!< Rename command
using QueryInformationCommand = SMBv1::Command< QueryInformationArgumentType, QueryInformationResultType>;                       //!< QueryInformation command. This transaction is used to get information about a specific file or directory. There are several information levels that can be queried.
using SetInformationCommand = SMBv1::Command< SetInformationArgumentType, SetInformationResultType>;                             //!< Set Information command. This transaction is used to set the standard and extended attribute information of a specific file or directory on the server.
using ReadCommand = SMBv1::Command< ReadArgumentType, ReadResultType>;                                                           //!< Read command
using WriteCommand = SMBv1::Command< WriteArgumentType, WriteResultType>;                                                        //!< Write command
using LockByteRangeCommand = SMBv1::Command< LockByteRangeArgumentType, LockByteRangeResultType>;                                //!< Lock Byte Range command. This command is used to explicitly lock a contiguous range of bytes in an open regular file.
using UnlockByteRangeCommand = SMBv1::Command< UnlockByteRangeArgumentType, UnlockByteRangeResultType>;                          //!< UnLock Byte Range command
using CreateTemporaryCommand = SMBv1::Command< CreateTemporaryArgumentType, CreateTemporaryResultType>;                          //!< Create Temporary file command. This command is used to create a file for temporary use by the client.
using CreateNewCommand = SMBv1::Command< CreateNewArgumentType, CreateNewResultType>;                                            //!< Create a new file command. This command is used to create a new file. It MUST NOT truncate or overwrite an existing file.
using CheckDirectoryCommand = SMBv1::Command< CheckDirectoryArgumentType, CheckDirectoryResultType>;                             //!< CheckDirectory command. This command is used to verify that a specified path resolves to a valid directory on the server.
using ProcessExitCommand = SMBv1::Command< ProcessExitArgumentType, ProcessExitResultType>;                                      //!< Process Exit command.An SMB_COM_PROCESS_EXIT request is sent by the client to indicate the catastrophic failure of a client process.
using SeekCommand = SMBv1::Command< SeekArgumentType, SeekResultType>;                                                           //!< Seek command
using LockAndReadCommand = SMBv1::Command< LockAndReadArgumentType, LockAndReadResultType>;                                      //!< Lock And Read command
using WriteAndUnlockCommand = SMBv1::Command< WriteAndUnlockArgumentType, WriteAndUnlockResultType>;                             //!< Write And Unlock command
using ReadRawCommand = SMBv1::Command< ReadRawArgumentType, ReadRawResultType>;                                                  //!< Read raw command
using ReadMpxCommand = SMBv1::Command< ReadMpxArgumentType, ReadMpxResultType>;                                                  //!< Read Mpx command. This is a specialized read command intended to maximize the performance of reading large blocks of data from a regular file while allowing for other operations to take place between the client and the server.
using ReadMpxSecondaryCommand = SMBv1::Command< ReadMpxSecondaryArgumentType, ReadMpxSecondaryResultType>;                       //!< Read Read Mpx Secondary command
using WriteRawCommand = SMBv1::Command< WriteRawArgumentType, WriteRawResultType>;                                               //!< Write Raw command. The command permits a client to send a large unformatted data (raw byte) message over the SMB transport without requiring the usual SMB request format
using WriteMpxCommand = SMBv1::Command< WriteMpxArgumentType, WriteMpxResultType>;                                               //!< Write Mpx command
using WriteMpxSecondaryCommand = SMBv1::Command< WriteMpxSecondaryArgumentType, WriteMpxSecondaryResultType>;                    //!< Write Mpx 2 command
using WriteCompleteCommand = SMBv1::Command< WriteCompleteArgumentType, WriteCompleteResultType>;                                //!< Write Complete command
using QueryServerCommand = SMBv1::Command< QueryServerArgumentType, QueryServerResultType>;                                      //!< Query Server (reserved) command
using SetInformation2Command = SMBv1::Command< SetInformation2ArgumentType, SetInformation2ResultType>;                          //!< Set Information 2 command
using QueryInformation2Command = SMBv1::Command< QueryInformation2ArgumentType, QueryInformation2ResultType>;                    //!< Query Information 2 command
using LockingAndxCommand = SMBv1::Command< LockingAndxArgumentType, LockingAndxResultType>;                                      //!< Lock some bytes of the file command
using TransactionCommand = SMBv1::Command< TransactionArgumentType, TransactionResultType>;                                      //!< Transaction command.These commands operate on mailslots and named pipes, which are interprocess communication endpoints within the CIFS file system
using TransactionSecondaryCommand = SMBv1::Command< TransactionSecondaryArgumentType, TransactionSecondaryResultType>;           //!< Transaction 2 command
using IoctlCommand = SMBv1::Command< IoctlArgumentType, IoctlResultType>;                                                        //!< Ioctl command
using IoctlSecondaryCommand = SMBv1::Command< IoctlSecondaryArgumentType, IoctlSecondaryResultType>;                             //!< Ioctl 2 command
using CopyCommand = SMBv1::Command< CopyArgumentType, CopyResultType>;                                                           //!< Copy command
using MoveCommand = SMBv1::Command< MoveArgumentType, MoveResultType>;                                                           //!< Move command
using EchoCommand = SMBv1::Command< EchoArgumentType, EchoResultType>;                                                           //!< Echo command
using WriteAndCloseCommand = SMBv1::Command< WriteAndCloseArgumentType, WriteAndCloseResultType>;                                //!< Write And Close command
using OpenAndxCommand = SMBv1::Command< OpenAndxArgumentType, OpenAndxResultType>;                                               //!< Open 2 command
using ReadAndxCommand = SMBv1::Command< ReadAndxArgumentType, ReadAndxResultType>;                                               //!< Read 2 command
using WriteAndxCommand = SMBv1::Command< WriteAndxArgumentType, WriteAndxResultType>;                                            //!< Write 2 command
using NewFileSizeCommand = SMBv1::Command< NewFileSizeArgumentType, NewFileSizeResultType>;                                      //!< New File Size command. Reserved but not implemented
using CloseAndTreeDiscCommand = SMBv1::Command< CloseAndTreeDiscArgumentType, CloseAndTreeDiscResultType>;                       //!< Reserved command
using Transaction2Command = SMBv1::Command< Transaction2ArgumentType, Transaction2ResultType>;                                   //!< Transaction 2 command
using Transaction2SecondaryCommand = SMBv1::Command< Transaction2SecondaryArgumentType, Transaction2SecondaryResultType>;        //!< Transaction 3 command
using FindClose2Command = SMBv1::Command< FindClose2ArgumentType, FindClose2ResultType>;                                         //!< Search handle close command
using FindNotifyCloseCommand = SMBv1::Command< FindNotifyCloseArgumentType, FindNotifyCloseResultType>;                          //!< Search handle close command
using TreeConnectCommand = SMBv1::Command< TreeConnectArgumentType, TreeConnectResultType>;                                      //!< establish a client connection to a server share command
using TreeDisconnectCommand = SMBv1::Command< TreeDisconnectArgumentType, TreeDisconnectResultType>;                             //!< Disconnect command
using NegotiateCommand = SMBv1::Command< NegotiateArgumentType, NegotiateResultType>;                                            //!< Negotiate command
using SessionSetupAndxCommand = SMBv1::Command< SessionSetupAndxArgumentType, SessionSetupAndxResultType>;                       //!< Session setup command
using LogoffAndxCommand = SMBv1::Command< LogoffAndxArgumentType, LogoffAndxResultType>;                                         //!< Log off command
using TreeConnectAndxCommand = SMBv1::Command< TreeConnectAndxArgumentType, TreeConnectAndxResultType>;                          //!< Tree Connect command
using SecurityPackageAndxCommand = SMBv1::Command< SecurityPackageAndxArgumentType, SecurityPackageAndxResultType>;              //!< Security Package command
using QueryInformationDiskCommand = SMBv1::Command< QueryInformationDiskArgumentType, QueryInformationDiskResultType>;           //!< Query Disk Information command
using SearchCommand = SMBv1::Command< SearchArgumentType, SearchResultType>;                                                     //!< Search command
using FindCommand = SMBv1::Command< FindArgumentType, FindResultType>;                                                           //!< Find command
using FindUniqueCommand = SMBv1::Command< FindUniqueArgumentType, FindUniqueResultType>;                                         //!< Find unique command
using FindCloseCommand = SMBv1::Command< FindCloseArgumentType, FindCloseResultType>;                                            //!< Find close command
using NtTransactCommand = SMBv1::Command< NtTransactArgumentType, NtTransactResultType>;                                         //!< Transact command
using NtTransactSecondaryCommand = SMBv1::Command< NtTransactSecondaryArgumentType, NtTransactSecondaryResultType>;              //!< Transact 2 command
using NtCreateAndxCommand = SMBv1::Command< NtCreateAndxArgumentType, NtCreateAndxResultType>;                                   //!< Create command
using NtCancelCommand = SMBv1::Command< NtCancelArgumentType, NtCancelResultType>;                                               //!< Cancel command
using NtRenameCommand = SMBv1::Command< NtRenameArgumentType, NtRenameResultType>;                                               //!< Rename command
using OpenPrintFileCommand = SMBv1::Command< OpenPrintFileArgumentType, OpenPrintFileResultType>;                                //!< Open Print File command
using WritePrintFileCommand = SMBv1::Command< WritePrintFileArgumentType, WritePrintFileResultType>;                             //!< Write Print File command
using ClosePrintFileCommand = SMBv1::Command< ClosePrintFileArgumentType, ClosePrintFileResultType>;                             //!< Close Print File command
using GetPrintQueueCommand = SMBv1::Command< GetPrintQueueArgumentType, GetPrintQueueResultType>;                                //!< Get Print Queue command
using ReadBulkCommand = SMBv1::Command< ReadBulkArgumentType, ReadBulkResultType>;                                               //!< Read Bulk command
using WriteBulkCommand = SMBv1::Command< WriteBulkArgumentType, WriteBulkResultType>;                                            //!< Write Bulk command
using WriteBulkDataCommand = SMBv1::Command< WriteBulkDataArgumentType, WriteBulkDataResultType>;                                //!< Write Bulk command
using InvalidCommand = SMBv1::Command< InvalidArgumentType, InvalidResultType>;                                                  //!< Invalid command
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
