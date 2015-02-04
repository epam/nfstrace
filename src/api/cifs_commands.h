//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Definition of CIFSv1 commands
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
#ifndef _SMBv1_COMMANDS_H
#define _SMBv1_COMMANDS_H
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

struct CreateDirectoryArgumentType{} __attribute__ ((__packed__));                                     //!< CreateDirectory arguments
struct CreateDirectoryResultType{} __attribute__ ((__packed__));                                       //!< CreateDirectory results

struct DeleteDirectoryArgumentType{} __attribute__ ((__packed__));                                     //!< DeleteDirectory arguments
struct DeleteDirectoryResultType{} __attribute__ ((__packed__));                                       //!< DeleteDirectory results

struct OpenArgumentType{} __attribute__ ((__packed__));                                                //!< Open arguments
struct OpenResultType{} __attribute__ ((__packed__));                                                  //!< Open results

struct CreateArgumentType{} __attribute__ ((__packed__));                                              //!< Create arguments
struct CreateResultType{} __attribute__ ((__packed__));                                                //!< Create results

struct CloseArgumentType{} __attribute__ ((__packed__));                                               //!< Close arguments
struct CloseResultType{} __attribute__ ((__packed__));                                                 //!< Close results

struct FlushArgumentType{} __attribute__ ((__packed__));                                               //!< Flush arguments
struct FlushResultType{} __attribute__ ((__packed__));                                                 //!< Flush results

struct DeleteArgumentType{} __attribute__ ((__packed__));                                              //!< Delete arguments
struct DeleteResultType{} __attribute__ ((__packed__));                                                //!< Delete results

struct RenameArgumentType{} __attribute__ ((__packed__));                                              //!< Rename arguments
struct RenameResultType{} __attribute__ ((__packed__));                                                //!< Rename results

struct QueryInformationArgumentType{} __attribute__ ((__packed__));                                    //!< QueryInformation arguments
struct QueryInformationResultType{} __attribute__ ((__packed__));                                      //!< QueryInformation results

struct SetInformationArgumentType{} __attribute__ ((__packed__));                                      //!< Set Information arguments
struct SetInformationResultType{} __attribute__ ((__packed__));                                        //!< Set Information results

struct ReadArgumentType{} __attribute__ ((__packed__));                                                //!< Read arguments
struct ReadResultType{} __attribute__ ((__packed__));                                                  //!< Read results

struct WriteArgumentType{} __attribute__ ((__packed__));                                               //!< Write arguments
struct WriteResultType{} __attribute__ ((__packed__));                                                 //!< Write results

struct LockByteRangeArgumentType{} __attribute__ ((__packed__));                                       //!< Lock Byte Range arguments
struct LockByteRangeResultType{} __attribute__ ((__packed__));                                         //!< Lock Byte Range results

struct UnlockByteRangeArgumentType{} __attribute__ ((__packed__));                                     //!< UnLock Byte Range arguments
struct UnlockByteRangeResultType{} __attribute__ ((__packed__));                                       //!< UnLock Byte Range results

struct CreateTemporaryArgumentType{} __attribute__ ((__packed__));                                     //!< Create Temporary file arguments
struct CreateTemporaryResultType{} __attribute__ ((__packed__));                                       //!< Create Temporary file results

struct CreateNewArgumentType{} __attribute__ ((__packed__));                                           //!< Create a new file arguments
struct CreateNewResultType{} __attribute__ ((__packed__));                                             //!< Create a new file results

struct CheckDirectoryArgumentType{} __attribute__ ((__packed__));                                      //!< CheckDirectory arguments
struct CheckDirectoryResultType{} __attribute__ ((__packed__));                                        //!< CheckDirectory results

struct ProcessExitArgumentType{} __attribute__ ((__packed__));                                         //!< Process Exit arguments
struct ProcessExitResultType{} __attribute__ ((__packed__));                                           //!< Process Exit results

struct SeekArgumentType{} __attribute__ ((__packed__));                                                //!< Seek arguments
struct SeekResultType{} __attribute__ ((__packed__));                                                  //!< Seek results

struct LockAndReadArgumentType{} __attribute__ ((__packed__));                                         //!< Lock And Read arguments
struct LockAndReadResultType{} __attribute__ ((__packed__));                                           //!< Lock And Read results

struct WriteAndUnlockArgumentType{} __attribute__ ((__packed__));                                      //!< Write And Unlock arguments
struct WriteAndUnlockResultType{} __attribute__ ((__packed__));                                        //!< Write And Unlock results

struct ReadRawArgumentType{} __attribute__ ((__packed__));                                             //!< Read raw command's arguments
struct ReadRawResultType{} __attribute__ ((__packed__));                                               //!< Read raw command's results

struct ReadMpxArgumentType{} __attribute__ ((__packed__));                                             //!< Read Mpx command's arguments
struct ReadMpxResultType{} __attribute__ ((__packed__));                                               //!< Read Mpx command's results

struct ReadMpxSecondaryArgumentType{} __attribute__ ((__packed__));                                    //!< Read Read Mpx Secondary command's arguments
struct ReadMpxSecondaryResultType{} __attribute__ ((__packed__));                                      //!< Read Read Mpx Secondary command's results

struct WriteRawArgumentType{} __attribute__ ((__packed__));                                            //!< Write Raw command's arguments
struct WriteRawResultType{} __attribute__ ((__packed__));                                              //!< Write Raw command's results

struct WriteMpxArgumentType{} __attribute__ ((__packed__));                                            //!< Write Mpx command's arguments
struct WriteMpxResultType{} __attribute__ ((__packed__));                                              //!< Write Mpx command's results

struct WriteMpxSecondaryArgumentType{} __attribute__ ((__packed__));                                   //!< Write Mpx 2 command's arguments
struct WriteMpxSecondaryResultType{} __attribute__ ((__packed__));                                     //!< Write Mpx 2 command's results

struct WriteCompleteArgumentType{} __attribute__ ((__packed__));                                       //!< Write Complete command's arguments
struct WriteCompleteResultType{} __attribute__ ((__packed__));                                         //!< Write Complete command's results

struct QueryServerArgumentType{} __attribute__ ((__packed__));                                         //!< Query Server (reserved) command's arguments
struct QueryServerResultType{} __attribute__ ((__packed__));                                           //!< Query Server (reserved) command's results

struct SetInformation2ArgumentType{} __attribute__ ((__packed__));                                     //!< Set Information 2 command's arguments
struct SetInformation2ResultType{} __attribute__ ((__packed__));                                       //!< Set Information 2 command's results

struct QueryInformation2ArgumentType{} __attribute__ ((__packed__));                                   //!< Query Information 2 command's arguments
struct QueryInformation2ResultType{} __attribute__ ((__packed__));                                     //!< Query Information 2 command's results

struct LockingAndxArgumentType{} __attribute__ ((__packed__));                                         //!< Lock some bytes of the file command's arguments
struct LockingAndxResultType{} __attribute__ ((__packed__));                                           //!< Lock some bytes of the file command's results

struct TransactionArgumentType{} __attribute__ ((__packed__));                                         //!< Transaction command's arguments
struct TransactionResultType{} __attribute__ ((__packed__));                                           //!< Transaction command's results

struct TransactionSecondaryArgumentType{} __attribute__ ((__packed__));                                //!< Transaction 2 command's arguments
struct TransactionSecondaryResultType{} __attribute__ ((__packed__));                                  //!< Transaction 2 command's results

struct IoctlArgumentType{} __attribute__ ((__packed__));                                               //!< Ioctl command's arguments
struct IoctlResultType{} __attribute__ ((__packed__));                                                 //!< Ioctl command's results

struct IoctlSecondaryArgumentType{} __attribute__ ((__packed__));                                      //!< Ioctl 2 command's arguments
struct IoctlSecondaryResultType{} __attribute__ ((__packed__));                                        //!< Ioctl 2 command's results

struct CopyArgumentType{} __attribute__ ((__packed__));                                                //!< Copy command's arguments
struct CopyResultType{} __attribute__ ((__packed__));                                                  //!< Copy command's results

struct MoveArgumentType{} __attribute__ ((__packed__));                                                //!< Move command's arguments
struct MoveResultType{} __attribute__ ((__packed__));                                                  //!< Move command's results

struct EchoArgumentType{} __attribute__ ((__packed__));                                                //!< Echo command's arguments
struct EchoResultType{} __attribute__ ((__packed__));                                                  //!< Echo command's results

struct WriteAndCloseArgumentType{} __attribute__ ((__packed__));                                       //!< Write And Close command's arguments
struct WriteAndCloseResultType{} __attribute__ ((__packed__));                                         //!< Write And Close command's results

struct OpenAndxArgumentType{} __attribute__ ((__packed__));                                            //!< Open 2 command's arguments
struct OpenAndxResultType{} __attribute__ ((__packed__));                                              //!< Open 2 command's results

struct ReadAndxArgumentType{} __attribute__ ((__packed__));                                            //!< Read 2 command's arguments
struct ReadAndxResultType{} __attribute__ ((__packed__));                                              //!< Read 2 command's results

struct WriteAndxArgumentType{} __attribute__ ((__packed__));                                           //!< Write 2 command's arguments
struct WriteAndxResultType{} __attribute__ ((__packed__));                                             //!< Write 2 command's results

struct NewFileSizeArgumentType{} __attribute__ ((__packed__));                                         //!< New File Size command's arguments
struct NewFileSizeResultType{} __attribute__ ((__packed__));                                           //!< New File Size command's results

struct CloseAndTreeDiscArgumentType{} __attribute__ ((__packed__));                                    //!< Reserved command's arguments
struct CloseAndTreeDiscResultType{} __attribute__ ((__packed__));                                      //!< Reserved command's results

struct Transaction2ArgumentType{} __attribute__ ((__packed__));                                        //!< Transaction 2 command's arguments
struct Transaction2ResultType{} __attribute__ ((__packed__));                                          //!< Transaction 2 command's results

struct Transaction2SecondaryArgumentType{} __attribute__ ((__packed__));                               //!< Transaction 3 command's arguments
struct Transaction2SecondaryResultType{} __attribute__ ((__packed__));                                 //!< Transaction 3 command's results

struct FindClose2ArgumentType{} __attribute__ ((__packed__));                                          //!< Search handle close command's arguments
struct FindClose2ResultType{} __attribute__ ((__packed__));                                            //!< Search handle close command's results

struct FindNotifyCloseArgumentType{} __attribute__ ((__packed__));                                     //!< Search handle close command's arguments
struct FindNotifyCloseResultType{} __attribute__ ((__packed__));                                       //!< Search handle close command's results

struct TreeConnectArgumentType{} __attribute__ ((__packed__));                                         //!< establish a client connection to a server share command's arguments
struct TreeConnectResultType{} __attribute__ ((__packed__));                                           //!< establish a client connection to a server share command's results

struct TreeDisconnectArgumentType{} __attribute__ ((__packed__));                                      //!< Disconnect command's arguments
struct TreeDisconnectResultType{} __attribute__ ((__packed__));                                        //!< Disconnect command's results

struct NegotiateArgumentType{} __attribute__ ((__packed__));                                           //!< Negotiate command's arguments
struct NegotiateResultType{} __attribute__ ((__packed__));                                             //!< Negotiate command's results

struct SessionSetupAndxArgumentType{} __attribute__ ((__packed__));                                    //!< Session setup command's arguments
struct SessionSetupAndxResultType{} __attribute__ ((__packed__));                                      //!< Session setup command's results

struct LogoffAndxArgumentType{} __attribute__ ((__packed__));                                          //!< Log off command's arguments
struct LogoffAndxResultType{} __attribute__ ((__packed__));                                            //!< Log off command's results

struct TreeConnectAndxArgumentType{} __attribute__ ((__packed__));                                     //!< Tree Connect command's arguments
struct TreeConnectAndxResultType{} __attribute__ ((__packed__));                                       //!< Tree Connect command's results

struct SecurityPackageAndxArgumentType{} __attribute__ ((__packed__));                                 //!< Security Package command's arguments
struct SecurityPackageAndxResultType{} __attribute__ ((__packed__));                                   //!< Security Package command's results

struct QueryInformationDiskArgumentType{} __attribute__ ((__packed__));                                //!< Query Disk Information command's arguments
struct QueryInformationDiskResultType{} __attribute__ ((__packed__));                                  //!< Query Disk Information command's results

struct SearchArgumentType{} __attribute__ ((__packed__));                                              //!< Search command's arguments
struct SearchResultType{} __attribute__ ((__packed__));                                                //!< Search command's results

struct FindArgumentType{} __attribute__ ((__packed__));                                                //!< Find command's arguments
struct FindResultType{} __attribute__ ((__packed__));                                                  //!< Find command's results

struct FindUniqueArgumentType{} __attribute__ ((__packed__));                                          //!< Find unique command's arguments
struct FindUniqueResultType{} __attribute__ ((__packed__));                                            //!< Find unique command's results

struct FindCloseArgumentType{} __attribute__ ((__packed__));                                           //!< Find close command's arguments
struct FindCloseResultType{} __attribute__ ((__packed__));                                             //!< Find close command's results

struct NtTransactArgumentType{} __attribute__ ((__packed__));                                          //!< Transact command's arguments
struct NtTransactResultType{} __attribute__ ((__packed__));                                            //!< Transact command's results

struct NtTransactSecondaryArgumentType{} __attribute__ ((__packed__));                                 //!< Transact 2 command's arguments
struct NtTransactSecondaryResultType{} __attribute__ ((__packed__));                                   //!< Transact 2 command's results

struct NtCreateAndxArgumentType{} __attribute__ ((__packed__));                                        //!< Create command's arguments
struct NtCreateAndxResultType{} __attribute__ ((__packed__));                                          //!< Create command's results

struct NtCancelArgumentType{} __attribute__ ((__packed__));                                            //!< Cancel command's arguments
struct NtCancelResultType{} __attribute__ ((__packed__));                                              //!< Cancel command's results

struct NtRenameArgumentType{} __attribute__ ((__packed__));                                            //!< Rename command's arguments
struct NtRenameResultType{} __attribute__ ((__packed__));                                              //!< Rename command's results

struct OpenPrintFileArgumentType{} __attribute__ ((__packed__));                                       //!< Open Print File command's arguments
struct OpenPrintFileResultType{} __attribute__ ((__packed__));                                         //!< Open Print File command's results

struct WritePrintFileArgumentType{} __attribute__ ((__packed__));                                      //!< Write Print File command's arguments
struct WritePrintFileResultType{} __attribute__ ((__packed__));                                        //!< Write Print File command's results

struct ClosePrintFileArgumentType{} __attribute__ ((__packed__));                                      //!< Close Print File command's arguments
struct ClosePrintFileResultType{} __attribute__ ((__packed__));                                        //!< Close Print File command's results

struct GetPrintQueueArgumentType{} __attribute__ ((__packed__));                                       //!< Get Print Queue command's arguments
struct GetPrintQueueResultType{} __attribute__ ((__packed__));                                         //!< Get Print Queue command's results

struct ReadBulkArgumentType{} __attribute__ ((__packed__));                                            //!< Read Bulk command's arguments
struct ReadBulkResultType{} __attribute__ ((__packed__));                                              //!< Read Bulk command's results

struct WriteBulkArgumentType{} __attribute__ ((__packed__));                                           //!< Write Bulk command's arguments
struct WriteBulkResultType{} __attribute__ ((__packed__));                                             //!< Write Bulk command's results

struct WriteBulkDataArgumentType{} __attribute__ ((__packed__));                                       //!< Write Bulk command's arguments
struct WriteBulkDataResultType{} __attribute__ ((__packed__));                                         //!< Write Bulk command's results

struct InvalidArgumentType{} __attribute__ ((__packed__));                                             //!< Invalid command's arguments
struct InvalidResultType{} __attribute__ ((__packed__));                                               //!< Invalid command's results

struct NoAndxCmdArgumentType{} __attribute__ ((__packed__));                                           //!< No command's arguments
struct NoAndxCmdResultType{} __attribute__ ((__packed__));                                             //!< No command's results

} // namespace SMBv1
} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//_SMBv1_COMMANDS_H
//------------------------------------------------------------------------------
