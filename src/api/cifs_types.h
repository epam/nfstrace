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


using EchoRequestArgumentType = int;//!< Echo request'a arguments
using EchoRequestResultType = int;//!< Echo request's results
using EchoRequestCommand = Command<EchoRequestArgumentType, EchoRequestResultType>;//!< Echo request command

using CloseFileArgumentType = int;//!< Close file command's arguments
using CloseFileResultType = int;//!< Close file command's results
using CloseFileCommand = Command<CloseFileArgumentType, CloseFileResultType>;//!< Close file command

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
