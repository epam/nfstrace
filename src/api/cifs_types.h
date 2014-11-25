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
namespace SMBv1 {

static const int commandsCount = 255;

using Session = u_int16_t;//!< Session IDentifier

using EchoRequestArgumentType = int;//!< Echo request'a arguments
using EchoRequestResultType = int;//!< Echo request's results

using CloseFileArgumentType = int;//!< Close file command's arguments
using CloseFileResultType = int;//!< Close file command's results

/*! Represents one SMB command
 */
template<
        typename ArgumentType,
        typename ResultType
        >
class Command {
public:
    Session session;//!< session ID
    ArgumentType parg;//!< Arguments of specified command
    ResultType pres;//!< Results of specified command
};

using EchoRequestCommand = Command<EchoRequestArgumentType, EchoRequestResultType>;//!< Echo request command
using CloseFileCommand = Command<CloseFileArgumentType, CloseFileResultType>;//!< Close file command


}

/*! SMB 2 version
 */
namespace SMBv2 {

enum class CommandType {

};

/*! Represents one SMB command
 */
class Command {
public:
    CommandType cmd;
};

}

}
}
#endif // CIFS_TYPES_H
