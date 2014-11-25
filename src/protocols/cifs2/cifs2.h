//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Helpers for parsing CIFS v2 structures.
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
#ifndef CIFSv2_HEADER_H
#define CIFSv2_HEADER_H
//------------------------------------------------------------------------------
#include <cstdint>

#include "protocols/cifs/cifs.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace CIFSv2
{

/*! CIFS v2 commands
 */
enum class Commands : uint16_t {
    NEGOTIATE         = 0x0000,
    SESSION_SETUP     = 0x0001,
    LOGOFF            = 0x0002,
    TREE_CONNECT      = 0x0003,
    TREE_DISCONNECT   = 0x0004,
    CREATE            = 0x0005,
    CLOSE             = 0x0006,
    FLUSH             = 0x0007,
    READ              = 0x0008,
    WRITE             = 0x0009,
    LOCK              = 0x000A,
    IOCTL             = 0x000B,
    CANCEL            = 0x000C,
    ECHO              = 0x000D,
    QUERY_DIRECTORY   = 0x000E,
    CHANGE_NOTIFY     = 0x000F,
    QUERY_INFO        = 0x0010,
    SET_INFO          = 0x0011,
    OPLOCK_BREAK      = 0x0012
};

/*! \class Raw CIFS v2 message header
 */
struct MessageHeader {
    CIFS::MessageHeaderHead head;//!< Same head as CIFS v1

    int16_t StructureSize;//!< In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. The sender MUST set this to 0, and the receiver MUST ignore it. In all other dialects, this field indicates the number of credits that this request consumes.
    int16_t CreditCharge;//!< In a request, this field is interpreted in different ways depending on the SMB2 dialect. In the SMB 3.x dialect family, this field is interpreted as the ChannelSequence field followed by the Reserved field in a request.

    int32_t status;//!< Used to communicate error messages from the server to the client.

    Commands cmd_code;//!< Code of SMB command
    int16_t Credit;//!< This MUST be set to 64, which is the size, in bytes, of the SMB2 header structure.

    int32_t flags;//!< 1-bit flags describing various features in effect for the message.

    int32_t nextCommand;//!< For a compounded request, this field MUST be set to the offset, in bytes, from the beginning of this SMB2 header to the start of the subsequent 8-byte aligned SMB2 header. If this is not a compounded request, or this is the last header in a compounded request, this value MUST be 0.
    int64_t messageId;//!< A value that identifies a message request and response uniquely across all messages that are sent on the same SMB 2 Protocol transport connection.
    int32_t _;//!< The client SHOULD<3> set this field to 0. The server MAY<4> ignore this field on receipt.
    int32_t TreeId;//!< Uniquely identifies the tree connect for the command. This MUST be 0 for the SMB2 TREE_CONNECT Request. The TreeId can be any unsigned 32-bit integer that is received from a previous SMB2 TREE_CONNECT Response. The following SMB 2 Protocol commands do not require the TreeId to be set to a nonzero value received from a previous SMB2 TREE_CONNECT Response.
    /*!
    TreeId SHOULD be set to 0 for the following commands:
    SMB2 NEGOTIATE Request
    SMB2 NEGOTIATE Response
    SMB2 SESSION_SETUP Request
    SMB2 SESSION_SETUP Response
    SMB2 LOGOFF Request
    SMB2 LOGOFF Response
    SMB2 ECHO Request
    SMB2 ECHO Response
    SMB2 CANCEL Request
    */
    int64_t SessionId;//!< Uniquely identifies the established session for the command
    int32_t Signature[4];//!< he 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the Flags field of the SMB2 header. If the message is not signed, this field MUST be 0.
} __attribute__ ((__packed__));

/*! Check is data valid CIFS message's header and return header or nullptr
 * \param data - raw packet data
 * \return pointer to input data which is casted to header structure or nullptr (if it is not valid header)
 */
const MessageHeader *get_header(const uint8_t *data);

/*! Constructs new command for API from raw message
 * \param header - message header
 * \return Command structure
 */
template <typename Cmd>
inline const Cmd command(const MessageHeader *header)
{
    Cmd cmd;
    cmd.session = header->SessionId;//FIXME: size of var
    return cmd;
}

} // CIFSv2

} // protocols
} // NST
//------------------------------------------------------------------------------
#endif // CIFSv2_HEADER_H
//------------------------------------------------------------------------------
