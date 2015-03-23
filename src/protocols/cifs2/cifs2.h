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
#include "api/cifs_commands.h"
#include "api/cifs2_commands.h"
#include "protocols/cifs/cifs.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace CIFSv2
{

using SMBv2Commands = NST::API::SMBv2::SMBv2Commands;
namespace SMBv2 = NST::API::SMBv2;
// https://msdn.microsoft.com/en-us/library/ff718266.aspx
struct Guid
{
  uint32_t Data1;               // unsigned long  replaced by uint32_t
  uint16_t Data2;               // unsigned short replaced by uint16_t
  uint16_t Data3;               // unsigned short replaced by uint16_t
  uint8_t  Data4[8];            // byte           replaced by uint8_t
}  __attribute__ ((__packed__));

/*! CIFS v2 Flags
 */
enum class Flags : uint32_t
{
    SERVER_TO_REDIR      = API::SMBv2::pc_to_net<uint32_t>(0x00000001), //!< When set, indicates the message is a response, rather than a request. This MUST be set on responses sent from the server to the client and MUST NOT be set on requests sent from the client to the server.
    ASYNC_COMMAND        = API::SMBv2::pc_to_net<uint32_t>(0x00000002), //!< When set, indicates that this is an ASYNC SMB2 header. This flag MUST NOT be set when using the SYNC SMB2 header.
    RELATED_OPERATIONS   = API::SMBv2::pc_to_net<uint32_t>(0x00000004), //!< When set in an SMB2 request, indicates that this request is a related operation in a compounded request chain. The use of this flag in an SMB2 request is as specified in 3.2.4.1.4.
    //!< When set in an SMB2 compound response, indicates that the request corresponding to this response was part of a related operation in a compounded request chain. The use of this flag in an SMB2 response is as specified in 3.3.5.2.7.2.
    SIGNED               = API::SMBv2::pc_to_net<uint32_t>(0x00000008), //!< When set, indicates that this packet has been signed. The use of this flag is as specified in 3.1.5.1.
    DFS_OPERATIONS       = API::SMBv2::pc_to_net<uint32_t>(0x01000000), //!< When set, indicates that this command is a DFS operation. The use of this flag is as specified in 3.3.5.9.
    REPLAY_OPERATION     = API::SMBv2::pc_to_net<uint32_t>(0x02000000)  //!< This flag is only valid for the SMB 3.x dialect family. When set, it indicates that this command is a replay operation. The client MUST ignore this bit on receipt.
};

/*! \class Raw CIFS v2 message header
 */
struct RawMessageHeader
{
    union
    {
        CIFSv1::MessageHeaderHead head;//!< Head of header
        uint32_t head_code;//!< For fast checking
    };

    int16_t StructureSize;//!< In the SMB 2.002 dialect, this field MUST NOT be used and MUST be reserved. The sender MUST set this to 0, and the receiver MUST ignore it. In all other dialects, this field indicates the number of credits that this request consumes.
    int16_t CreditCharge;//!< In a request, this field is interpreted in different ways depending on the SMB2 dialect. In the SMB 3.x dialect family, this field is interpreted as the ChannelSequence field followed by the Reserved field in a request.

    uint32_t status;//!< Used to communicate error messages from the server to the client.

    SMBv2Commands cmd_code;//!< Code of SMB command
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

/*! High level user friendly message structure
 */
struct MessageHeader : public RawMessageHeader
{
    /*! Check flag
     * \param flag - flag to be check
     * \return True, if flag set, and False in other case
     */
    bool isFlag(const Flags flag) const;
};

/*! Check is data valid CIFS message's header and return header or nullptr
 * \param data - raw packet data
 * \return pointer to input data which is casted to header structure or nullptr (if it is not valid header)
 */
const MessageHeader* get_header(const uint8_t* data);

void parseGuid(uint8_t (&guid)[16]);
void parse(SMBv2::ErrResponse*&);
void parse(SMBv2::NegotiateRequest*&);
void parse(SMBv2::NegotiateResponse*&);
void parse(SMBv2::SessionSetupRequest*&);
void parse(SMBv2::SessionSetupResponse*&);
void parse(SMBv2::LogOffRequest*&);
void parse(SMBv2::LogOffResponse*&);
void parse(SMBv2::TreeConnectRequest*&);
void parse(SMBv2::TreeConnectResponse*&);
void parse(SMBv2::TreeDisconnectRequest*&);
void parse(SMBv2::TreeDisconnectResponse*&);
void parse(SMBv2::CreateRequest*&);
void parse(SMBv2::CreateResponse*&);
void parse(SMBv2::CloseRequest*&);
void parse(SMBv2::CloseResponse*&);
void parse(SMBv2::EchoRequest*&);
void parse(SMBv2::EchoResponse*&);
void parse(SMBv2::QueryInfoRequest*&);
void parse(SMBv2::QueryInfoResponse*&);
void parse(SMBv2::QueryDirRequest*&);
void parse(SMBv2::QueryDirResponse*&);
void parse(SMBv2::FlushRequest*&);
void parse(SMBv2::FlushResponse*&);
void parse(SMBv2::ReadRequest*&);
void parse(SMBv2::ReadResponse*&);
void parse(SMBv2::Lock*&);
void parse(SMBv2::WriteRequest*&);
void parse(SMBv2::WriteResponse*&);
void parse(SMBv2::LockRequest*&);
void parse(SMBv2::LockResponse*&);
void parse(SMBv2::ChangeNotifyRequest*&);
void parse(SMBv2::FileNotifyInformation*&);
void parse(SMBv2::ChangeNotifyResponse*&);
void parse(SMBv2::OplockAcknowledgment*&);
void parse(SMBv2::OplockResponse*&);
void parse(SMBv2::IoCtlRequest*&);
void parse(SMBv2::IoCtlResponse*&);
void parse(SMBv2::SetInfoRequest*&);
void parse(SMBv2::SetInfoResponse*&);
void parse(SMBv2::CancelResponce*&);
void parse(SMBv2::CancelRequest*&);

/*! Constructs new command for API from raw message
 * \param request - Call's
 * \param response - Reply's
 * \param session - session
 * \return Command structure
 */
template <typename Cmd, typename Data, typename Session>
inline const Cmd command(Data& request, Data& response, Session* session)
{
    Cmd cmd;
    cmd.session = session;
    // Set time stamps
    cmd.ctimestamp = &request->timestamp;
    cmd.rtimestamp = response ? &response->timestamp : &request->timestamp;

    //
    // Since we have to modify structures before command creation
    // we have to cast raw data to pointer type ( in contrast to const pointer )
    //
    auto req_header = reinterpret_cast<RawMessageHeader*>(request->data);
    auto pargs = reinterpret_cast<typename Cmd::RequestType*>(request->data + sizeof(RawMessageHeader));

    parse(pargs);

    cmd.req_header = req_header;
    if(response)
    {
        cmd.res_header = reinterpret_cast<RawMessageHeader*>(response->data);
        cmd.pres = reinterpret_cast<typename Cmd::ResponseType*>(response->data + sizeof(RawMessageHeader));
    }
    cmd.parg = pargs; 
    return cmd;
}

extern "C"
NST_PUBLIC
const char* print_cifs2_procedures(SMBv2Commands cmd_code);

} // namespace CIFSv2
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//CIFSv2_HEADER_H
//------------------------------------------------------------------------------
