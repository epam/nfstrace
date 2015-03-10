//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Helpers for parsing CIFS structures.
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
#include <arpa/inet.h>
#include <assert.h>

#include "protocols/cifs2/cifs2.h"
#include "protocols/cifs/cifs.h"
#include "api/cifs_pc_to_net.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::CIFSv2;

# if NFSTRACE_BYTE_ORDER == NFSTRACE_BIG_ENDIAN

inline uint64_t ntohll(uint64_t input)
{
    // Network byte order == Big Endian
    return input;
}

# else
#  if NFSTRACE_BYTE_ORDER == NFSTRACE_LITTLE_ENDIAN

inline uint64_t ntohll(uint64_t input)
{
    return be64toh(input);
}
#  endif
# endif

union SMBCode
{
    uint8_t codes[4];
    uint32_t code;
};

static inline uint32_t get_code()
{
    SMBCode code;

    code.codes[0] = static_cast<uint8_t>(NST::protocols::CIFSv1::ProtocolCodes::SMB2);
    code.codes[1] = 'S';
    code.codes[2] = 'M';
    code.codes[3] = 'B';

    return code.code;
}

const NST::protocols::CIFSv2::MessageHeader* NST::protocols::CIFSv2::get_header(const uint8_t* data)
{
    static uint32_t code = get_code ();

    const MessageHeader* header (reinterpret_cast<const MessageHeader*>(data));
    if (header->head_code == code)
    {
        return header;
    }
    return nullptr;
}

bool MessageHeader::isFlag(const Flags flag) const
{
    return static_cast<uint32_t>(flag) & flags;
}

void NST::protocols::CIFSv2::parseGuid(uint8_t* pGuid)
{
    // Bytes:   4          2      2      2      6
    //          f193fb68 - 13b3 - 409f - 9f44 - 87d98987e0b7
    SMBv2::Guid *p = reinterpret_cast<SMBv2::Guid*>(pGuid);
    p->Data1 = le32toh(p->Data1);
    p->Data2 = le16toh(p->Data2);
    p->Data3 = le16toh(p->Data3);
}

void NST::protocols::CIFSv2::parse(SMBv2::ErrResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::NegotiateRequest*& p)
{
    parseGuid(p->clientGUID);
}
void NST::protocols::CIFSv2::parse(SMBv2::NegotiateResponse*& p)
{
    parseGuid(p->serverGUID);
}
void NST::protocols::CIFSv2::parse(SMBv2::SessionSetupRequest*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::SessionSetupResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::LogOffRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::LogOffResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::TreeConnectRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::TreeConnectResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::TreeDisconnectRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::TreeDisconnectResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::CreateRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::CreateResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::CloseRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::CloseResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::EchoRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::EchoResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::QueryInfoRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::QueryInfoResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::QueryDirRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::QueryDirResponse*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::FlushRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::FlushResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::ReadRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::ReadResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::Lock*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::WriteRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::WriteResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::LockRequest*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::LockResponse*&) { }
void NST::protocols::CIFSv2::parse(SMBv2::ChangeNotifyRequest*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::FileNotifyInformation*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::ChangeNotifyResponse*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::OplockAcknowledgment*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::OplockResponse*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::IoCtlRequest*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::IoCtlResponse*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::SetInfoRequest*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::SetInfoResponse*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::CancelResponce*&){ }
void NST::protocols::CIFSv2::parse(SMBv2::CancelRequest*&){ }


// TODO: This implementation currently copy of
// epm-nfs/analyzers/src/cifs/cifs2_commands.cpp
// const std::string NST::breakdown::SMBv2Commands::command_name(int cmd_code)
// Futre fix: We need to merege these enums
const char* NST::protocols::CIFSv2::print_cifs2_procedures(Commands cmd)
{
    assert(cmd < Commands::CMD_COUNT);

    static const char* const commandNames[] =
    {
        "NEGOTIATE",        "SESSION SETUP",    "LOGOFF",           "TREE CONNECT",
        "TREE DISCONNECT",  "CREATE",           "CLOSE",            "FLUSH",
        "READ",             "WRITE",            "LOCK",             "IOCTL",
        "CANCEL",           "ECHO",             "QUERY DIRECTORY",  "CHANGE NOTIFY",
        "QUERY INFO",       "SET INFO",         "OPLOCK BREAK"
    };

    return commandNames[static_cast<int>(cmd)];
}
