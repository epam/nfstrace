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

template<> void NST::protocols::CIFSv2::parse(SMBv2::ErrResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::NegotiateRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::NegotiateResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::SessionSetupRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::SessionSetupResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::LogOffRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::LogOffResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::TreeConnectRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::TreeConnectResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::TreeDisconnectRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::TreeDisconnectResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CreateRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CreateResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CloseRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CloseResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::EchoRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::EchoResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::QueryInfoRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::QueryInfoResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::QueryDirRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::QueryDirResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::FlushRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::FlushResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::ReadRequest& param)
{
    param.structureSize         = ntohs(param.structureSize);
    param.length                = ntohl(param.length);
    param.offset                = ntohll(param.offset);
    param.persistentFileId      = ntohll(param.persistentFileId);
    param.volatileFileId        = ntohll(param.volatileFileId);
    param.minimumCount          = ntohl(param.minimumCount);
    param.RemainingBytes        = ntohl(param.RemainingBytes);
    param.ReadChannelInfoOffset = ntohs(param.ReadChannelInfoOffset);
    param.ReadChannelInfoLength = ntohs(param.ReadChannelInfoLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::ReadResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.DataLength    = ntohl(param.DataLength);
    param.DataRemaining = ntohl(param.DataRemaining);
    // param.Reserved2 is reserved, do not convert it
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::WriteRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::WriteResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::LockRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::LockResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CancelRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::ChangeNotifyRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::ChangeNotifyResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::OplockResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::IoCtlRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::IoCtlResponse& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::SetInfoRequest& )
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::SetInfoResponse& )
{
}
