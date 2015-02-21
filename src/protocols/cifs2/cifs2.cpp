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

template<> void NST::protocols::CIFSv2::parse(SMBv2::ErrResponse& param)
{
    param.byteCount = ntohl(param.byteCount);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::NegotiateRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.dialectCount = ntohs(param.dialectCount);
    param.clientStartTime = ntohll(param.clientStartTime);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::NegotiateResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.dialectRevision = ntohs(param.dialectRevision);
    param.maxTransactSize = ntohl(param.maxTransactSize);
    param.maxReadSize = ntohl(param.maxReadSize);
    param.maxWriteSize = ntohl(param.maxWriteSize);
    param.systemTime = ntohll(param.systemTime);
    param.serverStartTime = ntohll(param.serverStartTime);
    param.securityBufferOffset = ntohs(param.securityBufferOffset);
    param.securityBufferLength = ntohs(param.securityBufferLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::SessionSetupRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.Channel = ntohl(param.Channel);
    param.SecurityBufferOffset = ntohs(param.SecurityBufferOffset);
    param.SecurityBufferLength = ntohs(param.SecurityBufferLength);
    param.PreviousSessionId = ntohll(param.PreviousSessionId);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::SessionSetupResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.SecurityBufferOffset = ntohs(param.SecurityBufferOffset);
    param.SecurityBufferLength = ntohs(param.SecurityBufferLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::LogOffRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::LogOffResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::TreeConnectRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.PathOffset = ntohs(param.PathOffset);
    param.PathLength = ntohs(param.PathLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::TreeConnectResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.MaximalAccess = ntohl(param.MaximalAccess);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::TreeDisconnectRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::TreeDisconnectResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CreateRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.SmbCreateFlags = ntohll(param.SmbCreateFlags);
    param.NameOffset = ntohs(param.NameOffset);
    param.NameLength = ntohs(param.NameLength);
    param.CreateContextsOffset = ntohl(param.CreateContextsOffset);
    param.CreateContextsLength = ntohl(param.CreateContextsLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CreateResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.CreationTime = ntohll(param.CreationTime);
    param.LastAccessTime = ntohll(param.LastAccessTime);
    param.LastWriteTime = ntohll(param.LastWriteTime);
    param.ChangeTime = ntohll(param.ChangeTime);
    param.AllocationSize = ntohll(param.AllocationSize);
    param.EndofFile = ntohll(param.EndofFile);
    param.PersistentFileId = ntohll(param.PersistentFileId);
    param.VolatileFileId = ntohll(param.VolatileFileId);
    param.CreateContextsOffset = ntohl(param.CreateContextsOffset);
    param.CreateContextsLength = ntohl(param.CreateContextsLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CloseRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.PersistentFileId = ntohll(param.PersistentFileId);
    param.VolatileFileId = ntohll(param.VolatileFileId);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CloseResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.CreationTime = ntohll(param.CreationTime);
    param.LastAccessTime = ntohll(param.LastAccessTime);
    param.LastWriteTime = ntohll(param.LastWriteTime);
    param.ChangeTime = ntohll(param.ChangeTime);
    param.AllocationSize = ntohll(param.AllocationSize);
    param.EndOfFile = ntohll(param.EndOfFile);
    param.Attributes = ntohl(param.Attributes);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::EchoRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::EchoResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::QueryInfoRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.OutputBufferLength = ntohl(param.OutputBufferLength);
    param.InputBufferOffset = ntohs(param.InputBufferOffset);
    param.InputBufferLength = ntohl(param.InputBufferLength);
    param.PersistentFileId = ntohll(param.PersistentFileId);
    param.VolatileFileId = ntohll(param.VolatileFileId);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::QueryInfoResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.OutputBufferOffset = ntohs(param.OutputBufferOffset);
    param.OutputBufferLength = ntohl(param.OutputBufferLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::QueryDirRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.FileIndex = ntohl(param.FileIndex);
    param.PersistentFileId = ntohll(param.PersistentFileId);
    param.VolatileFileId = ntohll(param.VolatileFileId);
    param.FileNameOffset = ntohs(param.FileNameOffset);
    param.FileNameLength = ntohs(param.FileNameLength);
    param.OutputBufferLength = ntohl(param.OutputBufferLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::QueryDirResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.OutputBufferOffset = ntohs(param.OutputBufferOffset);
    param.OutputBufferLength = ntohl(param.OutputBufferLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::FlushRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.PersistentFileId = ntohll(param.PersistentFileId);
    param.VolatileFileId = ntohll(param.VolatileFileId);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::FlushResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::ReadRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.length = ntohl(param.length);
    param.offset = ntohll(param.offset);
    param.persistentFileId = ntohll(param.persistentFileId);
    param.volatileFileId = ntohll(param.volatileFileId);
    param.minimumCount = ntohl(param.minimumCount);
    param.RemainingBytes = ntohl(param.RemainingBytes);
    param.ReadChannelInfoOffset = ntohs(param.ReadChannelInfoOffset);
    param.ReadChannelInfoLength = ntohs(param.ReadChannelInfoLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::ReadResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.DataLength = ntohl(param.DataLength);
    param.DataRemaining = ntohl(param.DataRemaining);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::WriteRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.dataOffset = ntohs(param.dataOffset);
    param.Length = ntohl(param.Length);
    param.Offset = ntohll(param.Offset);
    param.persistentFileId = ntohll(param.persistentFileId);
    param.volatileFileId = ntohll(param.volatileFileId);
    param.RemainingBytes = ntohl(param.RemainingBytes);
    param.WriteChannelInfoOffset = ntohs(param.WriteChannelInfoOffset);
    param.WriteChannelInfoLength = ntohs(param.WriteChannelInfoLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::WriteResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.Count = ntohl(param.Count);
    param.Remaining = ntohl(param.Remaining);
    param.WriteChannelInfoOffset = ntohs(param.WriteChannelInfoOffset);
    param.WriteChannelInfoLength = ntohs(param.WriteChannelInfoLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::Lock& param)
{
    param.Offset = ntohll(param.Offset);
    param.Length = ntohll(param.Length);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::LockRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.LockCount = ntohs(param.LockCount);
    param.LockSequence = ntohl(param.LockSequence);
    param.persistentFileId = ntohll(param.persistentFileId);
    param.volatileFileId = ntohll(param.volatileFileId);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::LockResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CancelRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::CancelResponce&)
{
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::ChangeNotifyRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.OutputBufferLength = ntohl(param.OutputBufferLength);
    param.persistentFileId = ntohll(param.persistentFileId);
    param.volatileFileId = ntohll(param.volatileFileId);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::FileNotifyInformation& param)
{
    param.NextEntryOffset = ntohl(param.NextEntryOffset);
    param.FileNameLength = ntohl(param.FileNameLength);
    param.FileName[1] = ntohl(param.FileName[1]);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::ChangeNotifyResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.OutputBufferOffset = ntohs(param.OutputBufferOffset);
    param.OutputBufferLength = ntohl(param.OutputBufferLength);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::OplockAcknowledgment& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.persistentFileId = ntohll(param.persistentFileId);
    param.volatileFileId = ntohll(param.volatileFileId);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::OplockResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.persistentFileId = ntohll(param.persistentFileId);
    param.volatileFileId = ntohll(param.volatileFileId);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::IoCtlRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.persistentFileId = ntohll(param.persistentFileId);
    param.volatileFileId = ntohll(param.volatileFileId);
    param.InputOffset = ntohl(param.InputOffset);
    param.InputCount = ntohl(param.InputCount);
    param.MaxInputResponse = ntohl(param.MaxInputResponse);
    param.OutputOffset = ntohl(param.OutputOffset);
    param.OutputCount = ntohl(param.OutputCount);
    param.MaxOutputResponse = ntohl(param.MaxOutputResponse);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::IoCtlResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.persistentFileId = ntohll(param.persistentFileId);
    param.volatileFileId = ntohll(param.volatileFileId);
    param.InputOffset = ntohl(param.InputOffset);
    param.InputCount = ntohl(param.InputCount);
    param.OutputOffset = ntohl(param.OutputOffset);
    param.OutputCount = ntohl(param.OutputCount);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::SetInfoRequest& param)
{
    param.structureSize = ntohs(param.structureSize);
    param.BufferLength = ntohl(param.BufferLength);
    param.BufferOffset = ntohs(param.BufferOffset);
    param.persistentFileId = ntohll(param.persistentFileId);
    param.volatileFileId = ntohll(param.volatileFileId);
}

template<> void NST::protocols::CIFSv2::parse(SMBv2::SetInfoResponse& param)
{
    param.structureSize = ntohs(param.structureSize);
}

// TODO: This implementation currently copy of
// epm-nfs/analyzers/src/cifs/cifs2_commands.cpp
// const std::string NST::breakdown::SMBv2Commands::command_name(int cmd_code)
// Futre fix: We need to merege this enums
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
