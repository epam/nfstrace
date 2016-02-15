//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Reduced definitions of RPC headers for fast parsing.
// Copyright (c) 2013 EPAM Systems
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
#ifndef RPC_HEADER_H
#define RPC_HEADER_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <arpa/inet.h> // for ntohl()

#include "api/rpc_types.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace rpc
{
using namespace NST::API;

struct MessageHeader
{
    inline uint32_t xid() const { return ntohl(m_xid); }
    inline MsgType  type() const { return MsgType(ntohl(m_type)); }
private:
    MessageHeader() = delete;

    uint32_t m_xid;
    uint32_t m_type;
};

struct CallHeader : public MessageHeader
{
    inline uint32_t rpcvers() const { return ntohl(m_rpcvers); }
    inline uint32_t prog() const { return ntohl(m_prog); }
    inline uint32_t vers() const { return ntohl(m_vers); }
    inline uint32_t proc() const { return ntohl(m_proc); }
    // OpaqueAuth cred - skipped
    // OpaqueAuth verf - skipped
private:
    CallHeader() = delete;

    uint32_t m_rpcvers; // must be equal to two (2)
    uint32_t m_prog;
    uint32_t m_vers;
    uint32_t m_proc;
};

struct ReplyHeader : public MessageHeader
{
    inline ReplyStat stat() const { return ReplyStat(ntohl(m_stat)); }
    // accepted_reply areply - skipped
    // rejected_reply rreply - skipped
private:
    ReplyHeader() = delete;

    uint32_t m_stat;
};

struct RecordMark //  RFC 5531 section 11 Record Marking Standard
{
    inline bool           is_last() const { return ntohl(mark) & 0x80000000; /*1st bit*/ }
    inline uint32_t       fragment_len() const { return ntohl(mark) & 0x7FFFFFFF; /*31 bits*/ }
    inline MessageHeader* fragment() const { return (MessageHeader*)(this + 1); }
private:
    RecordMark() = delete;

    uint32_t mark;
};

class RPCValidator
{
public:
    static inline bool check(const MessageHeader* const msg)
    {
        const MsgType type = msg->type();

        return type == MsgType::CALL ||
               type == MsgType::REPLY;
    }

    static inline bool check(const CallHeader* const call)
    {
        return call->rpcvers() == SUNRPC_MSG_VERSION;
    }

    static inline bool check(const ReplyHeader* const reply)
    {
        const ReplyStat stat = reply->stat();

        return stat == ReplyStat::MSG_ACCEPTED ||
               stat == ReplyStat::MSG_DENIED;
    }

private:
    RPCValidator() = delete;
};

template <
    uint32_t Program, // remote program number
    uint32_t Version, // remote program version number
    uint32_t MinProc, // min remote procedure number
    uint32_t MaxProc  // max remote procedure number
    >
class RPCProgramValidator
{
public:
    static inline bool check(const CallHeader* const call)
    {
        const uint32_t proc = call->proc();

        return proc <= MaxProc &&
               proc >= MinProc &&
               call->prog() == Program &&
               call->vers() == Version;
    }

private:
    RPCProgramValidator() = delete;
};

//This template specialization for remove warning to compare unsigned with zero
template <
    uint32_t Program,
    uint32_t Version,
    uint32_t MaxProc>
class RPCProgramValidator<Program, Version, 0, MaxProc>
{
public:
    static inline bool check(const CallHeader* const call)
    {
        const uint32_t proc = call->proc();

        // do not compare uint32_t with 0 (MinProc)
        return proc <= MaxProc &&
               call->prog() == Program &&
               call->vers() == Version;
    }

private:
    RPCProgramValidator() = delete;
};

} // namespace rpc
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif // RPC_HEADER_H
//------------------------------------------------------------------------------
