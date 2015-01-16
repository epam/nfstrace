//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of filtrated NFSv3 Procedures.
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
#include "analysis/nfs_parser.h"
#include "protocols/nfs/nfs_procedure.h"
#include "protocols/rpc/rpc_header.h"
#include "protocols/xdr/xdr_decoder.h"
#include "utils/log.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::xdr;
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{


bool NFSParser::parse_data(FilteredDataQueue::Ptr& ptr)
{
    using namespace NST::protocols::rpc;

    // TODO: refactor and generalize this code
    if(ptr->dlen < sizeof(MessageHeader))
    {
        return false;
    }
    auto msg = reinterpret_cast<const MessageHeader*>(ptr->data);
    switch(msg->type())
    {
    case MsgType::CALL:
    {
        if(ptr->dlen < sizeof(CallHeader))
        {
            return false;
        }

        auto call = static_cast<const CallHeader*>(msg);

        if(RPCValidator::check(call) && (protocols::NFS4::Validator::check(call) ||
                                         protocols::NFS3::Validator::check(call)))
        {
            Session* session = sessions.get_session(ptr->session, ptr->direction, MsgType::CALL);
            if(session)
            {
                session->save_call_data(call->xid(), std::move(ptr));
            }
            return true;
        }
    }
    break;
    case MsgType::REPLY:
    {
        if(ptr->dlen < sizeof(ReplyHeader))
        {
            return false;
        }
        auto reply = static_cast<const ReplyHeader*>(msg);

        if(!RPCValidator::check(reply))
        {
            return false;
        }

        Session* session = sessions.get_session(ptr->session, ptr->direction, MsgType::REPLY);
        if(session)
        {
            FilteredDataQueue::Ptr&& call_data = session->get_call_data(reply->xid());
            if(call_data)
            {
                analyze_nfs_operation(std::move(call_data), std::move(ptr), session);
            }
            return true;
        }
    }
    }
    return false;
}

void NFSParser::analyze_nfs_operation( FilteredDataQueue::Ptr&& call,
                                             FilteredDataQueue::Ptr&& reply,
                                             Session* session)
{
    using namespace NST::protocols::rpc;
    using namespace NST::protocols::NFS3;
    using namespace NST::protocols::NFS4;

    auto header = reinterpret_cast<const CallHeader*>(call->data);
    const uint32_t procedure {header->proc()};
    const uint32_t version   {header->vers()};
    try
    {
        XDRDecoder c {std::move(call) };
        XDRDecoder r {std::move(reply)};
        const Session* s {session->get_session()};

        switch(version)
        {
        case NFS_V4:
            switch(procedure)
            {
            case ProcEnumNFS4::NFS_NULL:    return analyzers(&IAnalyzer::INFSv4rpcgen::null,        NFSPROC4RPCGEN_NULL         {c,r,s});
            case ProcEnumNFS4::COMPOUND:    return analyzers(&IAnalyzer::INFSv4rpcgen::compound4,   NFSPROC4RPCGEN_COMPOUND     {c,r,s});
            }
        break;
        case NFS_V3:
            switch(procedure)
            {
            case ProcEnumNFS3::NFS_NULL:    return analyzers(&IAnalyzer::INFSv3rpcgen::null,       NFSPROC3RPCGEN_NULL       {c, r, s});
            case ProcEnumNFS3::GETATTR:     return analyzers(&IAnalyzer::INFSv3rpcgen::getattr3,   NFSPROC3RPCGEN_GETATTR    {c, r, s});
            case ProcEnumNFS3::SETATTR:     return analyzers(&IAnalyzer::INFSv3rpcgen::setattr3,   NFSPROC3RPCGEN_SETATTR    {c, r, s});
            case ProcEnumNFS3::LOOKUP:      return analyzers(&IAnalyzer::INFSv3rpcgen::lookup3,    NFSPROC3RPCGEN_LOOKUP     {c, r, s});
            case ProcEnumNFS3::ACCESS:      return analyzers(&IAnalyzer::INFSv3rpcgen::access3,    NFSPROC3RPCGEN_ACCESS     {c, r, s});
            case ProcEnumNFS3::READLINK:    return analyzers(&IAnalyzer::INFSv3rpcgen::readlink3,  NFSPROC3RPCGEN_READLINK   {c, r, s});
            case ProcEnumNFS3::READ:        return analyzers(&IAnalyzer::INFSv3rpcgen::read3,      NFSPROC3RPCGEN_READ       {c, r, s});
            case ProcEnumNFS3::WRITE:       return analyzers(&IAnalyzer::INFSv3rpcgen::write3,     NFSPROC3RPCGEN_WRITE      {c, r, s});
            case ProcEnumNFS3::CREATE:      return analyzers(&IAnalyzer::INFSv3rpcgen::create3,    NFSPROC3RPCGEN_CREATE     {c, r, s});
            case ProcEnumNFS3::MKDIR:       return analyzers(&IAnalyzer::INFSv3rpcgen::mkdir3,     NFSPROC3RPCGEN_MKDIR      {c, r, s});
            case ProcEnumNFS3::SYMLINK:     return analyzers(&IAnalyzer::INFSv3rpcgen::symlink3,   NFSPROC3RPCGEN_SYMLINK    {c, r, s});
            case ProcEnumNFS3::MKNOD:       return analyzers(&IAnalyzer::INFSv3rpcgen::mknod3,     NFSPROC3RPCGEN_MKNOD      {c, r, s});
            case ProcEnumNFS3::REMOVE:      return analyzers(&IAnalyzer::INFSv3rpcgen::remove3,    NFSPROC3RPCGEN_REMOVE     {c, r, s});
            case ProcEnumNFS3::RMDIR:       return analyzers(&IAnalyzer::INFSv3rpcgen::rmdir3,     NFSPROC3RPCGEN_RMDIR      {c, r, s});
            case ProcEnumNFS3::RENAME:      return analyzers(&IAnalyzer::INFSv3rpcgen::rename3,    NFSPROC3RPCGEN_RENAME     {c, r, s});
            case ProcEnumNFS3::LINK:        return analyzers(&IAnalyzer::INFSv3rpcgen::link3,      NFSPROC3RPCGEN_LINK       {c, r, s});
            case ProcEnumNFS3::READDIR:     return analyzers(&IAnalyzer::INFSv3rpcgen::readdir3,   NFSPROC3RPCGEN_READDIR    {c, r, s});
            case ProcEnumNFS3::READDIRPLUS: return analyzers(&IAnalyzer::INFSv3rpcgen::readdirplus3, NFSPROC3RPCGEN_READDIRPLUS{c, r, s});
            case ProcEnumNFS3::FSSTAT:      return analyzers(&IAnalyzer::INFSv3rpcgen::fsstat3,    NFSPROC3RPCGEN_FSSTAT     {c, r, s});
            case ProcEnumNFS3::FSINFO:      return analyzers(&IAnalyzer::INFSv3rpcgen::fsinfo3,    NFSPROC3RPCGEN_FSINFO     {c, r, s});
            case ProcEnumNFS3::PATHCONF:    return analyzers(&IAnalyzer::INFSv3rpcgen::pathconf3,  NFSPROC3RPCGEN_PATHCONF   {c, r, s});
            case ProcEnumNFS3::COMMIT:      return analyzers(&IAnalyzer::INFSv3rpcgen::commit3,    NFSPROC3RPCGEN_COMMIT     {c, r, s});
            }
       break;
       }
    }
    catch(XDRDecoderError& e)
    {
        const char* procedure_name{"Unknown procedure"};
        switch(version)
        {
        case NFS_V4:
            procedure_name = print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(procedure));
        break;
        case NFS_V3:
            procedure_name = print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(procedure));
        break;
        }
        LOG("Some data of NFS operation %s %s(%u) was not parsed: %s", session->str().c_str(), procedure_name, procedure, e.what());
    }
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
