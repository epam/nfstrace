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
#include "analysis/nfs_parser_thread.h"
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

NFSParserThread::NFSParserThread(FilteredDataQueue& q, Analyzers& a, RunningStatus& s)
: status   (s)
, analyzers(a)
, queue    (q)
, running  {ATOMIC_FLAG_INIT} // false
{
}

NFSParserThread::~NFSParserThread()
{
    if (parsing.joinable()) stop();
}

void NFSParserThread::start()
{
    if(running.test_and_set()) return;
    parsing = std::thread(&NFSParserThread::thread, this);
}

void NFSParserThread::stop()
{
    running.clear();
    parsing.join();
}

inline void NFSParserThread::thread()
{
    try
    {
        while(running.test_and_set())
        {
            // process all available items from queue
            process_queue();

            // then sleep this thread
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        process_queue(); // flush data from queue
    }
    catch(...)
    {
        status.push_current_exception();
    }
}

inline void NFSParserThread::process_queue()
{
    while(true)
    {
        // take all items from the queue
        FilteredDataQueue::List list{queue};
        if(!list)
        {
            return; // list from queue is empty, break infinity loop
        }

        do
        {
            parse_data(list.get_current());
        }
        while(list);
    }
}

void NFSParserThread::parse_data(FilteredDataQueue::Ptr&& ptr)
{
    using namespace NST::protocols::rpc;

    // TODO: refactor and generalize this code
    if(ptr->dlen < sizeof(MessageHeader)) return;
    auto msg = reinterpret_cast<const MessageHeader*>(ptr->data);
    switch(msg->type())
    {
    case MsgType::CALL:
    {
        if(ptr->dlen < sizeof(CallHeader)) return;
        auto call = static_cast<const CallHeader*>(msg);

        if(RPCValidator::check(call) && (protocols::NFS4::Validator::check(call) ||
                                         protocols::NFS3::Validator::check(call)))
        {
            RPCSession* session = sessions.get_session(ptr->session, ptr->direction, MsgType::CALL);
            if(session)
            {
                session->save_nfs_call_data(call->xid(), std::move(ptr));
            }
        }
    }
    break;
    case MsgType::REPLY:
    {
        if(ptr->dlen < sizeof(ReplyHeader)) return;
        auto reply = static_cast<const ReplyHeader*>(msg);

        if(!RPCValidator::check(reply)) return;

        RPCSession* session = sessions.get_session(ptr->session, ptr->direction, MsgType::REPLY);
        if(session)
        {
            FilteredDataQueue::Ptr&& call_data = session->get_nfs_call_data(reply->xid());
            if(call_data)
            {
                analyze_nfs_procedure(std::move(call_data), std::move(ptr), session);
            }
        }
    }
    break;
    }
}

// ----------------------------------------------------------------------------
// Forward declarations of internal functions used inside analyze_nfs_procedure
// They're supposed to be used inside analyze_nfs_procedure only
// ----------------------------------------------------------------------------

static uint32_t get_nfs4_compound_minor_version(const std::uint8_t* rpc_nfs4_call);

using NFS40CompoundType = NST::protocols::NFS4::NFSPROC4RPCGEN_COMPOUND;
using NFS41CompoundType = NST::protocols::NFS41::NFSPROC41RPCGEN_COMPOUND;

template
<
    typename ArgOpType,
    typename ResOpType,
    typename NFS4CompoundType
>
void analyze_nfs4_operations(Analyzers& analyzers, NFS4CompoundType& nfs4_compound_procedure);

inline void analyze_nfs40_operations(Analyzers& analyzers, NFS40CompoundType& nfs40_compound_procedure)
{
    analyze_nfs4_operations<NST::API::NFS4::nfs_argop4,
                            NST::API::NFS4::nfs_resop4,
                            NFS40CompoundType>(analyzers, nfs40_compound_procedure);
}

inline void analyze_nfs41_operations(Analyzers& analyzers, NFS41CompoundType& nfs41_compound_procedure)
{
    analyze_nfs4_operations<NST::API::NFS41::nfs_argop4,
                            NST::API::NFS41::nfs_resop4,
                            NFS41CompoundType>(analyzers, nfs41_compound_procedure);
}

void nfs4_ops_switch(Analyzers& analyzers,
                     const RPCProcedure* rpc_procedure,
                     const NST::API::NFS4::nfs_argop4* arg,
                     const NST::API::NFS4::nfs_resop4* res);

void nfs4_ops_switch(Analyzers& analyzers,
                     const RPCProcedure* rpc_procedure,
                     const NST::API::NFS41::nfs_argop4* arg,
                     const NST::API::NFS41::nfs_resop4* res);

// ----------------------------------------------------------------------------

void NFSParserThread::analyze_nfs_procedure( FilteredDataQueue::Ptr&& call,
                                             FilteredDataQueue::Ptr&& reply,
                                             RPCSession* session)
{
    using namespace NST::protocols::rpc;
    using namespace NST::protocols::NFS3;
    using namespace NST::protocols::NFS4;
    using namespace NST::protocols::NFS41;

    auto header = reinterpret_cast<const CallHeader*>(call->data);
    const uint32_t procedure     {header->proc()};
    const uint32_t major_version {header->vers()};
    uint32_t minor_version {0};

    if(major_version == NFS_V4 &&
       procedure     == ProcEnumNFS4::COMPOUND)
    {
        minor_version = get_nfs4_compound_minor_version(call->data);
    }

    try
    {
        XDRDecoder c {std::move(call) };
        XDRDecoder r {std::move(reply)};
        const Session* s {session->get_session()};

        switch(major_version)
        {
        case NFS_V4:
            switch(minor_version)
            {
            case NFS_V40:
                switch(procedure)
                {
                case ProcEnumNFS4::NFS_NULL:
                    return analyzers(&IAnalyzer::INFSv4rpcgen::null, NFSPROC4RPCGEN_NULL {c,r,s});
                case ProcEnumNFS4::COMPOUND:
                    {
                    NFSPROC4RPCGEN_COMPOUND compound {c,r,s};
                    analyzers(&IAnalyzer::INFSv4rpcgen::compound4, compound);
                    analyze_nfs40_operations(analyzers, compound);
                    break;
                    }
                }
            break;
            case NFS_V41:
                switch(procedure)
                {
                case ProcEnumNFS41::NFS_NULL: return analyzers(&IAnalyzer::INFSv41rpcgen::null41, NFSPROC41RPCGEN_NULL {c,r,s});
                case ProcEnumNFS41::COMPOUND:
                    {
                    NFSPROC41RPCGEN_COMPOUND compound {c,r,s};
                    analyzers(&IAnalyzer::INFSv41rpcgen::compound41, compound);
                    analyze_nfs41_operations(analyzers, compound);
                    break;
                    }
                }
            break;
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
        switch(major_version)
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

//! Get NFSv4.x minor version
/*! This is a fast method. It doesn't call expensive XDR's mechanisms &
* doesn't create new objects. It simply moves pointer to a proper 
* place.
*
* According to NFSv4.0 & 4.1 RFC's it's possible to determine
* minor version ONLY in call COMPOUND(1) procedure.
* That's why only call can be passed here.
*/
static uint32_t get_nfs4_compound_minor_version(const std::uint8_t* rpc_nfs4_call)
{
    // get initial data
    auto* it = rpc_nfs4_call;

    // move to rpc's credentials length
    it += (sizeof(protocols::rpc::CallHeader) + sizeof(uint32_t));
    size_t rpc_cred_length = ntohl(*(uint32_t*)it);

    // skip credentials & move to rpc's verifier length
    it += (rpc_cred_length * sizeof(uint8_t) + sizeof(uint32_t));
    size_t rpc_verf_length = ntohl(*(uint32_t*)it);

    // skip verifier & move to nfsv4's tag length
    it += (rpc_verf_length * sizeof(uint8_t) + sizeof(uint32_t));
    size_t rpc_tag_length = ntohl(*(uint32_t*)it);

    // skip tag & move to nfsv4's minor version
    it += (rpc_tag_length * sizeof(uint8_t) + 2 * sizeof(uint32_t));

    return ntohl(*(uint32_t*)it);
}

//! Common internal function for parsing NFSv4.x's COMPOUND procedure
//! It's supposed to be used inside analyze_nfs_procedure only
template
<
    typename ArgOpType,       // Type of arguments(call part of nfs's procedure)
    typename ResOpType,       // Type of results(reply part of nfs's procedure)
    typename NFS4CompoundType // Type of NFSv4.x COMPOUND procedure. Can be 4.0 or 4.1
>
void analyze_nfs4_operations(Analyzers& analyzers, NFS4CompoundType& nfs4_compound_procedure)
{
    ArgOpType* arg {nullptr};
    ResOpType* res {nullptr};

    uint32_t arg_ops_count  {0}; // Amount of NFS operations (call part)
    uint32_t res_ops_count  {0}; // Amount of NFS operations (reply part)
    uint32_t total_ops_count{0};

    if(nfs4_compound_procedure.parg) // Checking if COMPOUND procedure has valid arg
    {
        arg_ops_count = nfs4_compound_procedure.parg->argarray.argarray_len;
        arg = nfs4_compound_procedure.parg->argarray.argarray_val;
    }

    if(nfs4_compound_procedure.pres) // Checking if COMPOUND procedure has valid res
    {
        res_ops_count = nfs4_compound_procedure.pres->resarray.resarray_len;
        res = nfs4_compound_procedure.pres->resarray.resarray_val;
    }

    // Determing which part of COMPOUND has the biggest amount of operations.
    if(arg && res)
    {
        total_ops_count = arg_ops_count > res_ops_count ? arg_ops_count : res_ops_count;
    }
    else if(arg)
    {
        total_ops_count = arg_ops_count;
    }
    else if(res)
    {
        total_ops_count = res_ops_count;
    }

    // Traversing through ALL COMPOUND procedure's operations
    for(uint32_t i {0}; i < total_ops_count; i++)
    {
        if((arg && res)&&(arg->argop != res->resop))
        {
            // Passing each operation to analyzers using the helper's function
            nfs4_ops_switch(analyzers, &nfs4_compound_procedure, arg, nullptr);
            nfs4_ops_switch(analyzers, &nfs4_compound_procedure, nullptr, res);
        }
        else
        {
            nfs4_ops_switch(analyzers, &nfs4_compound_procedure, arg, res);
        }

        if(arg && i < (arg_ops_count-1)) arg++; else arg = nullptr;
        if(res && i < (res_ops_count-1)) res++; else res = nullptr;
    }
}

//! Internal function for proper passing NFSv4.0's operations to analyzers
//! It's supposed to be used inside analyze_nfs4_operations only
void nfs4_ops_switch(Analyzers& analyzers,
                     const RPCProcedure* rpc_procedure,
                     const NST::API::NFS4::nfs_argop4* arg,
                     const NST::API::NFS4::nfs_resop4* res)
{
    uint32_t nfs_op_num = arg ? arg->argop : res->resop;
    switch(nfs_op_num)
    {
    case ProcEnumNFS4::ACCESS:
        analyzers(&IAnalyzer::INFSv4rpcgen::access40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opaccess : nullptr,
                  res ? &res->nfs_resop4_u.opaccess : nullptr);
        break;
    case ProcEnumNFS4::CLOSE:
        analyzers(&IAnalyzer::INFSv4rpcgen::close40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opclose : nullptr,
                  res ? &res->nfs_resop4_u.opclose : nullptr);
        break;
    case ProcEnumNFS4::COMMIT:
        analyzers(&IAnalyzer::INFSv4rpcgen::commit40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opcommit : nullptr,
                  res ? &res->nfs_resop4_u.opcommit : nullptr);
        break;
    case ProcEnumNFS4::CREATE:
        analyzers(&IAnalyzer::INFSv4rpcgen::create40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opcreate : nullptr,
                  res ? &res->nfs_resop4_u.opcreate : nullptr);
        break;
    case ProcEnumNFS4::DELEGPURGE:
        analyzers(&IAnalyzer::INFSv4rpcgen::delegpurge40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opdelegpurge : nullptr,
                  res ? &res->nfs_resop4_u.opdelegpurge : nullptr);
        break;
    case ProcEnumNFS4::DELEGRETURN:
        analyzers(&IAnalyzer::INFSv4rpcgen::delegreturn40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opdelegreturn : nullptr,
                  res ? &res->nfs_resop4_u.opdelegreturn : nullptr);
        break;
    case ProcEnumNFS4::GETATTR:
        analyzers(&IAnalyzer::INFSv4rpcgen::getattr40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opgetattr : nullptr,
                  res ? &res->nfs_resop4_u.opgetattr : nullptr);
        break;
    case ProcEnumNFS4::GETFH:
        analyzers(&IAnalyzer::INFSv4rpcgen::getfh40, rpc_procedure,
                  res ? &res->nfs_resop4_u.opgetfh : nullptr);
        break;
    case ProcEnumNFS4::LINK:
        analyzers(&IAnalyzer::INFSv4rpcgen::link40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplink : nullptr,
                  res ? &res->nfs_resop4_u.oplink : nullptr);
        break;
    case ProcEnumNFS4::LOCK:
        analyzers(&IAnalyzer::INFSv4rpcgen::lock40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplock : nullptr,
                  res ? &res->nfs_resop4_u.oplock : nullptr);
        break;
    case ProcEnumNFS4::LOCKT:
        analyzers(&IAnalyzer::INFSv4rpcgen::lockt40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplockt : nullptr,
                  res ? &res->nfs_resop4_u.oplockt : nullptr);
        break;
    case ProcEnumNFS4::LOCKU:
        analyzers(&IAnalyzer::INFSv4rpcgen::locku40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplocku : nullptr,
                  res ? &res->nfs_resop4_u.oplocku : nullptr);
        break;
    case ProcEnumNFS4::LOOKUP:
        analyzers(&IAnalyzer::INFSv4rpcgen::lookup40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplookup : nullptr,
                  res ? &res->nfs_resop4_u.oplookup : nullptr);
        break;
    case ProcEnumNFS4::LOOKUPP:
        analyzers(&IAnalyzer::INFSv4rpcgen::lookupp40, rpc_procedure,
                  res ? &res->nfs_resop4_u.oplookupp : nullptr);
        break;
    case ProcEnumNFS4::NVERIFY:
        analyzers(&IAnalyzer::INFSv4rpcgen::nverify40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opnverify : nullptr,
                  res ? &res->nfs_resop4_u.opnverify : nullptr);
        break;
    case ProcEnumNFS4::OPEN:
        analyzers(&IAnalyzer::INFSv4rpcgen::open40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opopen : nullptr,
                  res ? &res->nfs_resop4_u.opopen : nullptr);
        break;
    case ProcEnumNFS4::OPENATTR:
        analyzers(&IAnalyzer::INFSv4rpcgen::openattr40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opopenattr : nullptr,
                  res ? &res->nfs_resop4_u.opopenattr : nullptr);
        break;
    case ProcEnumNFS4::OPEN_CONFIRM:
        analyzers(&IAnalyzer::INFSv4rpcgen::open_confirm40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opopen_confirm : nullptr,
                  res ? &res->nfs_resop4_u.opopen_confirm : nullptr);
        break;
    case ProcEnumNFS4::OPEN_DOWNGRADE:
        analyzers(&IAnalyzer::INFSv4rpcgen::open_downgrade40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opopen_downgrade : nullptr,
                  res ? &res->nfs_resop4_u.opopen_downgrade : nullptr);
        break;
    case ProcEnumNFS4::PUTFH:
        analyzers(&IAnalyzer::INFSv4rpcgen::putfh40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opputfh : nullptr,
                  res ? &res->nfs_resop4_u.opputfh : nullptr);
        break;
    case ProcEnumNFS4::PUTPUBFH:
        analyzers(&IAnalyzer::INFSv4rpcgen::putpubfh40, rpc_procedure,
                  res ? &res->nfs_resop4_u.opputpubfh : nullptr);
        break;
    case ProcEnumNFS4::PUTROOTFH:
        analyzers(&IAnalyzer::INFSv4rpcgen::putrootfh40, rpc_procedure,
                  res ? &res->nfs_resop4_u.opputrootfh : nullptr);
        break;
    case ProcEnumNFS4::READ:
        analyzers(&IAnalyzer::INFSv4rpcgen::read40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opread : nullptr,
                  res ? &res->nfs_resop4_u.opread : nullptr);
        break;
    case ProcEnumNFS4::READDIR:
        analyzers(&IAnalyzer::INFSv4rpcgen::readdir40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opreaddir : nullptr,
                  res ? &res->nfs_resop4_u.opreaddir : nullptr);
        break;
    case ProcEnumNFS4::READLINK:
        analyzers(&IAnalyzer::INFSv4rpcgen::readlink40, rpc_procedure,
                  res ? &res->nfs_resop4_u.opreadlink : nullptr);
        break;
    case ProcEnumNFS4::REMOVE:
        analyzers(&IAnalyzer::INFSv4rpcgen::remove40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opremove : nullptr,
                  res ? &res->nfs_resop4_u.opremove : nullptr);
        break;
    case ProcEnumNFS4::RENAME:
        analyzers(&IAnalyzer::INFSv4rpcgen::rename40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oprename : nullptr,
                  res ? &res->nfs_resop4_u.oprename : nullptr);
        break;
    case ProcEnumNFS4::RENEW:
        analyzers(&IAnalyzer::INFSv4rpcgen::renew40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oprenew : nullptr,
                  res ? &res->nfs_resop4_u.oprenew : nullptr);
        break;
    case ProcEnumNFS4::RESTOREFH:
        analyzers(&IAnalyzer::INFSv4rpcgen::restorefh40, rpc_procedure,
                  res ? &res->nfs_resop4_u.oprestorefh : nullptr);
        break;
    case ProcEnumNFS4::SAVEFH:
        analyzers(&IAnalyzer::INFSv4rpcgen::savefh40, rpc_procedure,
                  res ? &res->nfs_resop4_u.opsavefh : nullptr);
        break;
    case ProcEnumNFS4::SECINFO:
        analyzers(&IAnalyzer::INFSv4rpcgen::secinfo40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsecinfo : nullptr,
                  res ? &res->nfs_resop4_u.opsecinfo : nullptr);
        break;
    case ProcEnumNFS4::SETATTR:
        analyzers(&IAnalyzer::INFSv4rpcgen::setattr40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsetattr : nullptr,
                  res ? &res->nfs_resop4_u.opsetattr : nullptr);
        break;
    case ProcEnumNFS4::SETCLIENTID:
        analyzers(&IAnalyzer::INFSv4rpcgen::setclientid40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsetclientid : nullptr,
                  res ? &res->nfs_resop4_u.opsetclientid : nullptr);
        break;
    case ProcEnumNFS4::SETCLIENTID_CONFIRM:
        analyzers(&IAnalyzer::INFSv4rpcgen::setclientid_confirm40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsetclientid_confirm : nullptr,
                  res ? &res->nfs_resop4_u.opsetclientid_confirm : nullptr);
        break;
    case ProcEnumNFS4::VERIFY:
        analyzers(&IAnalyzer::INFSv4rpcgen::verify40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opverify : nullptr,
                  res ? &res->nfs_resop4_u.opverify : nullptr);
        break;
    case ProcEnumNFS4::WRITE:
        analyzers(&IAnalyzer::INFSv4rpcgen::write40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opwrite : nullptr,
                  res ? &res->nfs_resop4_u.opwrite : nullptr);
        break;
    case ProcEnumNFS4::RELEASE_LOCKOWNER:
        analyzers(&IAnalyzer::INFSv4rpcgen::release_lockowner40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oprelease_lockowner : nullptr,
                  res ? &res->nfs_resop4_u.oprelease_lockowner : nullptr);
        break;
    case ProcEnumNFS4::GET_DIR_DELEGATION:
        analyzers(&IAnalyzer::INFSv4rpcgen::get_dir_delegation40, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opget_dir_delegation : nullptr,
                  res ? &res->nfs_resop4_u.opget_dir_delegation : nullptr);
        break;
    case ProcEnumNFS4::ILLEGAL:
        analyzers(&IAnalyzer::INFSv4rpcgen::illegal40, rpc_procedure,
                  res ? &res->nfs_resop4_u.opillegal : nullptr);
        break;
    default: break;
    }
}

//! Internal function for proper passing NFSv4.1's operations to analyzers
//! It's supposed to be used inside analyze_nfs4_operations only
void nfs4_ops_switch(Analyzers& analyzers,
                     const RPCProcedure* rpc_procedure,
                     const NST::API::NFS41::nfs_argop4* arg,
                     const NST::API::NFS41::nfs_resop4* res)
{
    uint32_t nfs_op_num = arg ? arg->argop : res->resop;
    switch(nfs_op_num)
    {
    case ProcEnumNFS41::ACCESS:
        analyzers(&IAnalyzer::INFSv41rpcgen::access41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opaccess : nullptr,
                  res ? &res->nfs_resop4_u.opaccess : nullptr);
        break;
    case ProcEnumNFS41::CLOSE:
        analyzers(&IAnalyzer::INFSv41rpcgen::close41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opclose : nullptr,
                  res ? &res->nfs_resop4_u.opclose : nullptr);
        break;
    case ProcEnumNFS41::COMMIT:
        analyzers(&IAnalyzer::INFSv41rpcgen::commit41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opcommit : nullptr,
                  res ? &res->nfs_resop4_u.opcommit : nullptr);
        break;
    case ProcEnumNFS41::CREATE:
        analyzers(&IAnalyzer::INFSv41rpcgen::create41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opcreate : nullptr,
                  res ? &res->nfs_resop4_u.opcreate : nullptr);
        break;
    case ProcEnumNFS41::DELEGPURGE:
        analyzers(&IAnalyzer::INFSv41rpcgen::delegpurge41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opdelegpurge : nullptr,
                  res ? &res->nfs_resop4_u.opdelegpurge : nullptr);
        break;
    case ProcEnumNFS41::DELEGRETURN:
        analyzers(&IAnalyzer::INFSv41rpcgen::delegreturn41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opdelegreturn : nullptr,
                  res ? &res->nfs_resop4_u.opdelegreturn : nullptr);
        break;
    case ProcEnumNFS41::GETATTR:
        analyzers(&IAnalyzer::INFSv41rpcgen::getattr41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opgetattr : nullptr,
                  res ? &res->nfs_resop4_u.opgetattr : nullptr);
        break;
    case ProcEnumNFS41::GETFH:
        analyzers(&IAnalyzer::INFSv41rpcgen::getfh41, rpc_procedure,
                  res ? &res->nfs_resop4_u.opgetfh : nullptr);
        break;
    case ProcEnumNFS41::LINK:
        analyzers(&IAnalyzer::INFSv41rpcgen::link41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplink : nullptr,
                  res ? &res->nfs_resop4_u.oplink : nullptr);
        break;
    case ProcEnumNFS41::LOCK:
        analyzers(&IAnalyzer::INFSv41rpcgen::lock41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplock : nullptr,
                  res ? &res->nfs_resop4_u.oplock : nullptr);
        break;
    case ProcEnumNFS41::LOCKT:
        analyzers(&IAnalyzer::INFSv41rpcgen::lockt41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplockt : nullptr,
                  res ? &res->nfs_resop4_u.oplockt : nullptr);
        break;
    case ProcEnumNFS41::LOCKU:
        analyzers(&IAnalyzer::INFSv41rpcgen::locku41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplocku : nullptr,
                  res ? &res->nfs_resop4_u.oplocku : nullptr);
        break;
    case ProcEnumNFS41::LOOKUP:
        analyzers(&IAnalyzer::INFSv41rpcgen::lookup41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplookup : nullptr,
                  res ? &res->nfs_resop4_u.oplookup : nullptr);
        break;
    case ProcEnumNFS41::LOOKUPP:
        analyzers(&IAnalyzer::INFSv41rpcgen::lookupp41, rpc_procedure,
                  res ? &res->nfs_resop4_u.oplookupp : nullptr);
        break;
    case ProcEnumNFS41::NVERIFY:
        analyzers(&IAnalyzer::INFSv41rpcgen::nverify41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opnverify : nullptr,
                  res ? &res->nfs_resop4_u.opnverify : nullptr);
        break;
    case ProcEnumNFS41::OPEN:
        analyzers(&IAnalyzer::INFSv41rpcgen::open41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opopen : nullptr,
                  res ? &res->nfs_resop4_u.opopen : nullptr);
        break;
    case ProcEnumNFS41::OPENATTR:
        analyzers(&IAnalyzer::INFSv41rpcgen::openattr41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opopenattr : nullptr,
                  res ? &res->nfs_resop4_u.opopenattr : nullptr);
        break;
    case ProcEnumNFS41::OPEN_CONFIRM:
        analyzers(&IAnalyzer::INFSv41rpcgen::open_confirm41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opopen_confirm : nullptr,
                  res ? &res->nfs_resop4_u.opopen_confirm : nullptr);
        break;
    case ProcEnumNFS41::OPEN_DOWNGRADE:
        analyzers(&IAnalyzer::INFSv41rpcgen::open_downgrade41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opopen_downgrade : nullptr,
                  res ? &res->nfs_resop4_u.opopen_downgrade : nullptr);
        break;
    case ProcEnumNFS41::PUTFH:
        analyzers(&IAnalyzer::INFSv41rpcgen::putfh41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opputfh : nullptr,
                  res ? &res->nfs_resop4_u.opputfh : nullptr);
        break;
    case ProcEnumNFS41::PUTPUBFH:
        analyzers(&IAnalyzer::INFSv41rpcgen::putpubfh41, rpc_procedure,
                  res ? &res->nfs_resop4_u.opputpubfh : nullptr);
        break;
    case ProcEnumNFS41::PUTROOTFH:
        analyzers(&IAnalyzer::INFSv41rpcgen::putrootfh41, rpc_procedure,
                  res ? &res->nfs_resop4_u.opputrootfh : nullptr);
        break;
    case ProcEnumNFS41::READ:
        analyzers(&IAnalyzer::INFSv41rpcgen::read41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opread : nullptr,
                  res ? &res->nfs_resop4_u.opread : nullptr);
        break;
    case ProcEnumNFS41::READDIR:
        analyzers(&IAnalyzer::INFSv41rpcgen::readdir41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opreaddir : nullptr,
                  res ? &res->nfs_resop4_u.opreaddir : nullptr);
        break;
    case ProcEnumNFS41::READLINK:
        analyzers(&IAnalyzer::INFSv41rpcgen::readlink41, rpc_procedure,
                  res ? &res->nfs_resop4_u.opreadlink : nullptr);
        break;
    case ProcEnumNFS41::REMOVE:
        analyzers(&IAnalyzer::INFSv41rpcgen::remove41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opremove : nullptr,
                  res ? &res->nfs_resop4_u.opremove : nullptr);
        break;
    case ProcEnumNFS41::RENAME:
        analyzers(&IAnalyzer::INFSv41rpcgen::rename41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oprename : nullptr,
                  res ? &res->nfs_resop4_u.oprename : nullptr);
        break;
    case ProcEnumNFS41::RENEW:
        analyzers(&IAnalyzer::INFSv41rpcgen::renew41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oprenew : nullptr,
                  res ? &res->nfs_resop4_u.oprenew : nullptr);
        break;
    case ProcEnumNFS41::RESTOREFH:
        analyzers(&IAnalyzer::INFSv41rpcgen::restorefh41, rpc_procedure,
                  res ? &res->nfs_resop4_u.oprestorefh : nullptr);
        break;
    case ProcEnumNFS41::SAVEFH:
        analyzers(&IAnalyzer::INFSv41rpcgen::savefh41, rpc_procedure,
                  res ? &res->nfs_resop4_u.opsavefh : nullptr);
        break;
    case ProcEnumNFS41::SECINFO:
        analyzers(&IAnalyzer::INFSv41rpcgen::secinfo41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsecinfo : nullptr,
                  res ? &res->nfs_resop4_u.opsecinfo : nullptr);
        break;
    case ProcEnumNFS41::SETATTR:
        analyzers(&IAnalyzer::INFSv41rpcgen::setattr41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsetattr : nullptr,
                  res ? &res->nfs_resop4_u.opsetattr : nullptr);
        break;
    case ProcEnumNFS41::SETCLIENTID:
        analyzers(&IAnalyzer::INFSv41rpcgen::setclientid41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsetclientid : nullptr,
                  res ? &res->nfs_resop4_u.opsetclientid : nullptr);
        break;
    case ProcEnumNFS41::SETCLIENTID_CONFIRM:
        analyzers(&IAnalyzer::INFSv41rpcgen::setclientid_confirm41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsetclientid_confirm : nullptr,
                  res ? &res->nfs_resop4_u.opsetclientid_confirm : nullptr);
        break;
    case ProcEnumNFS41::VERIFY:
        analyzers(&IAnalyzer::INFSv41rpcgen::verify41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opverify : nullptr,
                  res ? &res->nfs_resop4_u.opverify : nullptr);
        break;
    case ProcEnumNFS41::WRITE:
        analyzers(&IAnalyzer::INFSv41rpcgen::write41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opwrite : nullptr,
                  res ? &res->nfs_resop4_u.opwrite : nullptr);
        break;
    case ProcEnumNFS41::RELEASE_LOCKOWNER:
        analyzers(&IAnalyzer::INFSv41rpcgen::release_lockowner41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oprelease_lockowner : nullptr,
                  res ? &res->nfs_resop4_u.oprelease_lockowner : nullptr);
        break;
    case ProcEnumNFS41::BACKCHANNEL_CTL:
        analyzers(&IAnalyzer::INFSv41rpcgen::backchannel_ctl41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opbackchannel_ctl : nullptr,
                  res ? &res->nfs_resop4_u.opbackchannel_ctl : nullptr);
        break;
    case ProcEnumNFS41::BIND_CONN_TO_SESSION:
        analyzers(&IAnalyzer::INFSv41rpcgen::bind_conn_to_session41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opbind_conn_to_session : nullptr,
                  res ? &res->nfs_resop4_u.opbind_conn_to_session : nullptr);
        break;
    case ProcEnumNFS41::EXCHANGE_ID:
        analyzers(&IAnalyzer::INFSv41rpcgen::exchange_id41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opexchange_id : nullptr,
                  res ? &res->nfs_resop4_u.opexchange_id : nullptr);
        break;
    case ProcEnumNFS41::CREATE_SESSION:
        analyzers(&IAnalyzer::INFSv41rpcgen::create_session41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opcreate_session : nullptr,
                  res ? &res->nfs_resop4_u.opcreate_session : nullptr);
        break;
    case ProcEnumNFS41::DESTROY_SESSION:
        analyzers(&IAnalyzer::INFSv41rpcgen::destroy_session41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opdestroy_session : nullptr,
                  res ? &res->nfs_resop4_u.opdestroy_session : nullptr);
        break;
    case ProcEnumNFS41::FREE_STATEID:
        analyzers(&IAnalyzer::INFSv41rpcgen::free_stateid41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opfree_stateid : nullptr,
                  res ? &res->nfs_resop4_u.opfree_stateid : nullptr);
        break;
    case ProcEnumNFS41::GET_DIR_DELEGATION:
        analyzers(&IAnalyzer::INFSv41rpcgen::get_dir_delegation41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opget_dir_delegation : nullptr,
                  res ? &res->nfs_resop4_u.opget_dir_delegation : nullptr);
        break;
    case ProcEnumNFS41::GETDEVICEINFO:
        analyzers(&IAnalyzer::INFSv41rpcgen::getdeviceinfo41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opgetdeviceinfo : nullptr,
                  res ? &res->nfs_resop4_u.opgetdeviceinfo : nullptr);
        break;
    case ProcEnumNFS41::GETDEVICELIST:
        analyzers(&IAnalyzer::INFSv41rpcgen::getdevicelist41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opgetdevicelist : nullptr,
                  res ? &res->nfs_resop4_u.opgetdevicelist : nullptr);
        break;
    case ProcEnumNFS41::LAYOUTCOMMIT:
        analyzers(&IAnalyzer::INFSv41rpcgen::layoutcommit41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplayoutcommit : nullptr,
                  res ? &res->nfs_resop4_u.oplayoutcommit : nullptr);
        break;
    case ProcEnumNFS41::LAYOUTGET:
        analyzers(&IAnalyzer::INFSv41rpcgen::layoutget41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplayoutget : nullptr,
                  res ? &res->nfs_resop4_u.oplayoutget : nullptr);
        break;
    case ProcEnumNFS41::LAYOUTRETURN:
        analyzers(&IAnalyzer::INFSv41rpcgen::layoutreturn41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.oplayoutreturn : nullptr,
                  res ? &res->nfs_resop4_u.oplayoutreturn : nullptr);
        break;
    case ProcEnumNFS41::SECINFO_NO_NAME:
        analyzers(&IAnalyzer::INFSv41rpcgen::secinfo_no_name41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsecinfo_no_name : nullptr,
                  res ? &res->nfs_resop4_u.opsecinfo_no_name : nullptr);
        break;
    case ProcEnumNFS41::SEQUENCE:
        analyzers(&IAnalyzer::INFSv41rpcgen::sequence41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opsequence : nullptr,
                  res ? &res->nfs_resop4_u.opsequence : nullptr);
        break;
    case ProcEnumNFS41::SET_SSV:
        analyzers(&IAnalyzer::INFSv41rpcgen::set_ssv41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opset_ssv : nullptr,
                  res ? &res->nfs_resop4_u.opset_ssv : nullptr);
        break;
    case ProcEnumNFS41::TEST_STATEID:
        analyzers(&IAnalyzer::INFSv41rpcgen::test_stateid41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.optest_stateid : nullptr,
                  res ? &res->nfs_resop4_u.optest_stateid : nullptr);
        break;
    case ProcEnumNFS41::WANT_DELEGATION:
        analyzers(&IAnalyzer::INFSv41rpcgen::want_delegation41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opwant_delegation : nullptr,
                  res ? &res->nfs_resop4_u.opwant_delegation : nullptr);
        break;
    case ProcEnumNFS41::DESTROY_CLIENTID:
        analyzers(&IAnalyzer::INFSv41rpcgen::destroy_clientid41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opdestroy_clientid : nullptr,
                  res ? &res->nfs_resop4_u.opdestroy_clientid : nullptr);
        break;
    case ProcEnumNFS41::RECLAIM_COMPLETE:
        analyzers(&IAnalyzer::INFSv41rpcgen::reclaim_complete41, rpc_procedure,
                  arg ? &arg->nfs_argop4_u.opreclaim_complete : nullptr,
                  res ? &res->nfs_resop4_u.opreclaim_complete : nullptr);
        break;
    case ProcEnumNFS41::ILLEGAL:
        analyzers(&IAnalyzer::INFSv41rpcgen::illegal41, rpc_procedure,
                  res ? &res->nfs_resop4_u.opillegal : nullptr);
        break;
    default: break;
    }
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
