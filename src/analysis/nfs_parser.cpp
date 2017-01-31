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
                analyze_nfs_procedure(std::move(call_data), std::move(ptr), session);
            }
            return true;
        }
    }
    }
    return false;
}

// ----------------------------------------------------------------------------
// Forward declarations of internal functions used inside analyze_nfs_procedure
// They're supposed to be used inside analyze_nfs_procedure only
// ----------------------------------------------------------------------------

static uint32_t get_nfs4_compound_minor_version(const uint32_t procedure, const std::uint8_t* rpc_nfs4_call);

using NFS40CompoundType = NST::protocols::NFS4::NFSPROC4RPCGEN_COMPOUND;
using NFS41CompoundType = NST::protocols::NFS41::NFSPROC41RPCGEN_COMPOUND;

template <
    typename ArgOpType,
    typename ResOpType,
    typename NFS4CompoundType>
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

void nfs4_ops_switch(Analyzers&                        analyzers,
                     const RPCProcedure*               rpc_procedure,
                     const NST::API::NFS4::nfs_argop4* arg,
                     const NST::API::NFS4::nfs_resop4* res);

void nfs4_ops_switch(Analyzers&                         analyzers,
                     const RPCProcedure*                rpc_procedure,
                     const NST::API::NFS41::nfs_argop4* arg,
                     const NST::API::NFS41::nfs_resop4* res);

// ----------------------------------------------------------------------------

static inline void analyze_nfsv3_procedure(const uint32_t procedure, XDRDecoder&& c, XDRDecoder&& r, const Session* s, Analyzers& analyzers)
{
    using namespace NST::protocols::NFS3;
    switch(procedure)
    {
    case ProcEnumNFS3::NFS_NULL:
        analyzers(&IAnalyzer::INFSv3rpcgen::null, NFSPROC3RPCGEN_NULL{c, r, s});
        break;
    case ProcEnumNFS3::GETATTR:
        analyzers(&IAnalyzer::INFSv3rpcgen::getattr3, NFSPROC3RPCGEN_GETATTR{c, r, s});
        break;
    case ProcEnumNFS3::SETATTR:
        analyzers(&IAnalyzer::INFSv3rpcgen::setattr3, NFSPROC3RPCGEN_SETATTR{c, r, s});
        break;
    case ProcEnumNFS3::LOOKUP:
        analyzers(&IAnalyzer::INFSv3rpcgen::lookup3, NFSPROC3RPCGEN_LOOKUP{c, r, s});
        break;
    case ProcEnumNFS3::ACCESS:
        analyzers(&IAnalyzer::INFSv3rpcgen::access3, NFSPROC3RPCGEN_ACCESS{c, r, s});
        break;
    case ProcEnumNFS3::READLINK:
        analyzers(&IAnalyzer::INFSv3rpcgen::readlink3, NFSPROC3RPCGEN_READLINK{c, r, s});
        break;
    case ProcEnumNFS3::READ:
        analyzers(&IAnalyzer::INFSv3rpcgen::read3, NFSPROC3RPCGEN_READ{c, r, s});
        break;
    case ProcEnumNFS3::WRITE:
        analyzers(&IAnalyzer::INFSv3rpcgen::write3, NFSPROC3RPCGEN_WRITE{c, r, s});
        break;
    case ProcEnumNFS3::CREATE:
        analyzers(&IAnalyzer::INFSv3rpcgen::create3, NFSPROC3RPCGEN_CREATE{c, r, s});
        break;
    case ProcEnumNFS3::MKDIR:
        analyzers(&IAnalyzer::INFSv3rpcgen::mkdir3, NFSPROC3RPCGEN_MKDIR{c, r, s});
        break;
    case ProcEnumNFS3::SYMLINK:
        analyzers(&IAnalyzer::INFSv3rpcgen::symlink3, NFSPROC3RPCGEN_SYMLINK{c, r, s});
        break;
    case ProcEnumNFS3::MKNOD:
        analyzers(&IAnalyzer::INFSv3rpcgen::mknod3, NFSPROC3RPCGEN_MKNOD{c, r, s});
        break;
    case ProcEnumNFS3::REMOVE:
        analyzers(&IAnalyzer::INFSv3rpcgen::remove3, NFSPROC3RPCGEN_REMOVE{c, r, s});
        break;
    case ProcEnumNFS3::RMDIR:
        analyzers(&IAnalyzer::INFSv3rpcgen::rmdir3, NFSPROC3RPCGEN_RMDIR{c, r, s});
        break;
    case ProcEnumNFS3::RENAME:
        analyzers(&IAnalyzer::INFSv3rpcgen::rename3, NFSPROC3RPCGEN_RENAME{c, r, s});
        break;
    case ProcEnumNFS3::LINK:
        analyzers(&IAnalyzer::INFSv3rpcgen::link3, NFSPROC3RPCGEN_LINK{c, r, s});
        break;
    case ProcEnumNFS3::READDIR:
        analyzers(&IAnalyzer::INFSv3rpcgen::readdir3, NFSPROC3RPCGEN_READDIR{c, r, s});
        break;
    case ProcEnumNFS3::READDIRPLUS:
        analyzers(&IAnalyzer::INFSv3rpcgen::readdirplus3, NFSPROC3RPCGEN_READDIRPLUS{c, r, s});
        break;
    case ProcEnumNFS3::FSSTAT:
        analyzers(&IAnalyzer::INFSv3rpcgen::fsstat3, NFSPROC3RPCGEN_FSSTAT{c, r, s});
        break;
    case ProcEnumNFS3::FSINFO:
        analyzers(&IAnalyzer::INFSv3rpcgen::fsinfo3, NFSPROC3RPCGEN_FSINFO{c, r, s});
        break;
    case ProcEnumNFS3::PATHCONF:
        analyzers(&IAnalyzer::INFSv3rpcgen::pathconf3, NFSPROC3RPCGEN_PATHCONF{c, r, s});
        break;
    case ProcEnumNFS3::COMMIT:
        analyzers(&IAnalyzer::INFSv3rpcgen::commit3, NFSPROC3RPCGEN_COMMIT{c, r, s});
        break;
    }
}

static inline void analyze_nfsv4_procedure(const uint32_t procedure, XDRDecoder&& c, XDRDecoder&& r, const Session* s, Analyzers& analyzers)
{
    using namespace NST::protocols::NFS4;
    using namespace NST::protocols::NFS41;

    switch(get_nfs4_compound_minor_version(procedure, c.data().data))
    {
    case NFS_V40:
        switch(procedure)
        {
        case ProcEnumNFS4::NFS_NULL:
            analyzers(&IAnalyzer::INFSv4rpcgen::null4, NFSPROC4RPCGEN_NULL{c, r, s});
            break;
        case ProcEnumNFS4::COMPOUND:
            NFSPROC4RPCGEN_COMPOUND compound{c, r, s};
            analyzers(&IAnalyzer::INFSv4rpcgen::compound4, compound);
            analyze_nfs40_operations(analyzers, compound);
            break;
        }
        break;
    case NFS_V41:
        if(ProcEnumNFS41::COMPOUND == procedure)
        {
            NFSPROC41RPCGEN_COMPOUND compound{c, r, s};
            analyzers(&IAnalyzer::INFSv41rpcgen::compound41, compound);
            analyze_nfs41_operations(analyzers, compound);
        }
        break;
    }
}

void NFSParser::analyze_nfs_procedure(FilteredDataQueue::Ptr&& call,
                                      FilteredDataQueue::Ptr&& reply,
                                      Session*                 session)
{
    using namespace NST::protocols::rpc;

    auto           header = reinterpret_cast<const CallHeader*>(call->data);
    const uint32_t major_version{header->vers()};
    const uint32_t procedure{header->proc()};

    try
    {
        const Session* s{session->get_session()};

        switch(major_version)
        {
        case NFS_V4:
            analyze_nfsv4_procedure(procedure, std::move(call), std::move(reply), s, this->analyzers);
            break;
        case NFS_V3:
            analyze_nfsv3_procedure(procedure, std::move(call), std::move(reply), s, this->analyzers);
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
static uint32_t get_nfs4_compound_minor_version(const uint32_t procedure, const std::uint8_t* rpc_nfs4_call)
{
    if(ProcEnumNFS4::COMPOUND != procedure)
    {
        return 0;
    }
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
template <
    typename ArgOpType,       // Type of arguments(call part of nfs's procedure)
    typename ResOpType,       // Type of results(reply part of nfs's procedure)
    typename NFS4CompoundType // Type of NFSv4.x COMPOUND procedure. Can be 4.0 or 4.1
    >
void analyze_nfs4_operations(Analyzers& analyzers, NFS4CompoundType& nfs4_compound_procedure)
{
    ArgOpType* arg{nullptr};
    ResOpType* res{nullptr};

    uint32_t arg_ops_count{0}; // Amount of NFS operations (call part)
    uint32_t res_ops_count{0}; // Amount of NFS operations (reply part)
    uint32_t total_ops_count{0};

    if(nfs4_compound_procedure.parg) // Checking if COMPOUND procedure has valid arg
    {
        arg_ops_count = nfs4_compound_procedure.parg->argarray.argarray_len;
        arg           = nfs4_compound_procedure.parg->argarray.argarray_val;
    }

    if(nfs4_compound_procedure.pres) // Checking if COMPOUND procedure has valid res
    {
        res_ops_count = nfs4_compound_procedure.pres->resarray.resarray_len;
        res           = nfs4_compound_procedure.pres->resarray.resarray_val;
    }

    // Determing which part of COMPOUND has the biggest amount of operations.
    total_ops_count = arg_ops_count > res_ops_count ? arg_ops_count : res_ops_count;

    // Traversing through ALL COMPOUND procedure's operations
    for(uint32_t i{0}; i < total_ops_count; i++)
    {
        if((arg && res) && (arg->argop != res->resop))
        {
            // Passing each operation to analyzers using the helper's function
            nfs4_ops_switch(analyzers, &nfs4_compound_procedure, arg, nullptr);
            nfs4_ops_switch(analyzers, &nfs4_compound_procedure, nullptr, res);
        }
        else
        {
            nfs4_ops_switch(analyzers, &nfs4_compound_procedure, arg, res);
        }

        if(arg && i < (arg_ops_count - 1))
        {
            arg++;
        }
        else
        {
            arg = nullptr;
        }
        if(res && i < (res_ops_count - 1))
        {
            res++;
        }
        else
        {
            res = nullptr;
        }
    }
}

//! Internal function for proper passing NFSv4.x's arg + res operations to analyzers
//! It's supposed to be used inside nfs4_ops_switch only
template <
    typename nfs_argop4_t,
    typename nfs_resop4_t,
    typename IAnalyzer_func_t,
    typename nfs_argop_member_t,
    typename nfs_resop_member_t>
inline void analyze(Analyzers&          analyzers,
                    const RPCProcedure* rpc_procedure,
                    const nfs_argop4_t* arg,
                    const nfs_resop4_t* res,
                    IAnalyzer_func_t&&  IAnalyzer_function,
                    nfs_argop_member_t  arg_operation,
                    nfs_resop_member_t  res_operation)
{
    analyzers(IAnalyzer_function, rpc_procedure,
              arg == nullptr ? nullptr : &(arg->nfs_argop4_u.*arg_operation),
              res == nullptr ? nullptr : &(res->nfs_resop4_u.*res_operation));
}

//! Internal function for proper passing NFSv4.x's res-only operations to analyzers
//! It's supposed to be used inside nfs4_ops_switch only
template <
    typename nfs_resop4_t,
    typename IAnalyzer_func_t,
    typename nfs_resop_member_t>
inline void analyze(Analyzers&          analyzers,
                    const RPCProcedure* rpc_procedure,
                    const nfs_resop4_t* res,
                    IAnalyzer_func_t&&  IAnalyzer_function,
                    nfs_resop_member_t  res_operation)
{
    analyzers(IAnalyzer_function, rpc_procedure,
              res == nullptr ? nullptr : &(res->nfs_resop4_u.*res_operation));
}

//! Internal function for proper passing NFSv4.0's operations to analyzers
//! It's supposed to be used inside analyze_nfs4_operations only
void nfs4_ops_switch(Analyzers&                        analyzers,
                     const RPCProcedure*               rpc_procedure,
                     const NST::API::NFS4::nfs_argop4* arg,
                     const NST::API::NFS4::nfs_resop4* res)
{
    using INFSv40 = NST::API::IAnalyzer::INFSv4rpcgen;
    using arg_t   = NST::API::NFS4::nfs_argop4_u_t;
    using res_t   = NST::API::NFS4::nfs_resop4_u_t;

    uint32_t nfs_op_num = arg ? arg->argop : res->resop;
    switch(nfs_op_num)
    {
    case ProcEnumNFS4::ACCESS:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::access40,
                &arg_t::opaccess,
                &res_t::opaccess);
        break;
    case ProcEnumNFS4::CLOSE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::close40,
                &arg_t::opclose,
                &res_t::opclose);
        break;
    case ProcEnumNFS4::COMMIT:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::commit40,
                &arg_t::opcommit,
                &res_t::opcommit);
        break;
    case ProcEnumNFS4::CREATE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::create40,
                &arg_t::opcreate,
                &res_t::opcreate);
        break;
    case ProcEnumNFS4::DELEGPURGE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::delegpurge40,
                &arg_t::opdelegpurge,
                &res_t::opdelegpurge);
        break;
    case ProcEnumNFS4::DELEGRETURN:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::delegreturn40,
                &arg_t::opdelegreturn,
                &res_t::opdelegreturn);
        break;
    case ProcEnumNFS4::GETATTR:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::getattr40,
                &arg_t::opgetattr,
                &res_t::opgetattr);
        break;
    case ProcEnumNFS4::GETFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv40::getfh40,
                &res_t::opgetfh);
        break;
    case ProcEnumNFS4::LINK:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::link40,
                &arg_t::oplink,
                &res_t::oplink);
        break;
    case ProcEnumNFS4::LOCK:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::lock40,
                &arg_t::oplock,
                &res_t::oplock);
        break;
    case ProcEnumNFS4::LOCKT:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::lockt40,
                &arg_t::oplockt,
                &res_t::oplockt);
        break;
    case ProcEnumNFS4::LOCKU:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::locku40,
                &arg_t::oplocku,
                &res_t::oplocku);
        break;
    case ProcEnumNFS4::LOOKUP:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::lookup40,
                &arg_t::oplookup,
                &res_t::oplookup);
        break;
    case ProcEnumNFS4::LOOKUPP:
        analyze(analyzers, rpc_procedure, res,
                &INFSv40::lookupp40,
                &res_t::oplookupp);
        break;
    case ProcEnumNFS4::NVERIFY:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::nverify40,
                &arg_t::opnverify,
                &res_t::opnverify);
        break;
    case ProcEnumNFS4::OPEN:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::open40,
                &arg_t::opopen,
                &res_t::opopen);
        break;
    case ProcEnumNFS4::OPENATTR:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::openattr40,
                &arg_t::opopenattr,
                &res_t::opopenattr);
        break;
    case ProcEnumNFS4::OPEN_CONFIRM:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::open_confirm40,
                &arg_t::opopen_confirm,
                &res_t::opopen_confirm);
        break;
    case ProcEnumNFS4::OPEN_DOWNGRADE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::open_downgrade40,
                &arg_t::opopen_downgrade,
                &res_t::opopen_downgrade);
        break;
    case ProcEnumNFS4::PUTFH:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::putfh40,
                &arg_t::opputfh,
                &res_t::opputfh);
        break;
    case ProcEnumNFS4::PUTPUBFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv40::putpubfh40,
                &res_t::opputpubfh);
        break;
    case ProcEnumNFS4::PUTROOTFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv40::putrootfh40,
                &res_t::opputrootfh);
        break;
    case ProcEnumNFS4::READ:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::read40,
                &arg_t::opread,
                &res_t::opread);
        break;
    case ProcEnumNFS4::READDIR:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::readdir40,
                &arg_t::opreaddir,
                &res_t::opreaddir);
        break;
    case ProcEnumNFS4::READLINK:
        analyze(analyzers, rpc_procedure, res,
                &INFSv40::readlink40,
                &res_t::opreadlink);
        break;
    case ProcEnumNFS4::REMOVE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::remove40,
                &arg_t::opremove,
                &res_t::opremove);
        break;
    case ProcEnumNFS4::RENAME:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::rename40,
                &arg_t::oprename,
                &res_t::oprename);
        break;
    case ProcEnumNFS4::RENEW:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::renew40,
                &arg_t::oprenew,
                &res_t::oprenew);
        break;
    case ProcEnumNFS4::RESTOREFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv40::restorefh40,
                &res_t::oprestorefh);
        break;
    case ProcEnumNFS4::SAVEFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv40::savefh40,
                &res_t::opsavefh);
        break;
    case ProcEnumNFS4::SECINFO:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::secinfo40,
                &arg_t::opsecinfo,
                &res_t::opsecinfo);
        break;
    case ProcEnumNFS4::SETATTR:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::setattr40,
                &arg_t::opsetattr,
                &res_t::opsetattr);
        break;
    case ProcEnumNFS4::SETCLIENTID:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::setclientid40,
                &arg_t::opsetclientid,
                &res_t::opsetclientid);
        break;
    case ProcEnumNFS4::SETCLIENTID_CONFIRM:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::setclientid_confirm40,
                &arg_t::opsetclientid_confirm,
                &res_t::opsetclientid_confirm);
        break;
    case ProcEnumNFS4::VERIFY:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::verify40,
                &arg_t::opverify,
                &res_t::opverify);
        break;
    case ProcEnumNFS4::WRITE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::write40,
                &arg_t::opwrite,
                &res_t::opwrite);
        break;
    case ProcEnumNFS4::RELEASE_LOCKOWNER:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::release_lockowner40,
                &arg_t::oprelease_lockowner,
                &res_t::oprelease_lockowner);
        break;
    case ProcEnumNFS4::GET_DIR_DELEGATION:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv40::get_dir_delegation40,
                &arg_t::opget_dir_delegation,
                &res_t::opget_dir_delegation);
        break;
    case ProcEnumNFS4::ILLEGAL:
        analyze(analyzers, rpc_procedure, res,
                &INFSv40::illegal40,
                &res_t::opillegal);
        break;
    default:
        break;
    }
}

//! Internal function for proper passing NFSv4.1's operations to analyzers
//! It's supposed to be used inside analyze_nfs4_operations only
void nfs4_ops_switch(Analyzers&                         analyzers,
                     const RPCProcedure*                rpc_procedure,
                     const NST::API::NFS41::nfs_argop4* arg,
                     const NST::API::NFS41::nfs_resop4* res)
{
    using INFSv41 = NST::API::IAnalyzer::INFSv41rpcgen;
    using arg_t   = NST::API::NFS41::nfs_argop4_u_t;
    using res_t   = NST::API::NFS41::nfs_resop4_u_t;

    uint32_t nfs_op_num = arg ? arg->argop : res->resop;
    switch(nfs_op_num)
    {
    case ProcEnumNFS41::ACCESS:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::access41,
                &arg_t::opaccess,
                &res_t::opaccess);
        break;
    case ProcEnumNFS41::CLOSE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::close41,
                &arg_t::opclose,
                &res_t::opclose);
        break;
    case ProcEnumNFS41::COMMIT:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::commit41,
                &arg_t::opcommit,
                &res_t::opcommit);
        break;
    case ProcEnumNFS41::CREATE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::create41,
                &arg_t::opcreate,
                &res_t::opcreate);
        break;
    case ProcEnumNFS41::DELEGPURGE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::delegpurge41,
                &arg_t::opdelegpurge,
                &res_t::opdelegpurge);
        break;
    case ProcEnumNFS41::DELEGRETURN:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::delegreturn41,
                &arg_t::opdelegreturn,
                &res_t::opdelegreturn);
        break;
    case ProcEnumNFS41::GETATTR:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::getattr41,
                &arg_t::opgetattr,
                &res_t::opgetattr);
        break;
    case ProcEnumNFS41::GETFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv41::getfh41,
                &res_t::opgetfh);
        break;
    case ProcEnumNFS41::LINK:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::link41,
                &arg_t::oplink,
                &res_t::oplink);
        break;
    case ProcEnumNFS41::LOCK:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::lock41,
                &arg_t::oplock,
                &res_t::oplock);
        break;
    case ProcEnumNFS41::LOCKT:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::lockt41,
                &arg_t::oplockt,
                &res_t::oplockt);
        break;
    case ProcEnumNFS41::LOCKU:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::locku41,
                &arg_t::oplocku,
                &res_t::oplocku);
        break;
    case ProcEnumNFS41::LOOKUP:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::lookup41,
                &arg_t::oplookup,
                &res_t::oplookup);
        break;
    case ProcEnumNFS41::LOOKUPP:
        analyze(analyzers, rpc_procedure, res,
                &INFSv41::lookupp41,
                &res_t::oplookupp);
        break;
    case ProcEnumNFS41::NVERIFY:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::nverify41,
                &arg_t::opnverify,
                &res_t::opnverify);
        break;
    case ProcEnumNFS41::OPEN:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::open41,
                &arg_t::opopen,
                &res_t::opopen);
        break;
    case ProcEnumNFS41::OPENATTR:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::openattr41,
                &arg_t::opopenattr,
                &res_t::opopenattr);
        break;
    case ProcEnumNFS41::OPEN_CONFIRM:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::open_confirm41,
                &arg_t::opopen_confirm,
                &res_t::opopen_confirm);
        break;
    case ProcEnumNFS41::OPEN_DOWNGRADE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::open_downgrade41,
                &arg_t::opopen_downgrade,
                &res_t::opopen_downgrade);
        break;
    case ProcEnumNFS41::PUTFH:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::putfh41,
                &arg_t::opputfh,
                &res_t::opputfh);
        break;
    case ProcEnumNFS41::PUTPUBFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv41::putpubfh41,
                &res_t::opputpubfh);
        break;
    case ProcEnumNFS41::PUTROOTFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv41::putrootfh41,
                &res_t::opputrootfh);
        break;
    case ProcEnumNFS41::READ:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::read41,
                &arg_t::opread,
                &res_t::opread);
        break;
    case ProcEnumNFS41::READDIR:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::readdir41,
                &arg_t::opreaddir,
                &res_t::opreaddir);
        break;
    case ProcEnumNFS41::READLINK:
        analyze(analyzers, rpc_procedure, res,
                &INFSv41::readlink41,
                &res_t::opreadlink);
        break;
    case ProcEnumNFS41::REMOVE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::remove41,
                &arg_t::opremove,
                &res_t::opremove);
        break;
    case ProcEnumNFS41::RENAME:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::rename41,
                &arg_t::oprename,
                &res_t::oprename);
        break;
    case ProcEnumNFS41::RENEW:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::renew41,
                &arg_t::oprenew,
                &res_t::oprenew);
        break;
    case ProcEnumNFS41::RESTOREFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv41::restorefh41,
                &res_t::oprestorefh);
        break;
    case ProcEnumNFS41::SAVEFH:
        analyze(analyzers, rpc_procedure, res,
                &INFSv41::savefh41,
                &res_t::opsavefh);
        break;
    case ProcEnumNFS41::SECINFO:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::secinfo41,
                &arg_t::opsecinfo,
                &res_t::opsecinfo);
        break;
    case ProcEnumNFS41::SETATTR:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::setattr41,
                &arg_t::opsetattr,
                &res_t::opsetattr);
        break;
    case ProcEnumNFS41::SETCLIENTID:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::setclientid41,
                &arg_t::opsetclientid,
                &res_t::opsetclientid);
        break;
    case ProcEnumNFS41::SETCLIENTID_CONFIRM:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::setclientid_confirm41,
                &arg_t::opsetclientid_confirm,
                &res_t::opsetclientid_confirm);
        break;
    case ProcEnumNFS41::VERIFY:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::verify41,
                &arg_t::opverify,
                &res_t::opverify);
        break;
    case ProcEnumNFS41::WRITE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::write41,
                &arg_t::opwrite,
                &res_t::opwrite);
        break;
    case ProcEnumNFS41::RELEASE_LOCKOWNER:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::release_lockowner41,
                &arg_t::oprelease_lockowner,
                &res_t::oprelease_lockowner);
        break;
    case ProcEnumNFS41::BACKCHANNEL_CTL:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::backchannel_ctl41,
                &arg_t::opbackchannel_ctl,
                &res_t::opbackchannel_ctl);
        break;
    case ProcEnumNFS41::BIND_CONN_TO_SESSION:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::bind_conn_to_session41,
                &arg_t::opbind_conn_to_session,
                &res_t::opbind_conn_to_session);
        break;
    case ProcEnumNFS41::EXCHANGE_ID:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::exchange_id41,
                &arg_t::opexchange_id,
                &res_t::opexchange_id);
        break;
    case ProcEnumNFS41::CREATE_SESSION:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::create_session41,
                &arg_t::opcreate_session,
                &res_t::opcreate_session);
        break;
    case ProcEnumNFS41::DESTROY_SESSION:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::destroy_session41,
                &arg_t::opdestroy_session,
                &res_t::opdestroy_session);
        break;
    case ProcEnumNFS41::FREE_STATEID:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::free_stateid41,
                &arg_t::opfree_stateid,
                &res_t::opfree_stateid);
        break;
    case ProcEnumNFS41::GET_DIR_DELEGATION:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::get_dir_delegation41,
                &arg_t::opget_dir_delegation,
                &res_t::opget_dir_delegation);
        break;
    case ProcEnumNFS41::GETDEVICEINFO:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::getdeviceinfo41,
                &arg_t::opgetdeviceinfo,
                &res_t::opgetdeviceinfo);
        break;
    case ProcEnumNFS41::GETDEVICELIST:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::getdevicelist41,
                &arg_t::opgetdevicelist,
                &res_t::opgetdevicelist);
        break;
    case ProcEnumNFS41::LAYOUTCOMMIT:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::layoutcommit41,
                &arg_t::oplayoutcommit,
                &res_t::oplayoutcommit);
        break;
    case ProcEnumNFS41::LAYOUTGET:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::layoutget41,
                &arg_t::oplayoutget,
                &res_t::oplayoutget);
        break;
    case ProcEnumNFS41::LAYOUTRETURN:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::layoutreturn41,
                &arg_t::oplayoutreturn,
                &res_t::oplayoutreturn);
        break;
    case ProcEnumNFS41::SECINFO_NO_NAME:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::secinfo_no_name41,
                &arg_t::opsecinfo_no_name,
                &res_t::opsecinfo_no_name);
        break;
    case ProcEnumNFS41::SEQUENCE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::sequence41,
                &arg_t::opsequence,
                &res_t::opsequence);
        break;
    case ProcEnumNFS41::SET_SSV:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::set_ssv41,
                &arg_t::opset_ssv,
                &res_t::opset_ssv);
        break;
    case ProcEnumNFS41::TEST_STATEID:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::test_stateid41,
                &arg_t::optest_stateid,
                &res_t::optest_stateid);
        break;
    case ProcEnumNFS41::WANT_DELEGATION:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::want_delegation41,
                &arg_t::opwant_delegation,
                &res_t::opwant_delegation);
        break;
    case ProcEnumNFS41::DESTROY_CLIENTID:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::destroy_clientid41,
                &arg_t::opdestroy_clientid,
                &res_t::opdestroy_clientid);
        break;
    case ProcEnumNFS41::RECLAIM_COMPLETE:
        analyze(analyzers, rpc_procedure, arg, res,
                &INFSv41::reclaim_complete41,
                &arg_t::opreclaim_complete,
                &res_t::opreclaim_complete);
        break;
    case ProcEnumNFS41::ILLEGAL:
        analyze(analyzers, rpc_procedure, res,
                &INFSv41::illegal41,
                &res_t::opillegal);
        break;
    default:
        break;
    }
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
