//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "analysis/print_analyzer.h"
#include "protocols/nfs3/nfs_utils.h"
#include "protocols/rpc/rpc_structs.h"
#include "utils/out.h"
#include "utils/session.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

using namespace NST::protocols::NFS3;   // NFSv3 helpers
using namespace NST::protocols::rpc;    // Sun/RPC helpers

namespace
{

inline bool out_all()
{
    using Out = NST::utils::Out;

    return Out::Global::get_level() == Out::Level::All;
}

// Special helper for print-out short representation of NFS FH
std::ostream& print_nfs_fh3(std::ostream& out, const nfs_fh3& fh)
{
    static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    const Opaque& opaque = fh.data;
    const uint8_t* data = opaque.data();
    const uint32_t size = opaque.size();

    if(size <= 8 || out_all())
    {
        for(uint32_t j = 0; j < size; j++)
        {
            uint8_t value = data[j];
            out << hex[value & 0xF];
            value >>= 4;
            out << hex[value & 0xF];
        }
    }
    else // truncate binary data to: 00112233...CCDDEEFF
    {
        for(uint32_t j = 0; j < 4; j++)
        {
            uint8_t value = data[j];
            out << hex[value & 0xF];
            value >>= 4;
            out << hex[value & 0xF];
        }
        out << "...";
        for(uint32_t j = size-4; j < size; j++)
        {
            uint8_t value = data[j];
            out << hex[value & 0xF];
            value >>= 4;
            out << hex[value & 0xF];
        }
    }
    return out;
}

bool print_procedure(std::ostream& out, const struct RPCProcedure* proc)
{
    bool result = false;
    NST::utils::operator<<(out, *(proc->session));
    if(out_all())
    {
        auto& call = proc->call;
        out << " XID: "         << call.xid;
        out << " RPC version: " << call.rpcvers;
        out << " RPC program: " << call.prog;
        out << " version: "     << call.vers;
    }

    out << ' ' << ProcEnum::NFSProcedure(proc->call.proc);

    // check procedure reply
    auto& reply = proc->reply;
    if(reply.stat == ReplyStat::MSG_ACCEPTED)
    {
        switch(reply.u.accepted.stat)
        {
            case AcceptStat::SUCCESS:
                result = true;    // Ok, reply is correct
                break;
            case AcceptStat::PROG_MISMATCH:
                out << " Program mismatch: "
                    << " low: " << reply.u.accepted.mismatch_info.low
                    << " high: " << reply.u.accepted.mismatch_info.high;
                break;
            case AcceptStat::PROG_UNAVAIL:
                out << " Program unavailable";
                break;
            case AcceptStat::PROC_UNAVAIL:
                out << " Procedure unavailable";
                break;
            case AcceptStat::GARBAGE_ARGS:
                out << " Garbage arguments";
                break;
            case AcceptStat::SYSTEM_ERR:
                out << " System error";
                break;
        }
    }
    else if(reply.stat == ReplyStat::MSG_DENIED)
    {
        out << " RPC Call rejected: ";
        switch(reply.u.rejected.stat)
        {
            case RejectStat::RPC_MISMATCH:
                out << "RPC version number mismatch, "
                    << " low: " << reply.u.rejected.u.mismatch_info.low
                    << " high: " << reply.u.rejected.u.mismatch_info.high;
                break;
            case RejectStat::AUTH_ERROR:
            {
                auto& stat = reply.u.rejected.u.auth_stat;
                out << " Authentication error: flavor: " << stat.flavor
                    << " opaque: " << std::string{(char*)stat.body.ptr, stat.body.len};
                break;
            }
        }
    }
    out << '\n'; // end line of RPC procedure information
    return result;
}

} // unnamed namespace

// Print NFSv3 procedures
// 1st line - PRC information: src and dst hosts, status of RPC procedure
// 2nd line - <tabulation>related RPC procedure-specific arguments
// 3rd line - <tabulation>related RPC procedure-specific results


void PrintAnalyzer::null(const struct RPCProcedure* proc,
                         const struct NULLargs*,
                         const struct NULLres*)
{
    if(!print_procedure(out, proc)) return;

    out << "\tCALL  []\n\tREPLY []\n";
}

void PrintAnalyzer::getattr3(const RPCProcedure* proc,
                             const struct GETATTR3args* args,
                             const struct GETATTR3res* res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " object: "; print_nfs_fh3(out, args->object);
        out << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [";
        out << " status: " << res->status;
        if(res->status == nfsstat3::OK && out_all())
        {
            out << " obj_attributes: " << res->resok.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::setattr3(const RPCProcedure* proc,
                             const struct SETATTR3args* args,
                             const struct SETATTR3res* res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " object: "; print_nfs_fh3(out, args->object);
        out << " new_attributes: " << args->new_attributes;
        out << " guard: "          << args->guard;
        out << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [";
        out << " status: " << res->status;
        if(out_all())
        {
            if(res->status == nfsstat3::OK)
            {
                out << " obj_wcc: " << res->resok.obj_wcc;
            }
            else
            {
                out << " obj_wcc: " << res->resfail.obj_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::lookup3(const RPCProcedure* proc,
                            const struct LOOKUP3args* args,
                            const struct LOOKUP3res* res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " what: " << args->what;
        out << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [";
        out << " status: " << res->status;
        if(out_all())
        {
            if(res->status == nfsstat3::OK)
            {
                out << " object: "; print_nfs_fh3(out, res->resok.object);
                out << " obj_attributes: "  << res->resok.obj_attributes;
                out << " dir_attributes: "  << res->resok.dir_attributes;
            }
            else
            {
                out << " dir_attributes: "  << res->resfail.dir_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::access3(const struct RPCProcedure* proc,
                            const struct ACCESS3args* args,
                            const struct ACCESS3res* res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " object: "; print_nfs_fh3(out, args->object);
        out << " access: ";
        if(args->access & ACCESS3args::ACCESS3_READ)   out << "READ ";
        if(args->access & ACCESS3args::ACCESS3_LOOKUP) out << "LOOKUP ";
        if(args->access & ACCESS3args::ACCESS3_MODIFY) out << "MODIFY ";
        if(args->access & ACCESS3args::ACCESS3_EXTEND) out << "EXTEND ";
        if(args->access & ACCESS3args::ACCESS3_DELETE) out << "DELETE ";
        if(args->access & ACCESS3args::ACCESS3_EXECUTE)out << "EXECUTE ";
        out << "]\n";
    }
    if(res)
    {
        out << "\tREPLY ["
            << " status: " << res->status;
            if(res->status == nfsstat3::OK)
            {
                out << " obj_attributes: " << res->resok.obj_attributes;
                out << " access: ";
                uint32_t access = res->resok.access;
                if(access & ACCESS3args::ACCESS3_READ)   out << "READ ";
                if(access & ACCESS3args::ACCESS3_LOOKUP) out << "LOOKUP ";
                if(access & ACCESS3args::ACCESS3_MODIFY) out << "MODIFY ";
                if(access & ACCESS3args::ACCESS3_EXTEND) out << "EXTEND ";
                if(access & ACCESS3args::ACCESS3_DELETE) out << "DELETE ";
                if(access & ACCESS3args::ACCESS3_EXECUTE)out << "EXECUTE ";
            }
            else
            {
                out << " obj_attributes: " << res->resfail.obj_attributes;
                out << ' ';
            }
        out << "]\n";
    }
}

void PrintAnalyzer::readlink3(const struct RPCProcedure* proc,
                              const struct READLINK3args* args,
                              const struct READLINK3res* res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " symlink: "; print_nfs_fh3(out, args->symlink);
        out << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [";
        out << " status: " << res->status;
        if(out_all())
        {
            if(res->status == nfsstat3::OK)
            {
                out << " symlink_attributes: " << res->resok.symlink_attributes;
                out << " data: "  << to_string(res->resok.data);
            }
            else
            {
                out << " symlink_attributes: " << res->resfail.symlink_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::read3(const struct RPCProcedure* proc,
                          const struct READ3args* args,
                          const struct READ3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " file: "; print_nfs_fh3(out, args->file);
    out << " offset: " << args->offset;
    out << " count: "  << args->count;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::write3(const struct RPCProcedure* proc,
                           const struct WRITE3args* args,
                           const struct WRITE3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " file: "; print_nfs_fh3(out, args->file);
    out << " offset: " << args->offset;
    out << " count: "  << args->count;
    out << " stable: " << args->stable;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::create3(const struct RPCProcedure* proc,
                            const struct CREATE3args* args,
                            const struct CREATE3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " where: " << args->where;
    out << " how: "   << args->how;
    out << "] REPLY [";
    out << " status: " << res->status;
    if(res->status == nfsstat3::OK)
    {
        out << " obj: "            << res->u.resok.obj;
        out << " obj_attributes: " << res->u.resok.obj_attributes;
        out << " dir_wcc: "        << res->u.resok.dir_wcc;
    }
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::mkdir3(const struct RPCProcedure* proc,
                           const struct MKDIR3args* args,
                           const struct MKDIR3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " where: "      << args->where;
    out << " attributes: " << args->attributes;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::symlink3(const struct RPCProcedure* proc,
                             const struct SYMLINK3args* args,
                             const struct SYMLINK3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " where: "       << args->where;
    out << " symlinkdata: " << args->symlink;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::mknod3(const struct RPCProcedure* proc,
                           const struct MKNOD3args* args,
                           const struct MKNOD3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " where: " << args->where;
    out << " what: "  << args->what;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::remove3(const struct RPCProcedure* proc,
                            const struct REMOVE3args* args,
                            const struct REMOVE3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " object: " << args->object;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::rmdir3(const struct RPCProcedure* proc,
                           const struct RMDIR3args* args,
                           const struct RMDIR3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " object: " << args->object;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::rename3(const struct RPCProcedure* proc,
                            const struct RENAME3args* args,
                            const struct RENAME3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " from: " << args->from;
    out << " to: "   << args->to;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::link3(const struct RPCProcedure* proc,
                          const struct LINK3args* args,
                          const struct LINK3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " file: "; print_nfs_fh3(out, args->file);;
    out << " link: " << args->link;
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::readdir3(const struct RPCProcedure* proc,
                             const struct READDIR3args* args,
                             const struct READDIR3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " dir: "; print_nfs_fh3(out, args->dir);
    out << " cookie: "      << args->cookie;
    out << " cookieverf: "  << args->cookieverf;
    out << " count: "       << args->count;
    out << "] REPLY [";
    out << " status: "      << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::readdirplus3(const struct RPCProcedure* proc,
                                 const struct READDIRPLUS3args* args,
                                 const struct READDIRPLUS3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " dir: "; print_nfs_fh3(out, args->dir);
    out << " cookie: "      << args->cookie;
    out << " cookieverf: "  << args->cookieverf;
    out << " dircount: "    << args->dircount;
    out << " maxcount: "    << args->maxcount;
    out << "] REPLY [";
    out << " status: " << res->status;
    if(res->status == nfsstat3::OK)
    {
        out << " dir_attributes: " << res->u.resok.dir_attributes;
        out << " cookieverf: "     << res->u.resok.cookieverf;
    }
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::fsstat3(const struct RPCProcedure* proc,
                            const struct FSSTAT3args* args,
                            const struct FSSTAT3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " fsroot: "; print_nfs_fh3(out, args->fsroot);
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::fsinfo3(const struct RPCProcedure* proc,
                            const struct FSINFO3args* args,
                            const struct FSINFO3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " fsroot: "; print_nfs_fh3(out, args->fsroot);
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::pathconf3(const struct RPCProcedure* proc,
                              const struct PATHCONF3args* args,
                              const struct PATHCONF3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " object: "; print_nfs_fh3(out, args->object);
    out << "] REPLY [";
    out << " status: " << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::commit3(const struct RPCProcedure* proc,
                            const struct COMMIT3args* args,
                            const struct COMMIT3res* res)
{
    print_procedure(out, proc);
    out << " CALL [";
    out << " file: "; print_nfs_fh3(out, args->file);
    out << " offset: "  << args->offset;
    out << " count: "   << args->count;
    out << "] REPLY [";
    out << " status: "  << res->status;
    out << " ]";
    out << std::endl;
}

void PrintAnalyzer::flush_statistics()
{
    // flush is in each handler
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
