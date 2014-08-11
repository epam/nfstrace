//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
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
#include "analysis/print_analyzer.h"
#include "protocols/nfs3/nfs3_utils.h"
#include "protocols/rpc/rpc_utils.h"
#include "utils/out.h"
#include "utils/sessions.h"
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
std::ostream& print_nfs_fh3(std::ostream& out, const uint8_t* data, const uint32_t size)
{
    out << std::hex << std::setfill('0') << std::setw(2);
    if(size <= 8 || out_all())
    {
        for(uint32_t j = 0; j < size; j++)
        {
            out << std::setw(2) << (uint32_t)data[j];
        }
    }
    else // truncate binary data to: 00112233...CCDDEEFF
    {
        for(uint32_t j = 0; j < 4; j++)
        {
            out << std::setw(2) << (uint32_t)data[j];
        }
        out << "...";
        for(uint32_t j = size-4; j < size; j++)
        {
            out << std::setw(2) << (uint32_t)data[j];
        }
    }
    out << std::dec << std::setfill(' ');
    return out;
}

std::ostream& print_nfs_fh3(std::ostream& out, const nfs_fh3& fh)
{
    return print_nfs_fh3(out, fh.data.data(), fh.data.size());
}

extern "C"
void print_nfs_fh3(std::ostream& out, const FH& fh)
{
    print_nfs_fh3(out, fh.data, fh.len);
}

bool print_procedure(std::ostream& out, const struct RPCProcedure* proc)
{
    bool result = false;
    NST::utils::operator<<(out, *(proc->session));

    auto& call = proc->rpc_call;
    const int nfs_version = call.ru.RM_cmb.cb_vers;
    if(out_all())
    {
        out << " XID: "         << call.rm_xid;
        out << " RPC version: " << call.ru.RM_cmb.cb_rpcvers;
        out << " RPC program: " << call.ru.RM_cmb.cb_prog;
        out << " version: "     << nfs_version;
    }
    switch(nfs_version)
    {
    case NFS_V3:
        out << ' ' << print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(call.ru.RM_cmb.cb_proc));
        break;
    case NFS_V4:
        out << ' ' << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(call.ru.RM_cmb.cb_proc));
        break;
    }

    // check procedure reply
    auto& reply = proc->rpc_reply;
    if(reply.ru.RM_rmb.rp_stat == reply_stat::MSG_ACCEPTED)
    {
        switch(reply.ru.RM_rmb.ru.RP_ar.ar_stat)
        {
            case accept_stat::SUCCESS:
                result = true;    // Ok, reply is correct
                break;
            case accept_stat::PROG_MISMATCH:
                out << " Program mismatch: "
                    << " low: "  << reply.ru.RM_rmb.ru.RP_ar.ru.AR_versions.low
                    << " high: " << reply.ru.RM_rmb.ru.RP_ar.ru.AR_versions.high;
                break;
            case accept_stat::PROG_UNAVAIL:
                out << " Program unavailable";
                break;
            case accept_stat::PROC_UNAVAIL:
                out << " Procedure unavailable";
                break;
            case accept_stat::GARBAGE_ARGS:
                out << " Garbage arguments";
                break;
            case accept_stat::SYSTEM_ERR:
                out << " System error";
                break;
        }
    }
    else if(reply.ru.RM_rmb.rp_stat == reply_stat::MSG_DENIED)
    {
        out << " RPC Call rejected: ";
        switch(reply.ru.RM_rmb.ru.RP_dr.rj_stat)
        {
            case reject_stat::RPC_MISMATCH:
                out << "RPC version number mismatch, "
                    << " low: "  << reply.ru.RM_rmb.ru.RP_dr.ru.RJ_versions.low
                    << " high: " << reply.ru.RM_rmb.ru.RP_dr.ru.RJ_versions.high;
                break;
            case reject_stat::AUTH_ERROR:
            {
                out << " Authentication check: ";
                switch(reply.ru.RM_rmb.ru.RP_dr.ru.RJ_why)
                {
                case auth_stat::AUTH_OK:
                    out << "OK";
                    break;
                case auth_stat::AUTH_BADCRED:
                    out << " bogus credentials (seal broken)"
                        << " (failed at remote end)";
                    break;
                case auth_stat::AUTH_REJECTEDCRED:
                    out << " rejected credentials (client should begin new session)"
                        << " (failed at remote end)";
                    break;
                case auth_stat::AUTH_BADVERF:
                    out << " bogus verifier (seal broken)"
                        << " (failed at remote end)";
                    break;
                case auth_stat::AUTH_REJECTEDVERF:
                    out << " verifier expired or was replayed"
                        << " (failed at remote end)";
                    break;
                case auth_stat::AUTH_TOOWEAK:
                    out << " too weak (rejected due to security reasons)"
                        << " (failed at remote end)";
                    break;
                case auth_stat::AUTH_INVALIDRESP:
                    out << " bogus response verifier"
                        << " (failed locally)";
                    break;
                case auth_stat::AUTH_FAILED:
                    out << " some unknown reason"
                        << " (failed locally)";
                    break;
                }
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

void PrintAnalyzer::getattr3(const RPCProcedure*        proc,
                             const struct GETATTR3args* args,
                             const struct GETATTR3res*  res)
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

void PrintAnalyzer::setattr3(const RPCProcedure*        proc,
                             const struct SETATTR3args* args,
                             const struct SETATTR3res*  res)
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

void PrintAnalyzer::lookup3(const RPCProcedure*       proc,
                            const struct LOOKUP3args* args,
                            const struct LOOKUP3res*  res)
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
                            const struct ACCESS3args*  args,
                            const struct ACCESS3res*   res)
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
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readlink3(const struct RPCProcedure*  proc,
                              const struct READLINK3args* args,
                              const struct READLINK3res*  res)
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
                          const struct READ3args*    args,
                          const struct READ3res*     res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " file: "; print_nfs_fh3(out, args->file);
        out << " offset: " << args->offset;
        out << " count: "  << args->count;
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
                out << " file_attributes: " << res->resok.file_attributes;
                out << " count: "           << res->resok.count;
                out << " eof: "             << bool(res->resok.eof);
                out << " data: skipped on filtration";
            }
            else
            {
                out << " file_attributes: " << res->resfail.file_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::write3(const struct RPCProcedure* proc,
                           const struct WRITE3args*   args,
                           const struct WRITE3res*    res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " file: "; print_nfs_fh3(out, args->file);
        out << " offset: " << args->offset;
        out << " count: "  << args->count;
        out << " stable: " << args->stable;
        if(out_all())
        {
            out << " data: skipped on filtration";
        }
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
                out << " file_wcc: "  << res->resok.file_wcc;
                out << " count: "     << res->resok.count;
                out << " committed: " << res->resok.committed;
                out << " verf: "      << res->resok.verf;
            }
            else
            {
                out << " file_wcc: " << res->resfail.file_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::create3(const struct RPCProcedure* proc,
                            const struct CREATE3args*  args,
                            const struct CREATE3res*   res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " where: " << args->where;
        out << " how: "   << args->how;
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
                out << " obj: "            << res->resok.obj;
                out << " obj_attributes: " << res->resok.obj_attributes;
                out << " dir_wcc: "        << res->resok.dir_wcc;
            }
            else
            {
                out << " dir_wcc: " << res->resfail.dir_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::mkdir3(const struct RPCProcedure* proc,
                           const struct MKDIR3args*   args,
                           const struct MKDIR3res*    res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " where: "      << args->where;
        out << " attributes: " << args->attributes;
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
                out << " obj: "            << res->resok.obj;
                out << " obj_attributes: " << res->resok.obj_attributes;
                out << " dir_wcc: "        << res->resok.dir_wcc;
            }
            else
            {
                out << " dir_wcc: " << res->resfail.dir_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::symlink3(const struct RPCProcedure* proc,
                             const struct SYMLINK3args* args,
                             const struct SYMLINK3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " where: "       << args->where;
        out << " symlinkdata: " << args->symlink;
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
                out << " obj: "            << res->resok.obj;
                out << " obj_attributes: " << res->resok.obj_attributes;
                out << " dir_wcc: "        << res->resok.dir_wcc;
            }
            else
            {
                out << " dir_wcc: " << res->resfail.dir_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::mknod3(const struct RPCProcedure* proc,
                           const struct MKNOD3args*   args,
                           const struct MKNOD3res*    res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " where: " << args->where;
        out << " what: "  << args->what;
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
                out << " obj: "            << res->resok.obj;
                out << " obj_attributes: " << res->resok.obj_attributes;
                out << " dir_wcc: "        << res->resok.dir_wcc;
            }
            else
            {
                out << " dir_wcc: " << res->resfail.dir_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::remove3(const struct RPCProcedure* proc,
                            const struct REMOVE3args*  args,
                            const struct REMOVE3res*   res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " object: " << args->object;
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
                out << " dir_wcc: " << res->resok.dir_wcc;
            }
            else
            {
                out << " dir_wcc: " << res->resfail.dir_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::rmdir3(const struct RPCProcedure* proc,
                           const struct RMDIR3args*   args,
                           const struct RMDIR3res*    res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " object: " << args->object;
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
                out << " dir_wcc: " << res->resok.dir_wcc;
            }
            else
            {
                out << " dir_wcc: " << res->resfail.dir_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::rename3(const struct RPCProcedure* proc,
                            const struct RENAME3args*  args,
                            const struct RENAME3res*   res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " from: " << args->from;
        out << " to: "   << args->to;
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
                out << " fromdir_wcc: " << res->resok.fromdir_wcc;
                out << " todir_wcc: "   << res->resok.todir_wcc;
            }
            else
            {
                out << " fromdir_wcc: " << res->resfail.fromdir_wcc;
                out << " todir_wcc: "   << res->resfail.todir_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::link3(const struct RPCProcedure* proc,
                          const struct LINK3args*    args,
                          const struct LINK3res*     res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " file: "; print_nfs_fh3(out, args->file);;
        out << " link: " << args->link;
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
                out << " file_attributes: " << res->resok.file_attributes;
                out << " linkdir_wcc: "     << res->resok.linkdir_wcc;
            }
            else
            {
                out << " file_attributes: " << res->resfail.file_attributes;
                out << " linkdir_wcc: "     << res->resfail.linkdir_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readdir3(const struct RPCProcedure* proc,
                             const struct READDIR3args* args,
                             const struct READDIR3res* res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " dir: "; print_nfs_fh3(out, args->dir);
        out << " cookie: "      << args->cookie;
        out << " cookieverf: "  << args->cookieverf;
        out << " count: "       << args->count;
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
                out << " dir_attributes: " << res->resok.dir_attributes;
                out << " cookieverf: "     << res->resok.cookieverf;
                out << " reply: Not implemented";//     << res->resok.reply;
            }
            else
            {
                out << " dir_attributes: " << res->resfail.dir_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readdirplus3(const struct RPCProcedure*     proc,
                                 const struct READDIRPLUS3args* args,
                                 const struct READDIRPLUS3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " dir: "; print_nfs_fh3(out, args->dir);
        out << " cookie: "      << args->cookie;
        out << " cookieverf: "  << args->cookieverf;
        out << " dircount: "    << args->dircount;
        out << " maxcount: "    << args->maxcount;
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
                out << " dir_attributes: " << res->resok.dir_attributes;
                out << " cookieverf: "     << res->resok.cookieverf;
                out << " reply: Not implemented";//     << res->resok.reply;
            }
            else
            {
                out << " dir_attributes: " << res->resfail.dir_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::fsstat3(const struct RPCProcedure* proc,
                            const struct FSSTAT3args*  args,
                            const struct FSSTAT3res*   res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " fsroot: "; print_nfs_fh3(out, args->fsroot);
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
                out << " obj_attributes: " << res->resok.obj_attributes;
                out << " tbytes: "     << res->resok.tbytes;
                out << " fbytes: "     << res->resok.fbytes;
                out << " abytes: "     << res->resok.abytes;
                out << " tfiles: "     << res->resok.tfiles;
                out << " ffiles: "     << res->resok.ffiles;
                out << " afiles: "     << res->resok.afiles;
                out << " invarsec: "   << res->resok.invarsec;
            }
            else
            {
                out << " obj_attributes: " << res->resfail.obj_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::fsinfo3(const struct RPCProcedure* proc,
                            const struct FSINFO3args*  args,
                            const struct FSINFO3res*   res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " fsroot: "; print_nfs_fh3(out, args->fsroot);
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
                out << " obj_attributes: " << res->resok.obj_attributes;
                out << " rtmax: "       << res->resok.rtmax;
                out << " rtpref: "      << res->resok.rtpref;
                out << " rtmult: "      << res->resok.rtmult;
                out << " wtmax: "       << res->resok.wtmax;
                out << " wtpref: "      << res->resok.wtpref;
                out << " wtmult: "      << res->resok.wtmult;
                out << " dtpref: "      << res->resok.dtpref;
                out << " maxfilesize: " << res->resok.maxfilesize;
                out << " time_delta: "  << res->resok.time_delta;
                out << " properties: ";
                out << " LINK:"        << bool(res->resok.properties & FSINFO3res::FSINFO3resok::FSF3_LINK);
                out << " SYMLINK:"     << bool(res->resok.properties & FSINFO3res::FSINFO3resok::FSF3_SYMLINK);
                out << " HOMOGENEOUS:" << bool(res->resok.properties & FSINFO3res::FSINFO3resok::FSF3_HOMOGENEOUS);
                out << " CANSETTIME:"  << bool(res->resok.properties & FSINFO3res::FSINFO3resok::FSF3_CANSETTIME);
            }
            else
            {
                out << " obj_attributes: " << res->resfail.obj_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::pathconf3(const struct RPCProcedure*  proc,
                              const struct PATHCONF3args* args,
                              const struct PATHCONF3res*  res)
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
        if(out_all())
        {
            if(res->status == nfsstat3::OK)
            {
                out << " obj_attributes: "   << res->resok.obj_attributes;
                out << " linkmax: "          << res->resok.linkmax;
                out << " name_max: "         << res->resok.name_max;
                out << " no_trunc: "         << bool(res->resok.no_trunc);
                out << " chown_restricted: " << bool(res->resok.chown_restricted);
                out << " case_insensitive: " << bool(res->resok.case_insensitive);
                out << " case_preserving: "  << bool(res->resok.case_preserving);
            }
            else
            {
                out << " obj_attributes: " << res->resfail.obj_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::commit3(const struct RPCProcedure* proc,
                            const struct COMMIT3args*  args,
                            const struct COMMIT3res*   res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " file: "; print_nfs_fh3(out, args->file);
        out << " offset: "  << args->offset;
        out << " count: "   << args->count;
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
                out << " file_wcc: " << res->resok.file_wcc;
                out << " verf: "     << res->resok.verf;
            }
            else
            {
                out << " file_wcc: " << res->resfail.file_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::null(const struct RPCProcedure* proc,
                         const struct rpcgen::NULL4args*,
                         const struct rpcgen::NULL4res*)
{
    if(!print_procedure(out, proc)) return;

    out << "\tCALL  []\n\tREPLY []\n";
}

void PrintAnalyzer::compound4(const struct RPCProcedure*          proc,
                              const struct rpcgen::COMPOUND4args* args,
                              const struct rpcgen::COMPOUND4res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [";
        out << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [";
        out << " ]\n";
    }
}

void PrintAnalyzer::flush_statistics()
{
    // flush is in each handler
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
