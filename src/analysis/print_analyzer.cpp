//------------------------------------------------------------------------------
// Author: Dzianis Huznou (Alexey Costroma)
// Description: Created for demonstration purpose only.
// Copyright (c) 2013,2014 EPAM Systems
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
#include <iomanip>

#include "analysis/print_analyzer.h"
#include "protocols/nfs/nfs_utils.h"
#include "protocols/nfs3/nfs3_utils.h"
#include "protocols/nfs4/nfs4_utils.h"
#include "protocols/rpc/rpc_utils.h"
#include "utils/out.h"
#include "utils/sessions.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

using namespace NST::protocols::NFS;  // NFS helpers
using namespace NST::protocols::NFS3; // NFSv3 helpers
using namespace NST::protocols::NFS4; // NFSv4 helpers

namespace
{

inline bool out_all()
{
    using Out = NST::utils::Out;

    return Out::Global::get_level() == Out::Level::All;
}

std::ostream& print_nfs_fh(std::ostream& out, const char* const val, const uint32_t len)
{
    if(len)
    {
        out << std::hex << std::setfill('0');
        if(len <= 8 || out_all())
        {
            for(uint32_t i = 0; i < len; i++)
            {
                out << std::setw(2) << ((static_cast<int32_t>(val[i])) & 0xFF);
            }
        }
        else // truncate binary data to: 00112233...CCDDEEFF
        {
            for(uint32_t i = 0; i < 4; i++)
            {
                out << std::setw(2) << ((static_cast<int32_t>(val[i])) & 0xFF);
            }
            out << "...";
            for(uint32_t i = len-4; i < len; i++)
            {
                out << std::setw(2) << ((static_cast<int32_t>(val[i])) & 0xFF);
            }
        }
        return out << std::dec << std::setfill(' ');
    }
    else
    {
        return out << "void";
    }
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
                default:
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

// Print NFSv3 procedures (rpcgen)
// 1st line - PRC information: src and dst hosts, status of RPC procedure
// 2nd line - <tabulation>related RPC procedure-specific arguments
// 3rd line - <tabulation>related RPC procedure-specific results

void PrintAnalyzer::null(const struct RPCProcedure* proc,
                         const struct rpcgen::NULL3args*,
                         const struct rpcgen::NULL3res*)
{
    if(!print_procedure(out, proc)) return;
    out << "\tCALL  []\n\tREPLY []\n";
}

void PrintAnalyzer::getattr3(const struct RPCProcedure*         proc,
                             const struct rpcgen::GETATTR3args* args,
                             const struct rpcgen::GETATTR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  ["
                 << " object: " << args->object
                 << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat3::NFS3_OK)
            out << " obj attributes: " << res->GETATTR3res_u.resok.obj_attributes;
        out << " ]\n";
    }
}

void PrintAnalyzer::setattr3(const struct RPCProcedure*         proc,
                             const struct rpcgen::SETATTR3args* args,
                             const struct rpcgen::SETATTR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  ["
                 << " object: "         << args->object
                 << " new attributes: " << args->new_attributes
                 << " guard: "          << args->guard
                 << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " obj_wcc: " << res->SETATTR3res_u.resok.obj_wcc;
            else
                out << " obj_wcc: " << res->SETATTR3res_u.resfail.obj_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::lookup3(const struct RPCProcedure*        proc,
                            const struct rpcgen::LOOKUP3args* args,
                            const struct rpcgen::LOOKUP3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  ["
                 << " what: " << args->what
                 << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " object: "            << res->LOOKUP3res_u.resok.object
                    << " object attributes: " << res->LOOKUP3res_u.resok.obj_attributes
                    << " dir attributes: "    << res->LOOKUP3res_u.resok.dir_attributes;
            else
                out << " dir attributes: "    << res->LOOKUP3res_u.resfail.dir_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::access3(const struct RPCProcedure*        proc,
                            const struct rpcgen::ACCESS3args* args,
                            const struct rpcgen::ACCESS3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  ["
                 << " object: ";
        print_nfs_fh(out, args->object.data.data_val, args->object.data.data_len);
        out << " access: ";
        print_access3(out, args->access);
        out << " ]\n";
    }

    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
            {
                out << " object attributes: " << res->ACCESS3res_u.resok.obj_attributes
                    << " access: "; print_access3(out, res->ACCESS3res_u.resok.access);
            }
            else
            {
                out << " access: " << res->ACCESS3res_u.resfail.obj_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readlink3(const struct RPCProcedure*          proc,
                              const struct rpcgen::READLINK3args* args,
                              const struct rpcgen::READLINK3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  ["
                 << " symlink: " << args->symlink
                 << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " symlink attributes: " << res->READLINK3res_u.resok.symlink_attributes
                    << " data: "               << res->READLINK3res_u.resok.data; 
            else
                out << " symlink attributes: " << res->READLINK3res_u.resfail.symlink_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::read3(const struct RPCProcedure*      proc,
                          const struct rpcgen::READ3args* args,
                          const struct rpcgen::READ3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  ["
                 << " file: "   << args->file
                 << " offset: " << args->offset
                 << " count: "  << args->count
                 << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
            {
                out << " file attributes: " << res->READ3res_u.resok.file_attributes
                    << " count: "           << res->READ3res_u.resok.count
                    << " eof: "             << res->READ3res_u.resok.eof;
            }
            else
            {
                out << " symlink attributes: " << res->READ3res_u.resfail.file_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::write3(const struct RPCProcedure*       proc,
                           const struct rpcgen::WRITE3args* args,
                           const struct rpcgen::WRITE3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  ["
            << " file: "   << args->file
            << " offset: " << args->offset
            << " count: "  << args->count
            << " stable: " << args->stable;
        out << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
            {
                out << " file_wcc: " << res->WRITE3res_u.resok.file_wcc
                    << " count: "    << res->WRITE3res_u.resok.count
                    << " commited: " << res->WRITE3res_u.resok.committed
                    << " verf: ";
                print_hex(out, res->WRITE3res_u.resok.verf, rpcgen::NFS3_WRITEVERFSIZE);
            }
            else
            {
                out << " file_wcc: " << res->WRITE3res_u.resfail.file_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::create3(const struct RPCProcedure*        proc,
                            const struct rpcgen::CREATE3args* args,
                            const struct rpcgen::CREATE3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " where: " << args->where
            << " how: "   << args->how
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " obj: " << res->CREATE3res_u.resok.obj
                    << " obj attributes: " << res->CREATE3res_u.resok.obj_attributes
                    << " dir_wcc: " << res->CREATE3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: " << res->CREATE3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::mkdir3(const struct RPCProcedure*       proc,
                           const struct rpcgen::MKDIR3args* args,
                           const struct rpcgen::MKDIR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " where: "      << args->where
            << " attributes: " << args->attributes
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " obj: "            << res->MKDIR3res_u.resok.obj
                    << " obj attributes: " << res->MKDIR3res_u.resok.obj_attributes
                    << " dir_wcc: "        << res->MKDIR3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "        << res->MKDIR3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::symlink3(const struct RPCProcedure*         proc,
                             const struct rpcgen::SYMLINK3args* args,
                             const struct rpcgen::SYMLINK3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " where: "   << args->where
            << " symlink: " << args->symlink
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " obj: "            << res->SYMLINK3res_u.resok.obj
                    << " obj attributes: " << res->SYMLINK3res_u.resok.obj_attributes
                    << " dir_wcc: "        << res->SYMLINK3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "        << res->SYMLINK3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::mknod3(const struct RPCProcedure*       proc,
                           const struct rpcgen::MKNOD3args* args,
                           const struct rpcgen::MKNOD3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  ["
            << " where: " << args->where
            << " what: "  << args->what
            << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " obj: "            << res->MKNOD3res_u.resok.obj
                    << " obj attributes: " << res->MKNOD3res_u.resok.obj_attributes
                    << " dir_wcc: "        << res->MKNOD3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "        << res->MKNOD3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::remove3(const struct RPCProcedure*        proc,
                            const struct rpcgen::REMOVE3args* args,
                            const struct rpcgen::REMOVE3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " object: " << args->object
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " dir_wcc: " << res->REMOVE3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: " << res->REMOVE3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::rmdir3(const struct RPCProcedure*       proc,
                           const struct rpcgen::RMDIR3args* args,
                           const struct rpcgen::RMDIR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  ["
            << " object: " << args->object
            << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " dir_wcc: " << res->RMDIR3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: " << res->RMDIR3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::rename3(const struct RPCProcedure*        proc,
                            const struct rpcgen::RENAME3args* args,
                            const struct rpcgen::RENAME3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " from: " << args->from
            << " to: "   << args->to
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " from dir_wcc: " << res->RENAME3res_u.resok.fromdir_wcc
                    << " to dir_wcc: "   << res->RENAME3res_u.resok.todir_wcc;
            else
                out << " from dir_wcc: " << res->RENAME3res_u.resfail.fromdir_wcc
                    << " to dir_wcc: "   << res->RENAME3res_u.resfail.todir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::link3(const struct RPCProcedure*      proc,
                          const struct rpcgen::LINK3args* args,
                          const struct rpcgen::LINK3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " file: " << args->file
            << " link: " << args->link
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " file attributes: " << res->LINK3res_u.resok.file_attributes
                    << " link dir_wcc: "    << res->LINK3res_u.resok.linkdir_wcc;
            else
                out << " file attributes: " << res->LINK3res_u.resfail.file_attributes
                    << " link dir_wcc: "    << res->LINK3res_u.resfail.linkdir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readdir3(const struct RPCProcedure*         proc,
                             const struct rpcgen::READDIR3args* args,
                             const struct rpcgen::READDIR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  ["
            << " dir: "        << args->dir
            << " cookie: "     << args->cookie
            << " cookieverf: ";
        print_hex(out, args->cookieverf, rpcgen::NFS3_COOKIEVERFSIZE);
        out << " count: "      << args->count
            << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
            {
                out << " dir attributes: " << res->READDIR3res_u.resok.dir_attributes
                    << " cookieverf: ";
                print_hex(out, res->READDIR3res_u.resok.cookieverf, rpcgen::NFS3_COOKIEVERFSIZE);
                out << " reply: "          << res->READDIR3res_u.resok.reply;
            }
            else
            {
                out << " dir attributes: " << res->READDIR3res_u.resfail.dir_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readdirplus3(const struct RPCProcedure*             proc,
                                 const struct rpcgen::READDIRPLUS3args* args,
                                 const struct rpcgen::READDIRPLUS3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  ["
            << " dir: "        << args->dir
            << " cookie: "     << args->cookie
            << " cookieverf: ";
        print_hex(out, args->cookieverf, rpcgen::NFS3_COOKIEVERFSIZE);
        out << " dir count: "  << args->dircount
            << " max count: "  << args->maxcount
            << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
            {
                out << " dir attributes: " << res->READDIRPLUS3res_u.resok.dir_attributes
                    << " cookieverf: ";
                print_hex(out, res->READDIRPLUS3res_u.resok.cookieverf, rpcgen::NFS3_COOKIEVERFSIZE);
                out << " reply: "          << res->READDIRPLUS3res_u.resok.reply;
            }
            else
            {
                out << " dir attributes: " << res->READDIRPLUS3res_u.resfail.dir_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::fsstat3(const struct RPCProcedure*        proc,
                            const struct rpcgen::FSSTAT3args* args,
                            const struct rpcgen::FSSTAT3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " fsroot: " << args->fsroot
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " obj attributes: " << res->FSSTAT3res_u.resok.obj_attributes
                    << " tbytes: "         << res->FSSTAT3res_u.resok.tbytes
                    << " fbytes: "         << res->FSSTAT3res_u.resok.fbytes
                    << " abytes: "         << res->FSSTAT3res_u.resok.abytes
                    << " tfile: "          << res->FSSTAT3res_u.resok.tfiles
                    << " ffile: "          << res->FSSTAT3res_u.resok.ffiles
                    << " afile: "          << res->FSSTAT3res_u.resok.afiles
                    << " invarsec: "       << res->FSSTAT3res_u.resok.invarsec;
            else
                out << " obj attributes: " << res->FSSTAT3res_u.resfail.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::fsinfo3(const struct RPCProcedure*        proc,
                            const struct rpcgen::FSINFO3args* args,
                            const struct rpcgen::FSINFO3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " fsroot: " << args->fsroot
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " obj attributes: " << res->FSINFO3res_u.resok.obj_attributes
                    << " rtmax: "          << res->FSINFO3res_u.resok.rtmax
                    << " rtpref: "         << res->FSINFO3res_u.resok.rtpref
                    << " rtmult: "         << res->FSINFO3res_u.resok.rtmult
                    << " wtmax: "          << res->FSINFO3res_u.resok.wtmax
                    << " wtpref: "         << res->FSINFO3res_u.resok.wtpref
                    << " wtmult: "         << res->FSINFO3res_u.resok.wtmult
                    << " dtpref: "         << res->FSINFO3res_u.resok.dtpref
                    << " max file size: "  << res->FSINFO3res_u.resok.maxfilesize
                    << " time delta: "     << res->FSINFO3res_u.resok.time_delta
                    << " properties: "     << res->FSINFO3res_u.resok.properties
                    << " LINK (filesystem supports hard links): "          << bool(res->FSINFO3res_u.resok.properties & rpcgen::FSF3_LINK)
                    << " SYMLINK (file system supports symbolic links): "  << bool(res->FSINFO3res_u.resok.properties & rpcgen::FSF3_SYMLINK)
                    << " HOMOGENEOUS (PATHCONF: is valid for all files): " << bool(res->FSINFO3res_u.resok.properties & rpcgen::FSF3_HOMOGENEOUS)
                    << " CANSETTIME (SETATTR can set time on server): "    << bool(res->FSINFO3res_u.resok.properties & rpcgen::FSF3_CANSETTIME);
            else
                out << " obj attributes: " << res->FSINFO3res_u.resfail.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::pathconf3(const struct RPCProcedure*          proc,
                              const struct rpcgen::PATHCONF3args* args,
                              const struct rpcgen::PATHCONF3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " object: " << args->object
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
                out << " obj attributes: "   << res->PATHCONF3res_u.resok.obj_attributes
                    << " link max: "         << res->PATHCONF3res_u.resok.linkmax
                    << " name max: "         << res->PATHCONF3res_u.resok.name_max
                    << " no trunc: "         << res->PATHCONF3res_u.resok.no_trunc
                    << " chwon restricted: " << res->PATHCONF3res_u.resok.chown_restricted
                    << " case insensitive: " << res->PATHCONF3res_u.resok.case_insensitive
                    << " case preserving: "  << res->PATHCONF3res_u.resok.case_preserving;
            else
                out << " obj attributes: " << res->PATHCONF3res_u.resfail.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::commit3(const struct RPCProcedure*        proc,
                            const struct rpcgen::COMMIT3args* args,
                            const struct rpcgen::COMMIT3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  ["
            << " file: "   << args->file
            << " offset: " << args->offset
            << " count: "  << args->count
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == rpcgen::nfsstat3::NFS3_OK)
            {
                out << " file_wcc: " << res->COMMIT3res_u.resok.file_wcc
                    << " verf: ";
                print_hex(out, res->COMMIT3res_u.resok.verf, rpcgen::NFS3_WRITEVERFSIZE);
            }
            else
            {
                out << " file_wcc: " << res->COMMIT3res_u.resfail.file_wcc;
            }
        }
        out << " ]\n";
    }
}


// Print NFSv4 procedures
// 1st line - PRC information: src and dst hosts, status of RPC procedure
// 2nd line - <tabulation>related RPC procedure-specific arguments
// 3rd line - <tabulation>related NFSv4-operations
// 4th line - <tabulation>related RPC procedure-specific results
// 5rd line - <tabulation>related NFSv4-operations

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

    const u_int* array_len {};
    if(args)
    {
        array_len = &args->argarray.argarray_len;
        out << "\tCALL  ["
            << " operations: " << *array_len
            << " tag: " << args->tag
            << " minor version: " << args->minorversion;
        if(*array_len)
        {
            rpcgen::nfs_argop4* current_el = args->argarray.argarray_val;
            for(u_int i=0; i<*array_len; i++, current_el++)
            {
                out << "\n\t\t[ ";
                nfs4_operation(current_el);
                out << " ] ";
            }
            out << " ]\n";
        } 
    }
    if(res)
    {
        array_len = &res->resarray.resarray_len;
        out << "\tREPLY [ "
            << " operations: " << *array_len;
        if(*array_len)
        {
            rpcgen::nfs_resop4* current_el = res->resarray.resarray_val;
            for(u_int i=0; i<*array_len; i++, current_el++)
            {
                out << "\n\t\t[ ";
                nfs4_operation(current_el);
                out << " ] ";
            }
            out << " ]\n";
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::nfs_argop4* op)
{
    if(op)
    {
    out << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(op->argop))
        << "(" << op->argop << ") [ ";
        switch(op->argop)
        {
        case rpcgen::OP_ACCESS:              return nfs4_operation(&op->nfs_argop4_u.opaccess);
        case rpcgen::OP_CLOSE:               return nfs4_operation(&op->nfs_argop4_u.opclose);
        case rpcgen::OP_COMMIT:              return nfs4_operation(&op->nfs_argop4_u.opcommit);
        case rpcgen::OP_CREATE:              return nfs4_operation(&op->nfs_argop4_u.opcreate);
        case rpcgen::OP_DELEGPURGE:          return nfs4_operation(&op->nfs_argop4_u.opdelegpurge);
        case rpcgen::OP_DELEGRETURN:         return nfs4_operation(&op->nfs_argop4_u.opdelegreturn);
        case rpcgen::OP_GETATTR:             return nfs4_operation(&op->nfs_argop4_u.opgetattr);
        case rpcgen::OP_GETFH:               break; /* no such operation in call procedure */
        case rpcgen::OP_LINK:                return nfs4_operation(&op->nfs_argop4_u.oplink);
        case rpcgen::OP_LOCK:                return nfs4_operation(&op->nfs_argop4_u.oplock);
        case rpcgen::OP_LOCKT:               return nfs4_operation(&op->nfs_argop4_u.oplockt);
        case rpcgen::OP_LOCKU:               return nfs4_operation(&op->nfs_argop4_u.oplocku);
        case rpcgen::OP_LOOKUP:              return nfs4_operation(&op->nfs_argop4_u.oplookup);
        case rpcgen::OP_LOOKUPP:             break; /* no such operation in call procedure */
        case rpcgen::OP_NVERIFY:             return nfs4_operation(&op->nfs_argop4_u.opnverify);
        case rpcgen::OP_OPEN:                return nfs4_operation(&op->nfs_argop4_u.opopen);
        case rpcgen::OP_OPENATTR:            return nfs4_operation(&op->nfs_argop4_u.opopenattr);
        case rpcgen::OP_OPEN_CONFIRM:        return nfs4_operation(&op->nfs_argop4_u.opopen_confirm);
        case rpcgen::OP_OPEN_DOWNGRADE:      return nfs4_operation(&op->nfs_argop4_u.opopen_downgrade);
        case rpcgen::OP_PUTFH:               return nfs4_operation(&op->nfs_argop4_u.opputfh);
        case rpcgen::OP_PUTPUBFH:            break; /* no such operation in call procedure */
        case rpcgen::OP_PUTROOTFH:           break; /* no such operation in call procedure */
        case rpcgen::OP_READ:                return nfs4_operation(&op->nfs_argop4_u.opread);
        case rpcgen::OP_READDIR:             return nfs4_operation(&op->nfs_argop4_u.opreaddir);
        case rpcgen::OP_READLINK:            break; /* no such operation in call procedure */
        case rpcgen::OP_REMOVE:              return nfs4_operation(&op->nfs_argop4_u.opremove);
        case rpcgen::OP_RENAME:              return nfs4_operation(&op->nfs_argop4_u.oprename);
        case rpcgen::OP_RENEW:               return nfs4_operation(&op->nfs_argop4_u.oprenew);
        case rpcgen::OP_RESTOREFH:           break; /* no such operation in call procedure */
        case rpcgen::OP_SAVEFH:              break; /* no such operation in call procedure */
        case rpcgen::OP_SECINFO:             return nfs4_operation(&op->nfs_argop4_u.opsecinfo);
        case rpcgen::OP_SETATTR:             return nfs4_operation(&op->nfs_argop4_u.opsetattr);
        case rpcgen::OP_SETCLIENTID:         return nfs4_operation(&op->nfs_argop4_u.opsetclientid);
        case rpcgen::OP_SETCLIENTID_CONFIRM: return nfs4_operation(&op->nfs_argop4_u.opsetclientid_confirm);
        case rpcgen::OP_VERIFY:              return nfs4_operation(&op->nfs_argop4_u.opverify);
        case rpcgen::OP_WRITE:               return nfs4_operation(&op->nfs_argop4_u.opwrite);
        case rpcgen::OP_RELEASE_LOCKOWNER:   return nfs4_operation(&op->nfs_argop4_u.oprelease_lockowner);
        case rpcgen::OP_GET_DIR_DELEGATION:  return nfs4_operation(&op->nfs_argop4_u.opget_dir_delegation);
        case rpcgen::OP_ILLEGAL:             break; /* no such operation in call procedure */
        }//switch
    out << " ]";
    }//if
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::nfs_resop4* op)
{
    if(op)
    {
    out << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(op->resop))
        << "(" << op->resop << ") [ ";
        switch(op->resop)
        {
        case rpcgen::OP_ACCESS:              return nfs4_operation(&op->nfs_resop4_u.opaccess);
        case rpcgen::OP_CLOSE:               return nfs4_operation(&op->nfs_resop4_u.opclose);
        case rpcgen::OP_COMMIT:              return nfs4_operation(&op->nfs_resop4_u.opcommit);
        case rpcgen::OP_CREATE:              return nfs4_operation(&op->nfs_resop4_u.opcreate);
        case rpcgen::OP_DELEGPURGE:          return nfs4_operation(&op->nfs_resop4_u.opdelegpurge);
        case rpcgen::OP_DELEGRETURN:         return nfs4_operation(&op->nfs_resop4_u.opdelegreturn);
        case rpcgen::OP_GETATTR:             return nfs4_operation(&op->nfs_resop4_u.opgetattr);
        case rpcgen::OP_GETFH:               return nfs4_operation(&op->nfs_resop4_u.opgetfh);
        case rpcgen::OP_LINK:                return nfs4_operation(&op->nfs_resop4_u.oplink);
        case rpcgen::OP_LOCK:                return nfs4_operation(&op->nfs_resop4_u.oplock);
        case rpcgen::OP_LOCKT:               return nfs4_operation(&op->nfs_resop4_u.oplockt);
        case rpcgen::OP_LOCKU:               return nfs4_operation(&op->nfs_resop4_u.oplocku);
        case rpcgen::OP_LOOKUP:              return nfs4_operation(&op->nfs_resop4_u.oplookup);
        case rpcgen::OP_LOOKUPP:             return nfs4_operation(&op->nfs_resop4_u.oplookupp);
        case rpcgen::OP_NVERIFY:             return nfs4_operation(&op->nfs_resop4_u.opnverify);
        case rpcgen::OP_OPEN:                return nfs4_operation(&op->nfs_resop4_u.opopen);
        case rpcgen::OP_OPENATTR:            return nfs4_operation(&op->nfs_resop4_u.opopenattr);
        case rpcgen::OP_OPEN_CONFIRM:        return nfs4_operation(&op->nfs_resop4_u.opopen_confirm);
        case rpcgen::OP_OPEN_DOWNGRADE:      return nfs4_operation(&op->nfs_resop4_u.opopen_downgrade);
        case rpcgen::OP_PUTFH:               return nfs4_operation(&op->nfs_resop4_u.opputfh);
        case rpcgen::OP_PUTPUBFH:            return nfs4_operation(&op->nfs_resop4_u.opputpubfh);
        case rpcgen::OP_PUTROOTFH:           return nfs4_operation(&op->nfs_resop4_u.opputrootfh);
        case rpcgen::OP_READ:                return nfs4_operation(&op->nfs_resop4_u.opread);
        case rpcgen::OP_READDIR:             return nfs4_operation(&op->nfs_resop4_u.opreaddir);
        case rpcgen::OP_READLINK:            return nfs4_operation(&op->nfs_resop4_u.opreadlink);
        case rpcgen::OP_REMOVE:              return nfs4_operation(&op->nfs_resop4_u.opremove);
        case rpcgen::OP_RENAME:              return nfs4_operation(&op->nfs_resop4_u.oprename);
        case rpcgen::OP_RENEW:               return nfs4_operation(&op->nfs_resop4_u.oprenew);
        case rpcgen::OP_RESTOREFH:           return nfs4_operation(&op->nfs_resop4_u.oprestorefh);
        case rpcgen::OP_SAVEFH:              return nfs4_operation(&op->nfs_resop4_u.opsavefh);
        case rpcgen::OP_SECINFO:             return nfs4_operation(&op->nfs_resop4_u.opsecinfo);
        case rpcgen::OP_SETATTR:             return nfs4_operation(&op->nfs_resop4_u.opsetattr);
        case rpcgen::OP_SETCLIENTID:         return nfs4_operation(&op->nfs_resop4_u.opsetclientid);
        case rpcgen::OP_SETCLIENTID_CONFIRM: return nfs4_operation(&op->nfs_resop4_u.opsetclientid_confirm);
        case rpcgen::OP_VERIFY:              return nfs4_operation(&op->nfs_resop4_u.opverify);
        case rpcgen::OP_WRITE:               return nfs4_operation(&op->nfs_resop4_u.opwrite);
        case rpcgen::OP_RELEASE_LOCKOWNER:   return nfs4_operation(&op->nfs_resop4_u.oprelease_lockowner);
        case rpcgen::OP_GET_DIR_DELEGATION:  return nfs4_operation(&op->nfs_resop4_u.opget_dir_delegation);
        case rpcgen::OP_ILLEGAL:             return nfs4_operation(&op->nfs_resop4_u.opillegal);
        }//switch
    out << " ]";
    }//if
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::ACCESS4args* args)
{
    if(args)
    {
        if ((args->access) & ACCESS4_READ)    out << "READ ";
        if ((args->access) & ACCESS4_LOOKUP)  out << "LOOKUP ";
        if ((args->access) & ACCESS4_MODIFY)  out << "MODIFY ";
        if ((args->access) & ACCESS4_EXTEND)  out << "EXTEND ";
        if ((args->access) & ACCESS4_DELETE)  out << "DELETE ";
        if ((args->access) & ACCESS4_EXECUTE) out << "EXECUTE ";
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::ACCESS4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
        {
            out << " supported: ";
            if ((res->ACCESS4res_u.resok4.supported) & ACCESS4_READ)    out << "READ ";
            if ((res->ACCESS4res_u.resok4.supported) & ACCESS4_LOOKUP)  out << "LOOKUP ";
            if ((res->ACCESS4res_u.resok4.supported) & ACCESS4_MODIFY)  out << "MODIFY ";
            if ((res->ACCESS4res_u.resok4.supported) & ACCESS4_EXTEND)  out << "EXTEND ";
            if ((res->ACCESS4res_u.resok4.supported) & ACCESS4_DELETE)  out << "DELETE ";
            if ((res->ACCESS4res_u.resok4.supported) & ACCESS4_EXECUTE) out << "EXECUTE ";
            out << " access: ";
            if ((res->ACCESS4res_u.resok4.access) & ACCESS4_READ)    out << "READ ";
            if ((res->ACCESS4res_u.resok4.access) & ACCESS4_LOOKUP)  out << "LOOKUP ";
            if ((res->ACCESS4res_u.resok4.access) & ACCESS4_MODIFY)  out << "MODIFY ";
            if ((res->ACCESS4res_u.resok4.access) & ACCESS4_EXTEND)  out << "EXTEND ";
            if ((res->ACCESS4res_u.resok4.access) & ACCESS4_DELETE)  out << "DELETE ";
            if ((res->ACCESS4res_u.resok4.access) & ACCESS4_EXECUTE) out << "EXECUTE ";
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::CLOSE4args* args)
{
    if(args) out <<  "seqid: 0x"       << std::hex << args->seqid << std::dec
                 << " open state id:" << args->open_stateid;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::CLOSE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << " open state id:" << res->CLOSE4res_u.open_stateid;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::COMMIT4args* args)
{
    if(args) out <<  "offset: " << args->offset
                 << " count: "  << args->count;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::COMMIT4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
        {
            out << " write verifier: ";
            print_hex(out, res->COMMIT4res_u.resok4.writeverf, rpcgen::NFS4_VERIFIER_SIZE);
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::CREATE4args* args)
{
    if(args) out <<  "object type: "       << args->objtype
                 << " object name: "       << args->objname
                 << " create attributes: " << args->createattrs;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::CREATE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << res->CREATE4res_u.resok4.cinfo << ' '
                << res->CREATE4res_u.resok4.attrset;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::DELEGPURGE4args* args)
{
    if(args) out << "client id: 0x" << std::hex << args->clientid << std::dec;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::DELEGPURGE4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::DELEGRETURN4args* args)
{
    if(args) out << args->deleg_stateid;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::DELEGRETURN4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::GETATTR4args* args)
{
    if(args) out << args->attr_request;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::GETATTR4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << ' ' << res->GETATTR4res_u.resok4.obj_attributes;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LINK4args* args)
{
    if(args) out << "new name: " << args->newname;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LINK4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << ' ' << res->LINK4res_u.resok4.cinfo;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LOCK4args* args)
{
    if(args) out <<  "lock type: " << args->locktype
                 << " reclaim: "   << args->reclaim
                 << " offset: "    << args->offset
                 << " length: "    << args->length
                 << " locker: "    << args->locker;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LOCK4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all())
        {
            switch(res->status)
            {
            case rpcgen::nfsstat4::NFS4_OK:
                out << " lock stat id: " << res->LOCK4res_u.resok4.lock_stateid; break;
            case rpcgen::nfsstat4::NFS4ERR_DENIED:
                out << " offset: "    << res->LOCK4res_u.denied.offset
                    << " length: "    << res->LOCK4res_u.denied.length
                    << " lock type: " << res->LOCK4res_u.denied.locktype
                    << " owner: "     << res->LOCK4res_u.denied.owner;           break;
            default: break;
            }
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LOCKT4args* args)
{
    if(args) out <<  "lock type: " << args->locktype
                 << " offset: "    << args->offset
                 << " length: "    << args->length
                 << " owner: "     << args->owner;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LOCKT4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4ERR_DENIED)
            out << " offset: "    << res->LOCKT4res_u.denied.offset
                << " length: "    << res->LOCKT4res_u.denied.length
                << " lock type: " << res->LOCKT4res_u.denied.locktype
                << " owner: "     << res->LOCKT4res_u.denied.owner;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LOCKU4args* args)
{
    if(args) out <<  "lock type: "     << args->locktype
                 << " seqid: 0x"       << std::hex << args->seqid << std::dec
                 << " lock state id: " << args->lock_stateid
                 << " offset: "        << args->offset
                 << " length: "        << args->length;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LOCKU4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << " lock state id: " << res->LOCKU4res_u.lock_stateid;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LOOKUP4args* args)
{
    if(args) out << "object name: " << args->objname;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LOOKUP4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::NVERIFY4args* args)
{
    if(args) out << "object attributes: " << args->obj_attributes;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::NVERIFY4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::OPEN4args* args)
{
    static const char* const open4_share_access[4] = {"",    "READ","WRITE","BOTH"};
    static const char* const open4_share_deny[4]   = {"NONE","READ","WRITE","BOTH"};

    if(args) out <<  "seqid: 0x" << std::hex << args->seqid << std::dec
                 << " share access: " << open4_share_access[args->share_access]
                 << " share deny: "   << open4_share_deny[args->share_deny] << ' '
                 <<  args->owner << ' '
                 <<  args->openhow << ' '
                 <<  args->claim;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::OPEN4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << res->OPEN4res_u.resok4.stateid
                << res->OPEN4res_u.resok4.cinfo
                << " results flags: 0x" << std::hex << res->OPEN4res_u.resok4.rflags << ' '  << std::dec
                << res->OPEN4res_u.resok4.attrset << ' '
                << res->OPEN4res_u.resok4.delegation;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::OPENATTR4args* args)
{
    if(args) out << "create directory: " << args->createdir;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::OPENATTR4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::OPEN_CONFIRM4args* args)
{
    if(args) out << "open state id:" << args->open_stateid
                 << " seqid: 0x"     << std::hex << args->seqid << std::dec;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::OPEN_CONFIRM4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << " open state id:" << res->OPEN_CONFIRM4res_u.resok4.open_stateid;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::OPEN_DOWNGRADE4args* args)
{
    if(args) out << " open state id: " << args->open_stateid
                 << " seqid: 0x"       << std::hex << args->seqid << std::dec
                 << " share access: "  << args->share_access
                 << " share deny: "    << args->share_deny;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::OPEN_DOWNGRADE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << ' ' << res->OPEN_DOWNGRADE4res_u.resok4.open_stateid;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::PUTFH4args* args)
{
    if(args)
    {
        out << "object: ";
        print_nfs_fh(out, args->object.nfs_fh4_val, args->object.nfs_fh4_len);
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::PUTFH4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::READ4args* args)
{
    if(args) out << args->stateid
                 << " offset: "   << args->offset
                 << " count: "    << args->count;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::READ4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
        {
            out << " eof: " << res->READ4res_u.resok4.eof;
            if(res->READ4res_u.resok4.data.data_len)
                out << " data : " << *res->READ4res_u.resok4.data.data_val;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::READDIR4args* args)
{
    if(args) out <<  "cookie: "             << args->cookie
                 << " cookieverf: "         << args->cookieverf
                 << " dir count: "          << args->dircount
                 << " max count: "          << args->maxcount
                 << " attributes request: " << args->attr_request;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::READDIR4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << " cookie verifier: " << res->READDIR4res_u.resok4.cookieverf
                << " reply: "           << res->READDIR4res_u.resok4.reply;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::REMOVE4args* args)
{
    if(args) out << "target: " << args->target;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::REMOVE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << ' ' << res->REMOVE4res_u.resok4.cinfo;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::RENAME4args* args)
{
    if(args) out <<  "old name: " << args->oldname
                 << " new name: " << args->newname;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::RENAME4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << " source: " << res->RENAME4res_u.resok4.source_cinfo
                << " target: " << res->RENAME4res_u.resok4.target_cinfo;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::RENEW4args* args)
{
    if(args) out << "client id: " << args->clientid;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::RENEW4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::SECINFO4args* args)
{
    if(args) out << "name: " << args->name;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::SECINFO4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
        {
            if(res->SECINFO4res_u.resok4.SECINFO4resok_len)
                out << " data : " << *res->SECINFO4res_u.resok4.SECINFO4resok_val;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::SETATTR4args* args)
{
    if(args) out <<  "state id:" << args->stateid << ' '
                 <<  args->obj_attributes;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::SETATTR4res*  res)
{
    if(res)
    {
        out <<  "status: " << res->status << ' ';
        if(out_all())  out << res->attrsset;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::SETCLIENTID4args* args)
{
    if(args) out <<  "client: "         << args->client
                 << " callback: "       << args->callback
                 << " callback ident: " << args->callback_ident;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::SETCLIENTID4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all())
        {
            switch(res->status)
            {
            case rpcgen::nfsstat4::NFS4_OK:
                out << " client id: " << res->SETCLIENTID4res_u.resok4.clientid
                    << " set client if confirm: "
                    << res->SETCLIENTID4res_u.resok4.setclientid_confirm;        break;
            case rpcgen::nfsstat4::NFS4ERR_CLID_INUSE:
                out << " client using: " << res->SETCLIENTID4res_u.client_using; break;
            default: break;
            }
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::SETCLIENTID_CONFIRM4args* args)
{
    if(args) out << " client id: "             << args->clientid
                 << " set client if confirm: " << args->setclientid_confirm;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::SETCLIENTID_CONFIRM4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::VERIFY4args* args)
{
    if(args) out << "object attributes: " << args->obj_attributes;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::VERIFY4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::WRITE4args* args)
{
    if(args)
    {
        out << args->stateid
            << " offset: "      << args->offset
            << " stable: "      << args->stable
            << " data length: " << args->data.data_len;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::WRITE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
        {
            out << " count: "          << res->WRITE4res_u.resok4.count
                << " commited: "       << res->WRITE4res_u.resok4.committed
                << " write verifier: ";
            print_hex(out, res->WRITE4res_u.resok4.writeverf, rpcgen::NFS4_VERIFIER_SIZE);
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::RELEASE_LOCKOWNER4args* args)
{
    if(args) out << "lock owner: " << args->lock_owner;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::RELEASE_LOCKOWNER4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::GET_DIR_DELEGATION4args* args)
{
    if(args)
        out <<  "client id: "                    << args->clientid
            << " notification types: "           << args->notif_types
            << " dir notification delay: "       << args->dir_notif_delay
            << " dir entry notification delay: " << args->dir_entry_notif_delay;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::GET_DIR_DELEGATION4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << ' ' << res->GET_DIR_DELEGATION4res_u.resok4.stateid
                << " status: " << res->GET_DIR_DELEGATION4res_u.resok4.status
                << " notification types: " << res->GET_DIR_DELEGATION4res_u.resok4.notif_types
                << " dir: "       << res->GET_DIR_DELEGATION4res_u.resok4.dir_notif_attrs
                << " dir entry: " << res->GET_DIR_DELEGATION4res_u.resok4.dir_entry_notif_attrs;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::GETFH4res* res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << " object: " << res->GETFH4res_u.resok4.object;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::LOOKUPP4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::PUTPUBFH4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::PUTROOTFH4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::READLINK4res* res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == rpcgen::nfsstat4::NFS4_OK)
            out << " link: " << res->READLINK4res_u.resok4.link;
    }
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::RESTOREFH4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::SAVEFH4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct rpcgen::ILLEGAL4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::flush_statistics()
{
    // flush is in each handler
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
