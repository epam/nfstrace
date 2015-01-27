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
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

using namespace NST::protocols::NFS;  // NFS helpers
using namespace NST::protocols::NFS3; // NFSv3 helpers
using namespace NST::protocols::NFS4; // NFSv4 helpers
namespace NFS3  = NST::API::NFS3;
namespace NFS4  = NST::API::NFS4;
namespace NFS41 = NST::API::NFS41;

namespace
{

bool print_procedure(std::ostream& out, const RPCProcedure* proc)
{
    bool result {false};
    NST::utils::operator<<(out, *(proc->session));

    auto& call = proc->call;
    const unsigned long nfs_version {call.ru.RM_cmb.cb_vers};
    if(out_all())
    {
        out << " XID: "         << call.rm_xid
            << " RPC version: " << call.ru.RM_cmb.cb_rpcvers
            << " RPC program: " << call.ru.RM_cmb.cb_prog
            << " version: "     << nfs_version << ' ';
    }
    switch(nfs_version)
    {
    case NFS_V3:
        out << print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(call.ru.RM_cmb.cb_proc));
        break;
    case NFS_V4:
        out << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(call.ru.RM_cmb.cb_proc));
        break;
    }

    // check procedure reply
    auto& reply = proc->reply;
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
                    << " low: "
                    << reply.ru.RM_rmb.ru.RP_dr.ru.RJ_versions.low
                    << " high: "
                    << reply.ru.RM_rmb.ru.RP_dr.ru.RJ_versions.high;
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

void PrintAnalyzer::null(const RPCProcedure* proc,
                         const struct NFS3::NULL3args*,
                         const struct NFS3::NULL3res*)
{
    if(!print_procedure(out, proc)) return;
    out << "\tCALL  []\n\tREPLY []\n";
}

void PrintAnalyzer::getattr3(const RPCProcedure*              proc,
                             const struct NFS3::GETATTR3args* args,
                             const struct NFS3::GETATTR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  ["
                 << " object: " << args->object
                 << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all() && res->status == NFS3::nfsstat3::NFS3_OK)
            out << " obj attributes: "
                << res->GETATTR3res_u.resok.obj_attributes;
        out << " ]\n";
    }
}

void PrintAnalyzer::setattr3(const RPCProcedure*              proc,
                             const struct NFS3::SETATTR3args* args,
                             const struct NFS3::SETATTR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  [ object: " << args->object
                 << " new attributes: "  << args->new_attributes
                 << " guard: "           << args->guard
                 << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj_wcc: "
                    << res->SETATTR3res_u.resok.obj_wcc;
            else
                out << " obj_wcc: "
                    << res->SETATTR3res_u.resfail.obj_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::lookup3(const RPCProcedure*             proc,
                            const struct NFS3::LOOKUP3args* args,
                            const struct NFS3::LOOKUP3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  [ what: " << args->what << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " object: "
                    << res->LOOKUP3res_u.resok.object
                    << " object attributes: "
                    << res->LOOKUP3res_u.resok.obj_attributes
                    << " dir attributes: "
                    << res->LOOKUP3res_u.resok.dir_attributes;
            else
                out << " dir attributes: "
                    << res->LOOKUP3res_u.resfail.dir_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::access3(const RPCProcedure*             proc,
                            const struct NFS3::ACCESS3args* args,
                            const struct NFS3::ACCESS3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [ object: ";
        print_nfs_fh(out,
                     args->object.data.data_val,
                     args->object.data.data_len);
        out << " access: ";
        print_access3(out, args->access);
        out << " ]\n";
    }

    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " object attributes: "
                    << res->ACCESS3res_u.resok.obj_attributes
                    << " access: ";
                print_access3(out, res->ACCESS3res_u.resok.access);
            }
            else
            {
                out << " access: "
                    << res->ACCESS3res_u.resfail.obj_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readlink3(const RPCProcedure*               proc,
                              const struct NFS3::READLINK3args* args,
                              const struct NFS3::READLINK3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  [ symlink: " << args->symlink << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " symlink attributes: "
                    << res->READLINK3res_u.resok.symlink_attributes
                    << " data: "
                    << res->READLINK3res_u.resok.data;
            else
                out << " symlink attributes: "
                    << res->READLINK3res_u.resfail.symlink_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::read3(const RPCProcedure*           proc,
                          const struct NFS3::READ3args* args,
                          const struct NFS3::READ3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args) out << "\tCALL  [ file: " << args->file
                 << " offset: " << args->offset
                 << " count: "  << args->count
                 << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " file attributes: "
                    << res->READ3res_u.resok.file_attributes
                    << " count: "
                    << res->READ3res_u.resok.count
                    << " eof: "
                    << res->READ3res_u.resok.eof;
            }
            else
            {
                out << " symlink attributes: "
                    << res->READ3res_u.resfail.file_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::write3(const RPCProcedure*            proc,
                           const struct NFS3::WRITE3args* args,
                           const struct NFS3::WRITE3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [ file: " << args->file
            << " offset: " << args->offset
            << " count: "  << args->count
            << " stable: " << args->stable
            << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " file_wcc: "
                    << res->WRITE3res_u.resok.file_wcc
                    << " count: "
                    << res->WRITE3res_u.resok.count
                    << " committed: "
                    << res->WRITE3res_u.resok.committed
                    << " verf: ";
                print_hex(out,
                          res->WRITE3res_u.resok.verf,
                          NFS3::NFS3_WRITEVERFSIZE);
            }
            else
            {
                out << " file_wcc: "
                    << res->WRITE3res_u.resfail.file_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::create3(const RPCProcedure*             proc,
                            const struct NFS3::CREATE3args* args,
                            const struct NFS3::CREATE3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ where: " << args->where
            << " how: " << args->how
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj: "
                    << res->CREATE3res_u.resok.obj
                    << " obj attributes: "
                    << res->CREATE3res_u.resok.obj_attributes
                    << " dir_wcc: "
                    << res->CREATE3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->CREATE3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::mkdir3(const RPCProcedure*            proc,
                           const struct NFS3::MKDIR3args* args,
                           const struct NFS3::MKDIR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ where: " << args->where
            << " attributes: "     << args->attributes
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj: "
                    << res->MKDIR3res_u.resok.obj
                    << " obj attributes: "
                    << res->MKDIR3res_u.resok.obj_attributes
                    << " dir_wcc: "
                    << res->MKDIR3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->MKDIR3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::symlink3(const RPCProcedure*              proc,
                             const struct NFS3::SYMLINK3args* args,
                             const struct NFS3::SYMLINK3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ where: " << args->where
            << " symlink: "        << args->symlink
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj: "
                    << res->SYMLINK3res_u.resok.obj
                    << " obj attributes: "
                    << res->SYMLINK3res_u.resok.obj_attributes
                    << " dir_wcc: "
                    << res->SYMLINK3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->SYMLINK3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::mknod3(const RPCProcedure*            proc,
                           const struct NFS3::MKNOD3args* args,
                           const struct NFS3::MKNOD3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [ where: " << args->where
            << " what: "           << args->what
            << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj: "
                    << res->MKNOD3res_u.resok.obj
                    << " obj attributes: "
                    << res->MKNOD3res_u.resok.obj_attributes
                    << " dir_wcc: "
                    << res->MKNOD3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->MKNOD3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::remove3(const RPCProcedure*             proc,
                            const struct NFS3::REMOVE3args* args,
                            const struct NFS3::REMOVE3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ object: " << args->object << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " dir_wcc: "
                    << res->REMOVE3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->REMOVE3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::rmdir3(const RPCProcedure*            proc,
                           const struct NFS3::RMDIR3args* args,
                           const struct NFS3::RMDIR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [ object: " << args->object << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " dir_wcc: "
                    << res->RMDIR3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->RMDIR3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::rename3(const RPCProcedure*             proc,
                            const struct NFS3::RENAME3args* args,
                            const struct NFS3::RENAME3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ from: " << args->from
            << " to: "            << args->to
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " from dir_wcc: "
                    << res->RENAME3res_u.resok.fromdir_wcc
                    << " to dir_wcc: "
                    << res->RENAME3res_u.resok.todir_wcc;
            else
                out << " from dir_wcc: "
                    << res->RENAME3res_u.resfail.fromdir_wcc
                    << " to dir_wcc: "
                    << res->RENAME3res_u.resfail.todir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::link3(const RPCProcedure*           proc,
                          const struct NFS3::LINK3args* args,
                          const struct NFS3::LINK3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ file: " << args->file
            << " link: "          << args->link
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " file attributes: "
                    << res->LINK3res_u.resok.file_attributes
                    << " link dir_wcc: "
                    << res->LINK3res_u.resok.linkdir_wcc;
            else
                out << " file attributes: "
                    << res->LINK3res_u.resfail.file_attributes
                    << " link dir_wcc: "
                    << res->LINK3res_u.resfail.linkdir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readdir3(const RPCProcedure*              proc,
                             const struct NFS3::READDIR3args* args,
                             const struct NFS3::READDIR3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [ dir: " << args->dir
            << " cookie: "       << args->cookie
            << " cookieverf: ";
        print_hex(out,
                  args->cookieverf,
                  NFS3::NFS3_COOKIEVERFSIZE);
        out << " count: " << args->count
            << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " dir attributes: "
                    << res->READDIR3res_u.resok.dir_attributes
                    << " cookieverf: ";
                print_hex(out,
                          res->READDIR3res_u.resok.cookieverf,
                          NFS3::NFS3_COOKIEVERFSIZE);
                out << " reply: "
                    << res->READDIR3res_u.resok.reply;
            }
            else
            {
                out << " dir attributes: "
                    << res->READDIR3res_u.resfail.dir_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readdirplus3(const RPCProcedure*                  proc,
                                 const struct NFS3::READDIRPLUS3args* args,
                                 const struct NFS3::READDIRPLUS3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
    {
        out << "\tCALL  [ dir: " << args->dir
            << " cookie: "       << args->cookie
            << " cookieverf: ";
        print_hex(out,
                  args->cookieverf,
                  NFS3::NFS3_COOKIEVERFSIZE);
        out << " dir count: " << args->dircount
            << " max count: " << args->maxcount
            << " ]\n";
    }
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " dir attributes: "
                    << res->READDIRPLUS3res_u.resok.dir_attributes
                    << " cookieverf: ";
                print_hex(out,
                          res->READDIRPLUS3res_u.resok.cookieverf,
                          NFS3::NFS3_COOKIEVERFSIZE);
                out << " reply: "
                    << res->READDIRPLUS3res_u.resok.reply;
            }
            else
            {
                out << " dir attributes: "
                    << res->READDIRPLUS3res_u.resfail.dir_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::fsstat3(const RPCProcedure*             proc,
                            const struct NFS3::FSSTAT3args* args,
                            const struct NFS3::FSSTAT3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ fsroot: " << args->fsroot << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj attributes: "
                    << res->FSSTAT3res_u.resok.obj_attributes
                    << " tbytes: "
                    << res->FSSTAT3res_u.resok.tbytes
                    << " fbytes: "
                    << res->FSSTAT3res_u.resok.fbytes
                    << " abytes: "
                    << res->FSSTAT3res_u.resok.abytes
                    << " tfile: "
                    << res->FSSTAT3res_u.resok.tfiles
                    << " ffile: "
                    << res->FSSTAT3res_u.resok.ffiles
                    << " afile: "
                    << res->FSSTAT3res_u.resok.afiles
                    << " invarsec: "
                    << res->FSSTAT3res_u.resok.invarsec;
            else
                out << " obj attributes: "
                    << res->FSSTAT3res_u.resfail.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::fsinfo3(const RPCProcedure*             proc,
                            const struct NFS3::FSINFO3args* args,
                            const struct NFS3::FSINFO3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ fsroot: " << args->fsroot << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj attributes: "
                    << res->FSINFO3res_u.resok.obj_attributes
                    << " rtmax: "
                    << res->FSINFO3res_u.resok.rtmax
                    << " rtpref: "
                    << res->FSINFO3res_u.resok.rtpref
                    << " rtmult: "
                    << res->FSINFO3res_u.resok.rtmult
                    << " wtmax: "
                    << res->FSINFO3res_u.resok.wtmax
                    << " wtpref: "
                    << res->FSINFO3res_u.resok.wtpref
                    << " wtmult: "
                    << res->FSINFO3res_u.resok.wtmult
                    << " dtpref: "
                    << res->FSINFO3res_u.resok.dtpref
                    << " max file size: "
                    << res->FSINFO3res_u.resok.maxfilesize
                    << " time delta: "
                    << res->FSINFO3res_u.resok.time_delta
                    << " properties: "
                    << res->FSINFO3res_u.resok.properties
                    << " LINK (filesystem supports hard links): "
                    << static_cast<bool>(res->FSINFO3res_u.resok.properties &
                                         NFS3::FSF3_LINK)
                    << " SYMLINK (file system supports symbolic links): "
                    << static_cast<bool>(res->FSINFO3res_u.resok.properties &
                                         NFS3::FSF3_SYMLINK)
                    << " HOMOGENEOUS (PATHCONF: is valid for all files): "
                    << static_cast<bool>(res->FSINFO3res_u.resok.properties &
                                         NFS3::FSF3_HOMOGENEOUS)
                    << " CANSETTIME (SETATTR can set time on server): "
                    << static_cast<bool>(res->FSINFO3res_u.resok.properties &
                                         NFS3::FSF3_CANSETTIME);
            else
                out << " obj attributes: "
                    << res->FSINFO3res_u.resfail.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::pathconf3(const RPCProcedure*               proc,
                              const struct NFS3::PATHCONF3args* args,
                              const struct NFS3::PATHCONF3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ object: " << args->object << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj attributes: "
                    << res->PATHCONF3res_u.resok.obj_attributes
                    << " link max: "
                    << res->PATHCONF3res_u.resok.linkmax
                    << " name max: "
                    << res->PATHCONF3res_u.resok.name_max
                    << " no trunc: "
                    << res->PATHCONF3res_u.resok.no_trunc
                    << " chwon restricted: "
                    << res->PATHCONF3res_u.resok.chown_restricted
                    << " case insensitive: "
                    << res->PATHCONF3res_u.resok.case_insensitive
                    << " case preserving: "
                    << res->PATHCONF3res_u.resok.case_preserving;
            else
                out << " obj attributes: "
                    << res->PATHCONF3res_u.resfail.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::commit3(const RPCProcedure*             proc,
                            const struct NFS3::COMMIT3args* args,
                            const struct NFS3::COMMIT3res*  res)
{
    if(!print_procedure(out, proc)) return;

    if(args)
        out << "\tCALL  [ file: " << args->file
            << " offset: "        << args->offset
            << " count: "         << args->count
            << " ]\n";
    if(res)
    {
        out << "\tREPLY [ status: " << res->status;
        if(out_all())
        {
            if(res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " file_wcc: "
                    << res->COMMIT3res_u.resok.file_wcc
                    << " verf: ";
                print_hex(out,
                          res->COMMIT3res_u.resok.verf,
                          NFS3::NFS3_WRITEVERFSIZE);
            }
            else
            {
                out << " file_wcc: "
                    << res->COMMIT3res_u.resfail.file_wcc;
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

void PrintAnalyzer::null(const RPCProcedure* proc,
                         const struct NFS4::NULL4args*,
                         const struct NFS4::NULL4res*)
{
    if(!print_procedure(out, proc)) return;

    out << "\tCALL  []\n\tREPLY []\n";
}

void PrintAnalyzer::compound4(const RPCProcedure*               proc,
                              const struct NFS4::COMPOUND4args* args,
                              const struct NFS4::COMPOUND4res*  res)
{
    if(!print_procedure(out, proc)) return;

    const u_int* array_len {};
    if(args)
    {
        array_len = &args->argarray.argarray_len;
        out << "\tCALL  [ operations: " << *array_len
            << " tag: "                 << args->tag
            << " minor version: "       << args->minorversion;
        if(*array_len)
        {
            NFS4::nfs_argop4* current_el {args->argarray.argarray_val};
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
        out << "\tREPLY [  operations: " << *array_len;
        if(*array_len)
        {
            NFS4::nfs_resop4* current_el {res->resarray.resarray_val};
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

void PrintAnalyzer::nfs4_operation(const struct NFS4::nfs_argop4* op)
{
    if(op)
    {
    out << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(op->argop))
        << '(' << op->argop << ") [ ";
        switch(op->argop)
        {
        case NFS4::OP_ACCESS:
             return nfs4_operation(&op->nfs_argop4_u.opaccess);
        case NFS4::OP_CLOSE:
             return nfs4_operation(&op->nfs_argop4_u.opclose);
        case NFS4::OP_COMMIT:
             return nfs4_operation(&op->nfs_argop4_u.opcommit);
        case NFS4::OP_CREATE:
             return nfs4_operation(&op->nfs_argop4_u.opcreate);
        case NFS4::OP_DELEGPURGE:
             return nfs4_operation(&op->nfs_argop4_u.opdelegpurge);
        case NFS4::OP_DELEGRETURN:
             return nfs4_operation(&op->nfs_argop4_u.opdelegreturn);
        case NFS4::OP_GETATTR:
             return nfs4_operation(&op->nfs_argop4_u.opgetattr);
        case NFS4::OP_GETFH:
             break; /* no such operation in call procedure */
        case NFS4::OP_LINK:
             return nfs4_operation(&op->nfs_argop4_u.oplink);
        case NFS4::OP_LOCK:
             return nfs4_operation(&op->nfs_argop4_u.oplock);
        case NFS4::OP_LOCKT:
             return nfs4_operation(&op->nfs_argop4_u.oplockt);
        case NFS4::OP_LOCKU:
             return nfs4_operation(&op->nfs_argop4_u.oplocku);
        case NFS4::OP_LOOKUP:
             return nfs4_operation(&op->nfs_argop4_u.oplookup);
        case NFS4::OP_LOOKUPP:
             break; /* no such operation in call procedure */
        case NFS4::OP_NVERIFY:
             return nfs4_operation(&op->nfs_argop4_u.opnverify);
        case NFS4::OP_OPEN:
             return nfs4_operation(&op->nfs_argop4_u.opopen);
        case NFS4::OP_OPENATTR:
             return nfs4_operation(&op->nfs_argop4_u.opopenattr);
        case NFS4::OP_OPEN_CONFIRM:
             return nfs4_operation(&op->nfs_argop4_u.opopen_confirm);
        case NFS4::OP_OPEN_DOWNGRADE:
             return nfs4_operation(&op->nfs_argop4_u.opopen_downgrade);
        case NFS4::OP_PUTFH:
             return nfs4_operation(&op->nfs_argop4_u.opputfh);
        case NFS4::OP_PUTPUBFH:
             break; /* no such operation in call procedure */
        case NFS4::OP_PUTROOTFH:
             break; /* no such operation in call procedure */
        case NFS4::OP_READ:
             return nfs4_operation(&op->nfs_argop4_u.opread);
        case NFS4::OP_READDIR:
             return nfs4_operation(&op->nfs_argop4_u.opreaddir);
        case NFS4::OP_READLINK:
             break; /* no such operation in call procedure */
        case NFS4::OP_REMOVE:
             return nfs4_operation(&op->nfs_argop4_u.opremove);
        case NFS4::OP_RENAME:
             return nfs4_operation(&op->nfs_argop4_u.oprename);
        case NFS4::OP_RENEW:
             return nfs4_operation(&op->nfs_argop4_u.oprenew);
        case NFS4::OP_RESTOREFH:
             break; /* no such operation in call procedure */
        case NFS4::OP_SAVEFH:
             break; /* no such operation in call procedure */
        case NFS4::OP_SECINFO:
             return nfs4_operation(&op->nfs_argop4_u.opsecinfo);
        case NFS4::OP_SETATTR:
             return nfs4_operation(&op->nfs_argop4_u.opsetattr);
        case NFS4::OP_SETCLIENTID:
             return nfs4_operation(&op->nfs_argop4_u.opsetclientid);
        case NFS4::OP_SETCLIENTID_CONFIRM:
             return nfs4_operation(&op->nfs_argop4_u.opsetclientid_confirm);
        case NFS4::OP_VERIFY:
             return nfs4_operation(&op->nfs_argop4_u.opverify);
        case NFS4::OP_WRITE:
             return nfs4_operation(&op->nfs_argop4_u.opwrite);
        case NFS4::OP_RELEASE_LOCKOWNER:
             return nfs4_operation(&op->nfs_argop4_u.oprelease_lockowner);
        case NFS4::OP_GET_DIR_DELEGATION:
             return nfs4_operation(&op->nfs_argop4_u.opget_dir_delegation);
        case NFS4::OP_ILLEGAL:
             break; /* no such operation in call procedure */
        }
    out << " ]";
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::nfs_resop4* op)
{
    if(op)
    {
    out << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(op->resop))
        << '(' << op->resop << ") [ ";
        switch(op->resop)
        {
        case NFS4::OP_ACCESS:
             return nfs4_operation(&op->nfs_resop4_u.opaccess);
        case NFS4::OP_CLOSE:
             return nfs4_operation(&op->nfs_resop4_u.opclose);
        case NFS4::OP_COMMIT:
             return nfs4_operation(&op->nfs_resop4_u.opcommit);
        case NFS4::OP_CREATE:
             return nfs4_operation(&op->nfs_resop4_u.opcreate);
        case NFS4::OP_DELEGPURGE:
             return nfs4_operation(&op->nfs_resop4_u.opdelegpurge);
        case NFS4::OP_DELEGRETURN:
             return nfs4_operation(&op->nfs_resop4_u.opdelegreturn);
        case NFS4::OP_GETATTR:
             return nfs4_operation(&op->nfs_resop4_u.opgetattr);
        case NFS4::OP_GETFH:
             return nfs4_operation(&op->nfs_resop4_u.opgetfh);
        case NFS4::OP_LINK:
             return nfs4_operation(&op->nfs_resop4_u.oplink);
        case NFS4::OP_LOCK:
             return nfs4_operation(&op->nfs_resop4_u.oplock);
        case NFS4::OP_LOCKT:
             return nfs4_operation(&op->nfs_resop4_u.oplockt);
        case NFS4::OP_LOCKU:
             return nfs4_operation(&op->nfs_resop4_u.oplocku);
        case NFS4::OP_LOOKUP:
             return nfs4_operation(&op->nfs_resop4_u.oplookup);
        case NFS4::OP_LOOKUPP:
             return nfs4_operation(&op->nfs_resop4_u.oplookupp);
        case NFS4::OP_NVERIFY:
             return nfs4_operation(&op->nfs_resop4_u.opnverify);
        case NFS4::OP_OPEN:
             return nfs4_operation(&op->nfs_resop4_u.opopen);
        case NFS4::OP_OPENATTR:
             return nfs4_operation(&op->nfs_resop4_u.opopenattr);
        case NFS4::OP_OPEN_CONFIRM:
             return nfs4_operation(&op->nfs_resop4_u.opopen_confirm);
        case NFS4::OP_OPEN_DOWNGRADE:
             return nfs4_operation(&op->nfs_resop4_u.opopen_downgrade);
        case NFS4::OP_PUTFH:
             return nfs4_operation(&op->nfs_resop4_u.opputfh);
        case NFS4::OP_PUTPUBFH:
             return nfs4_operation(&op->nfs_resop4_u.opputpubfh);
        case NFS4::OP_PUTROOTFH:
             return nfs4_operation(&op->nfs_resop4_u.opputrootfh);
        case NFS4::OP_READ:
             return nfs4_operation(&op->nfs_resop4_u.opread);
        case NFS4::OP_READDIR:
             return nfs4_operation(&op->nfs_resop4_u.opreaddir);
        case NFS4::OP_READLINK:
             return nfs4_operation(&op->nfs_resop4_u.opreadlink);
        case NFS4::OP_REMOVE:
             return nfs4_operation(&op->nfs_resop4_u.opremove);
        case NFS4::OP_RENAME:
             return nfs4_operation(&op->nfs_resop4_u.oprename);
        case NFS4::OP_RENEW:
             return nfs4_operation(&op->nfs_resop4_u.oprenew);
        case NFS4::OP_RESTOREFH:
             return nfs4_operation(&op->nfs_resop4_u.oprestorefh);
        case NFS4::OP_SAVEFH:
             return nfs4_operation(&op->nfs_resop4_u.opsavefh);
        case NFS4::OP_SECINFO:
             return nfs4_operation(&op->nfs_resop4_u.opsecinfo);
        case NFS4::OP_SETATTR:
             return nfs4_operation(&op->nfs_resop4_u.opsetattr);
        case NFS4::OP_SETCLIENTID:
             return nfs4_operation(&op->nfs_resop4_u.opsetclientid);
        case NFS4::OP_SETCLIENTID_CONFIRM:
             return nfs4_operation(&op->nfs_resop4_u.opsetclientid_confirm);
        case NFS4::OP_VERIFY:
             return nfs4_operation(&op->nfs_resop4_u.opverify);
        case NFS4::OP_WRITE:
             return nfs4_operation(&op->nfs_resop4_u.opwrite);
        case NFS4::OP_RELEASE_LOCKOWNER:
             return nfs4_operation(&op->nfs_resop4_u.oprelease_lockowner);
        case NFS4::OP_GET_DIR_DELEGATION:
             return nfs4_operation(&op->nfs_resop4_u.opget_dir_delegation);
        case NFS4::OP_ILLEGAL:
             return nfs4_operation(&op->nfs_resop4_u.opillegal);
        }
    out << " ]";
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::ACCESS4args* args)
{
    if(args)
    {
        if ((args->access) & NFS4::ACCESS4_READ)    out << "READ ";
        if ((args->access) & NFS4::ACCESS4_LOOKUP)  out << "LOOKUP ";
        if ((args->access) & NFS4::ACCESS4_MODIFY)  out << "MODIFY ";
        if ((args->access) & NFS4::ACCESS4_EXTEND)  out << "EXTEND ";
        if ((args->access) & NFS4::ACCESS4_DELETE)  out << "DELETE ";
        if ((args->access) & NFS4::ACCESS4_EXECUTE) out << "EXECUTE ";
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::ACCESS4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " supported: ";
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_READ)
                out << "READ ";
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_LOOKUP)
                out << "LOOKUP ";
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_MODIFY)
                out << "MODIFY ";
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_EXTEND)
                out << "EXTEND ";
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_DELETE)
                out << "DELETE ";
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_EXECUTE)
                out << "EXECUTE ";
            out << " access: ";
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_READ)
                out << "READ ";
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_LOOKUP)
                out << "LOOKUP ";
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_MODIFY)
                out << "MODIFY ";
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_EXTEND)
                out << "EXTEND ";
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_DELETE)
                out << "DELETE ";
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_EXECUTE)
                out << "EXECUTE ";
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::CLOSE4args* args)
{
    if(args) out <<  "seqid: "        << std::hex << args->seqid << std::dec
                 << " open state id:" << args->open_stateid;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::CLOSE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << " open state id:" << res->CLOSE4res_u.open_stateid;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::COMMIT4args* args)
{
    if(args) out <<  "offset: " << args->offset
                 << " count: "  << args->count;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::COMMIT4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " write verifier: ";
            print_hex(out,
                      res->COMMIT4res_u.resok4.writeverf,
                      NFS4::NFS4_VERIFIER_SIZE);
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::CREATE4args* args)
{
    if(args) out <<  "object type: "       << args->objtype
                 << " object name: "       << args->objname
                 << " create attributes: " << args->createattrs;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::CREATE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << res->CREATE4res_u.resok4.cinfo << ' '
                << res->CREATE4res_u.resok4.attrset;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::DELEGPURGE4args* args)
{
    if(args) out << "client id: " << std::hex << args->clientid << std::dec;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::DELEGPURGE4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::DELEGRETURN4args* args)
{
    if(args) out << args->deleg_stateid;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::DELEGRETURN4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GETATTR4args* args)
{
    if(args) out << args->attr_request;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GETATTR4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << ' ' << res->GETATTR4res_u.resok4.obj_attributes;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LINK4args* args)
{
    if(args) out << "new name: " << args->newname;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LINK4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << ' ' << res->LINK4res_u.resok4.cinfo;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCK4args* args)
{
    if(args) out <<  "lock type: " << args->locktype
                 << " reclaim: "   << args->reclaim
                 << " offset: "    << args->offset
                 << " length: "    << args->length
                 << " locker: "    << args->locker;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCK4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all())
        {
            switch(res->status)
            {
            case NFS4::nfsstat4::NFS4_OK:
                out << " lock stat id: "
                    << res->LOCK4res_u.resok4.lock_stateid;
                break;
            case NFS4::nfsstat4::NFS4ERR_DENIED:
                out << " offset: "    << res->LOCK4res_u.denied.offset
                    << " length: "    << res->LOCK4res_u.denied.length
                    << " lock type: " << res->LOCK4res_u.denied.locktype
                    << " owner: "     << res->LOCK4res_u.denied.owner;
                break;
            default: break;
            }
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCKT4args* args)
{
    if(args) out <<  "lock type: " << args->locktype
                 << " offset: "    << args->offset
                 << " length: "    << args->length
                 << " owner: "     << args->owner;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCKT4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4ERR_DENIED)
            out << " offset: "    << res->LOCKT4res_u.denied.offset
                << " length: "    << res->LOCKT4res_u.denied.length
                << " lock type: " << res->LOCKT4res_u.denied.locktype
                << " owner: "     << res->LOCKT4res_u.denied.owner;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCKU4args* args)
{
    if(args) out <<  "lock type: "     << args->locktype
                 << " seqid: "       << std::hex << args->seqid << std::dec
                 << " lock state id: " << args->lock_stateid
                 << " offset: "        << args->offset
                 << " length: "        << args->length;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCKU4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << " lock state id: " << res->LOCKU4res_u.lock_stateid;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOOKUP4args* args)
{
    if(args) out << "object name: " << args->objname;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOOKUP4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::NVERIFY4args* args)
{
    if(args) out << "object attributes: " << args->obj_attributes;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::NVERIFY4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN4args* args)
{
    static const char* const open4_share_access[4] = {"",    "READ","WRITE","BOTH"};
    static const char* const open4_share_deny[4]   = {"NONE","READ","WRITE","BOTH"};

    if(args) out <<  "seqid: " << std::hex << args->seqid << std::dec
                 << " share access: " << open4_share_access[args->share_access]
                 << " share deny: "   << open4_share_deny[args->share_deny]
                 << ' ' << args->owner
                 << ' ' << args->openhow
                 << ' ' << args->claim;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << res->OPEN4res_u.resok4.stateid
                << res->OPEN4res_u.resok4.cinfo
                << " results flags: "
                << std::hex << res->OPEN4res_u.resok4.rflags << std::dec
                << ' ' << res->OPEN4res_u.resok4.attrset
                << ' ' << res->OPEN4res_u.resok4.delegation;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPENATTR4args* args)
{
    if(args) out << "create directory: " << args->createdir;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPENATTR4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN_CONFIRM4args* args)
{
    if(args) out <<  "open state id:" << args->open_stateid
                 << " seqid: "        << std::hex << args->seqid << std::dec;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN_CONFIRM4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << " open state id:" << res->OPEN_CONFIRM4res_u.resok4.open_stateid;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN_DOWNGRADE4args* args)
{
    if(args) out << " open state id: " << args->open_stateid
                 << " seqid: "       << std::hex << args->seqid << std::dec
                 << " share access: "  << args->share_access
                 << " share deny: "    << args->share_deny;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN_DOWNGRADE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << ' ' << res->OPEN_DOWNGRADE4res_u.resok4.open_stateid;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::PUTFH4args* args)
{
    if(args)
    {
        out << "object: ";
        print_nfs_fh(out, args->object.nfs_fh4_val, args->object.nfs_fh4_len);
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::PUTFH4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READ4args* args)
{
    if(args) out << args->stateid
                 << " offset: "   << args->offset
                 << " count: "    << args->count;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READ4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " eof: " << res->READ4res_u.resok4.eof;
            if(res->READ4res_u.resok4.data.data_len)
                out << " data : " << *res->READ4res_u.resok4.data.data_val;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READDIR4args* args)
{
    if(args) out <<  "cookie: "             << args->cookie
                 << " cookieverf: "         << args->cookieverf
                 << " dir count: "          << args->dircount
                 << " max count: "          << args->maxcount
                 << " attributes request: " << args->attr_request;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READDIR4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << " cookie verifier: " << res->READDIR4res_u.resok4.cookieverf
                << " reply: "           << res->READDIR4res_u.resok4.reply;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::REMOVE4args* args)
{
    if(args) out << "target: " << args->target;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::REMOVE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << ' ' << res->REMOVE4res_u.resok4.cinfo;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RENAME4args* args)
{
    if(args) out <<  "old name: " << args->oldname
                 << " new name: " << args->newname;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RENAME4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << " source: "
                << res->RENAME4res_u.resok4.source_cinfo
                << " target: "
                << res->RENAME4res_u.resok4.target_cinfo;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RENEW4args* args)
{
    if(args) out << "client id: "
                 << std::hex << args->clientid << std::dec;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RENEW4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SECINFO4args* args)
{
    if(args) out << "name: " << args->name;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SECINFO4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            if(res->SECINFO4res_u.resok4.SECINFO4resok_len)
                out << " data : "
                    << *res->SECINFO4res_u.resok4.SECINFO4resok_val;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETATTR4args* args)
{
    if(args) out << "state id:" << args->stateid
                         << ' ' << args->obj_attributes;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETATTR4res*  res)
{
    if(res)
    {
        out <<  "status: " << res->status;
        if(out_all()) out << ' ' << res->attrsset;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETCLIENTID4args* args)
{
    if(args) out << args->client
                 << " callback: "
                 << args->callback
                 << " callback ident: "
                 << std::hex << args->callback_ident << std::dec;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETCLIENTID4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all())
        {
            switch(res->status)
            {
            case NFS4::nfsstat4::NFS4_OK:
                out << " client id: "
                    << std::hex << res->SETCLIENTID4res_u.resok4.clientid << std::dec
                    << " verifier: ";
                print_hex(out,
                          res->SETCLIENTID4res_u.resok4.setclientid_confirm,
                          NFS4::NFS4_VERIFIER_SIZE);
                break;
            case NFS4::nfsstat4::NFS4ERR_CLID_INUSE:
                out << " client using: " << res->SETCLIENTID4res_u.client_using;
                break;
            default: break;
            }
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETCLIENTID_CONFIRM4args* args)
{
    if(args)
    {
        out << " client id: " << std::hex << args->clientid << std::dec
            << " verifier: ";
        print_hex(out, args->setclientid_confirm, NFS4::NFS4_VERIFIER_SIZE);
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETCLIENTID_CONFIRM4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::VERIFY4args* args)
{
    if(args) out << "object attributes: " << args->obj_attributes;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::VERIFY4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::WRITE4args* args)
{
    if(args)
    {
        out << args->stateid
            << " offset: "      << args->offset
            << " stable: "      << args->stable
            << " data length: " << args->data.data_len;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::WRITE4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " count: "          << res->WRITE4res_u.resok4.count
                << " committed: "       << res->WRITE4res_u.resok4.committed
                << " write verifier: ";
            print_hex(out,
                      res->WRITE4res_u.resok4.writeverf,
                      NFS4::NFS4_VERIFIER_SIZE);
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RELEASE_LOCKOWNER4args* args)
{
    if(args) out << "lock owner: " << args->lock_owner;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RELEASE_LOCKOWNER4res*  res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GET_DIR_DELEGATION4args* args)
{
    if(args)
        out <<  "client id: "                    << args->clientid
            << " notification types: "           << args->notif_types
            << " dir notification delay: "       << args->dir_notif_delay
            << " dir entry notification delay: " << args->dir_entry_notif_delay;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GET_DIR_DELEGATION4res*  res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << ' ' << res->GET_DIR_DELEGATION4res_u.resok4.stateid
                << " status: "
                << res->GET_DIR_DELEGATION4res_u.resok4.status
                << " notification types: "
                << res->GET_DIR_DELEGATION4res_u.resok4.notif_types
                << " dir: "
                << res->GET_DIR_DELEGATION4res_u.resok4.dir_notif_attrs
                << " dir entry: "
                << res->GET_DIR_DELEGATION4res_u.resok4.dir_entry_notif_attrs;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GETFH4res* res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << " object: " << res->GETFH4res_u.resok4.object;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOOKUPP4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::PUTPUBFH4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::PUTROOTFH4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READLINK4res* res)
{
    if(res)
    {
        out << "status: " << res->status;
        if(out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << " link: " << res->READLINK4res_u.resok4.link;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RESTOREFH4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SAVEFH4res* res)
{
    if(res) out << "status: " << res->status;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::ILLEGAL4res* res)
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
