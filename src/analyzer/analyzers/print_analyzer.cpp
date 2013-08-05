//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <sstream>

#include "../nfs3/nfs_operation.h"
#include "../nfs3/nfs_structs.h"
#include "print_analyzer.h"
//------------------------------------------------------------------------------
using namespace NST::analyzer::NFS3;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

// Spesial helper for printout short representation of NFS FH
std::ostream& operator += (std::ostream& out, const nfs_fh3& fh)
{
    static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    const Opaque& opaque = fh.get_data();
    const uint8_t* data = opaque.data();
    const uint32_t size = opaque.size();

    if(size <= 8)
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

bool PrintAnalyzer::call_null(const RPCOperation& operation)
{
    const NFSPROC3_NULL& op = static_cast<const NFSPROC3_NULL&>(operation);

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << "] REPLY [";
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_getattr(const RPCOperation& operation)
{
    const NFSPROC3_GETATTR& op = static_cast<const NFSPROC3_GETATTR&>(operation);
    const NFSPROC3_GETATTR::Arg& arg = op.get_arg();
    const NFSPROC3_GETATTR::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " object: " += arg.get_object();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_setattr(const RPCOperation& operation)
{
    const NFSPROC3_SETATTR& op = static_cast<const NFSPROC3_SETATTR&>(operation);
    const NFSPROC3_SETATTR::Arg& arg = op.get_arg();
    const NFSPROC3_SETATTR::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " object: " += arg.get_object();
    out << " new_attributes: " << arg.get_new_attributes();
    out << " guard: " << arg.get_guard();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_lookup(const RPCOperation& operation)
{
    const NFSPROC3_LOOKUP& op = static_cast<const NFSPROC3_LOOKUP&>(operation);
    const NFSPROC3_LOOKUP::Arg& arg = op.get_arg();
    const NFSPROC3_LOOKUP::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " dir: "  += arg.get_what().get_dir();
    out << " name: " << arg.get_what().get_name().get_string();
    out << "] REPLY [";
    out << " status: " << res.status;
    if(res.status == nfsstat3::OK)
    {
        out << " object: "  += res.resok.object;
        out << " obj_attributes: "  << res.resok.obj_attributes;
        out << " dir_attributes: "  << res.resok.dir_attributes;
    }
    else
    {
        out << " dir_attributes: "  << res.resfail.dir_attributes;
    }
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_access(const RPCOperation& operation)
{
    const NFSPROC3_ACCESS& op = static_cast<const NFSPROC3_ACCESS&>(operation);
    const NFSPROC3_ACCESS::Arg& arg = op.get_arg();
    const NFSPROC3_ACCESS::Res& res = op.get_res();

    const RPC::RPCReply& rep = op.get_reply();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " object: "  += arg.get_object();
    out << " access: " << arg.get_access();
    out << "] REPLY [";
    out << " Reply Status: " << rep.stat;
    out << " Accepted Status: " << rep.accepted.stat;
    out << " Result Status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_readlink(const RPCOperation& operation)
{
    const NFSPROC3_READLINK& op = static_cast<const NFSPROC3_READLINK&>(operation);
    const NFSPROC3_READLINK::Arg& arg = op.get_arg();
    const NFSPROC3_READLINK::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " symlink: "  += arg.get_symlink();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_read(const RPCOperation& operation)
{
    const NFSPROC3_READ& op = static_cast<const NFSPROC3_READ&>(operation);
    const NFSPROC3_READ::Arg& arg = op.get_arg();
    const NFSPROC3_READ::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " file: "  += arg.get_file();
    out << " offset: "  << arg.get_offset();
    out << " count: " << arg.get_count();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_write(const RPCOperation& operation)
{
    const NFSPROC3_WRITE& op = static_cast<const NFSPROC3_WRITE&>(operation);
    const NFSPROC3_WRITE::Arg& arg = op.get_arg();
    const NFSPROC3_WRITE::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " file: " += arg.get_file();
    out << " offset: " << arg.get_offset();
    out << " count: " << arg.get_count();
    switch(arg.get_stable())
    {
        case WRITE3args::UNSTABLE:  out << " stable: UNSTABLE";  break;
        case WRITE3args::DATA_SYNC: out << " stable: DATA_SYNC"; break;
        case WRITE3args::FYLE_SYNC: out << " stable: FYLE_SYNC"; break;
    }
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_create(const RPCOperation& operation)
{
    const NFSPROC3_CREATE& op = static_cast<const NFSPROC3_CREATE&>(operation);
    const NFSPROC3_CREATE::Arg& arg = op.get_arg();
    const NFSPROC3_CREATE::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " where: " << arg.get_where();
    out << " how: " << arg.get_how();
    out << "] REPLY [";
    out << " status: " << res.status;
    if(res.status == nfsstat3::OK)
    {
        out << " obj: " << res.resok.obj;
        out << " obj_attributes: " << res.resok.obj_attributes;
        out << " dir_wcc: " << res.resok.dir_wcc;
    }
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_mkdir(const RPCOperation& operation)
{
    const NFSPROC3_MKDIR& op = static_cast<const NFSPROC3_MKDIR&>(operation);
    const NFSPROC3_MKDIR::Arg& arg = op.get_arg();
    const NFSPROC3_MKDIR::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " where: " << arg.get_where();
    out << " attributes: " << arg.get_attributes();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_symlink(const RPCOperation& operation)
{
    const NFSPROC3_SYMLINK& op = static_cast<const NFSPROC3_SYMLINK&>(operation);
    const NFSPROC3_SYMLINK::Arg& arg = op.get_arg();
    const NFSPROC3_SYMLINK::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " where: " << arg.get_where();
    out << " symlinkdata: " << arg.get_symlink();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_mknod(const RPCOperation& operation)
{
    const NFSPROC3_MKNOD& op = static_cast<const NFSPROC3_MKNOD&>(operation);
    const NFSPROC3_MKNOD::Arg& arg = op.get_arg();
    const NFSPROC3_MKNOD::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " where: " << arg.get_where();
    out << " what: " << arg.get_what();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_remove(const RPCOperation& operation)
{
    const NFSPROC3_REMOVE& op = static_cast<const NFSPROC3_REMOVE&>(operation);
    const NFSPROC3_REMOVE::Arg& arg = op.get_arg();
    const NFSPROC3_REMOVE::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " object: " << arg.get_object();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_rmdir(const RPCOperation& operation)
{
    const NFSPROC3_RMDIR& op = static_cast<const NFSPROC3_RMDIR&>(operation);
    const NFSPROC3_RMDIR::Arg& arg = op.get_arg();
    const NFSPROC3_RMDIR::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " object: " << arg.get_object();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_rename(const RPCOperation& operation)
{
    const NFSPROC3_RENAME& op = static_cast<const NFSPROC3_RENAME&>(operation);
    const NFSPROC3_RENAME::Arg& arg = op.get_arg();
    const NFSPROC3_RENAME::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " from: " << arg.get_from();
    out << " to: " << arg.get_to();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_link(const RPCOperation& operation)
{
    const NFSPROC3_LINK& op = static_cast<const NFSPROC3_LINK&>(operation);
    const NFSPROC3_LINK::Arg& arg = op.get_arg();
    const NFSPROC3_LINK::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " file: " += arg.get_file();
    out << " link: " << arg.get_link();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_readdir(const RPCOperation& operation)
{
    const NFSPROC3_READDIR& op = static_cast<const NFSPROC3_READDIR&>(operation);
    const NFSPROC3_READDIR::Arg& arg = op.get_arg();
    const NFSPROC3_READDIR::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " dir: " += arg.get_dir();
    out << " cookie: " << arg.get_cookie();
    out << " cookieverf: " << arg.get_cookieverf();
    out << " count: " << arg.get_count();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_readdirplus(const RPCOperation& operation)
{
    const NFSPROC3_READDIRPLUS& op = static_cast<const NFSPROC3_READDIRPLUS&>(operation);
    const NFSPROC3_READDIRPLUS::Arg& arg = op.get_arg();
    const NFSPROC3_READDIRPLUS::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " dir: " += arg.get_dir();
    out << " cookie: " << arg.get_cookie();
    out << " cookieverf: " << arg.get_cookieverf();
    out << " dircount: " << arg.get_dircount();
    out << " maxcount: " << arg.get_maxcount();
    out << "] REPLY [";
    out << " status: " << res.status;
    if(res.status == nfsstat3::OK)
    {
        out << res.resok.dir_attributes;
        out << res.resok.cookieverf;
    }
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_fsstat(const RPCOperation& operation)
{
    const NFSPROC3_FSSTAT& op = static_cast<const NFSPROC3_FSSTAT&>(operation);
    const NFSPROC3_FSSTAT::Arg& arg = op.get_arg();
    const NFSPROC3_FSSTAT::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " fsroot: " += arg.get_fsroot();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_fsinfo(const RPCOperation& operation)
{
    const NFSPROC3_FSINFO& op = static_cast<const NFSPROC3_FSINFO&>(operation);
    const NFSPROC3_FSINFO::Arg& arg = op.get_arg();
    const NFSPROC3_FSINFO::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " fsroot: " += arg.get_fsroot();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_pathconf(const RPCOperation& operation)
{
    const NFSPROC3_PATHCONF& op = static_cast<const NFSPROC3_PATHCONF&>(operation);
    const NFSPROC3_PATHCONF::Arg& arg = op.get_arg();
    const NFSPROC3_PATHCONF::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " object: " += arg.get_object();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_commit(const RPCOperation& operation)
{
    const NFSPROC3_COMMIT& op = static_cast<const NFSPROC3_COMMIT&>(operation);
    const NFSPROC3_COMMIT::Arg& arg = op.get_arg();
    const NFSPROC3_COMMIT::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << " CALL [";
    out << " file: " += arg.get_file();
    out << " offset: " << arg.get_offset();
    out << " count: " << arg.get_count();
    out << "] REPLY [";
    out << " status: " << res.status;
    out << " ]";
    out << std::endl;

    return true;
}

void PrintAnalyzer::print(std::ostream& out)
{
    return;
}

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
