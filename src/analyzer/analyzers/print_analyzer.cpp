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
//    const NFSPROC3_NULL& op = static_cast<const NFSPROC3_NULL&>(operation);
/*    const NFSPROC3_NULL& data = static_cast<const NFSPROC3_NULL&>(operation);
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] << ". XID: " << data.get_xid() << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_getattr(const RPCOperation& operation)
{
/*    const GetAttrArgs& data = static_cast<const GetAttrArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] << ". XID: " << data.get_xid() << " File: ";
    print_fh(out, data.get_file().get_data());
    out << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_setattr(const RPCOperation& operation)
{
//    out << operation << std::endl;
    return true;
}

bool PrintAnalyzer::call_lookup(const RPCOperation& operation)
{
    const NFSPROC3_LOOKUP& op = static_cast<const NFSPROC3_LOOKUP&>(operation);
    const NFSPROC3_LOOKUP::Arg& arg = op.get_arg();
// unused   const NFSPROC3_LOOKUP::Res& res = op.get_res();

    out << op.get_session().str() << ' ' << Proc::Titles[op.procedure()] << " XID: " << op.xid();
    out << "CALL [";
    out << " dir: "  += arg.get_what().get_dir();
    out << " name: " << arg.get_what().get_name().get_string();
    out << "] REPLY [";
// unused   out << res;
    out << " ]";
    out << std::endl;

    return true;
}

bool PrintAnalyzer::call_access(const RPCOperation& operation)
{
/*    const AccessArgs& data = static_cast<const AccessArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Object: ";
    print_fh(out, data.get_object().get_data());
    out << " Access: " << data.get_access() << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_readlink(const RPCOperation& operation)
{
/*    const ReadLinkArgs& data = static_cast<const ReadLinkArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Symlink: ";
    print_fh(out, data.get_symlink().get_data()) << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_read(const RPCOperation& operation)
{
/*    const ReadArgs& data = static_cast<const ReadArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Offset: " << data.get_offset() << " Count: " << data.get_count() << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_write(const RPCOperation& operation)
{
//    out << operation << std::endl;
    return true;
}

bool PrintAnalyzer::call_create(const RPCOperation& operation)
{
//    out << operation << std::endl;
    return true;
}

bool PrintAnalyzer::call_mkdir(const RPCOperation& operation)
{
//    out << operation << std::endl;
    return true;
}

bool PrintAnalyzer::call_symlink(const RPCOperation& operation)
{
//    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[Proc::SYMLINK] <<"." << std::endl;
    return true;
}

bool PrintAnalyzer::call_mknod(const RPCOperation& operation)
{
//    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[Proc::MKNOD] <<"." << std::endl;
    return true;
}

bool PrintAnalyzer::call_remove(const RPCOperation& operation)
{
/*    const RemoveArgs& data = static_cast<const RemoveArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    print_fh(out, data.get_object().get_dir().get_data());
    out << " Name: " << data.get_object().get_name().get_string() << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_rmdir(const RPCOperation& operation)
{
/*    const RmDirArgs& data = static_cast<const RmDirArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    print_fh(out, data.get_object().get_dir().get_data());
    out << " Name: " << data.get_object().get_name().get_string() << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_rename(const RPCOperation& operation)
{
/*    const RenameArgs& data = static_cast<const RenameArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid();
    out << " from dir: "; print_fh(out, data.get_from().get_dir().get_data());
    out << " name: " << data.get_from().get_name().get_string();
    out << " to dir: "; print_fh(out, data.get_to().get_dir().get_data());
    out << " name: " << data.get_to().get_name().get_string();
    out << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_link(const RPCOperation& operation)
{
/*    const LinkArgs& data = static_cast<const LinkArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid();
    out << " File: "; print_fh(out, data.get_file().get_data());
    out << " Dir: "; print_fh(out, data.get_link().get_dir().get_data());
    out << " Name: " << data.get_link().get_name().get_string() << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_readdir(const RPCOperation& operation)
{
/*    const ReadDirArgs& data = static_cast<const ReadDirArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    print_fh(out, data.get_dir().get_data());
    out << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Count: " << data.get_count() << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_readdirplus(const RPCOperation& operation)
{
/*    const ReadDirPlusArgs& data = static_cast<const ReadDirPlusArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    print_fh(out, data.get_dir().get_data());
    out << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Dir Count: " << data.get_dircount() << " Max Count: " << data.get_maxcount() << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_fsstat(const RPCOperation& operation)
{
/*    const FSStatArgs& data = static_cast<const FSStatArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " FS Root:";
    print_fh(out, data.get_fsroot().get_data()) << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_fsinfo(const RPCOperation& operation)
{
/*    const FSInfoArgs& data = static_cast<const FSInfoArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " FS Root:";
    print_fh(out, data.get_fsroot().get_data()) << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_pathconf(const RPCOperation& operation)
{
/*    const PathConfArgs& data = static_cast<const PathConfArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID : " << data.get_xid() << " Object: ";
    print_fh(out, data.get_object().get_data()) << std::endl;*/
    return true;
}

bool PrintAnalyzer::call_commit(const RPCOperation& operation)
{
/*    const CommitArgs& data = static_cast<const CommitArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid();
    out << " File: ";
    print_fh(out, data.get_file().get_data());
    out << " Offset: " << data.get_offset();
    out << " Count: " << data.get_count()  << std::endl;*/
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
