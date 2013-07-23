//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <sstream>

#include "../nfs3/nfs_operation.h"
#include "../nfs3/nfs_procedures.h"
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

bool PrintAnalyzer::call_null(const NFSOperation& operation)
{
    const NullArgs& data = static_cast<const NullArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] << ". XID: " << data.get_xid() << std::endl;
    return true;
}

bool PrintAnalyzer::call_getattr(const NFSOperation& operation)
{
    const GetAttrArgs& data = static_cast<const GetAttrArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] << ". XID: " << data.get_xid() << " File: ";
    out << print_fh(data.get_file()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_setattr(const NFSOperation& operation)
{
    out << operation << std::endl;
    return true;
}

bool PrintAnalyzer::call_lookup(const NFSOperation& operation)
{
    const LookUpArgs& data = static_cast<const LookUpArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Name: " << data.get_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_access(const NFSOperation& operation)
{
    const AccessArgs& data = static_cast<const AccessArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Object: ";
    out << print_fh(data.get_object());
    out << " Access: " << data.get_access() << std::endl;
    return true;
}

bool PrintAnalyzer::call_readlink(const NFSOperation& operation)
{
    const ReadLinkArgs& data = static_cast<const ReadLinkArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Symlink: ";
    out << print_fh(data.get_symlink()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_read(const NFSOperation& operation)
{
    const ReadArgs& data = static_cast<const ReadArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Offset: " << data.get_offset() << " Count: " << data.get_count() << std::endl;
    return true;
}

bool PrintAnalyzer::call_write(const NFSOperation& operation)
{
    const WriteArgs& data = static_cast<const WriteArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Offset: " << data.get_offset() << " Count: " << data.get_count() << " Type: ";
    switch(data.get_stable())
    {
    case 0:
        {
            out << "Unstable";
        }
        break;
    case 1:
        {
            out << "Data Sync";
        }
        break;
    case 2:
        {
            out << "File Sync";
        }
        break;
    }
    out << std::endl;
    return true;
}

bool PrintAnalyzer::call_create(const NFSOperation& operation)
{
    out << operation << std::endl;
    return true;
}

bool PrintAnalyzer::call_mkdir(const NFSOperation& operation)
{
    out << operation << std::endl;
    return true;
}

bool PrintAnalyzer::call_symlink(const NFSOperation& operation)
{
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[Proc::SYMLINK] <<"." << std::endl;
    return true;
}

bool PrintAnalyzer::call_mknod(const NFSOperation& operation)
{
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[Proc::MKNOD] <<"." << std::endl;
    return true;
}

bool PrintAnalyzer::call_remove(const NFSOperation& operation)
{
    const RemoveArgs& data = static_cast<const RemoveArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Name: " << data.get_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_rmdir(const NFSOperation& operation)
{
    const RmDirArgs& data = static_cast<const RmDirArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Name: " << data.get_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_rename(const NFSOperation& operation)
{
    const RenameArgs& data = static_cast<const RenameArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " From Dir: ";
    out << print_fh(data.get_from_dir());
    out << " From Name: " << data.get_from_name() << " To Dir: ";
    out << print_fh(data.get_to_dir());
    out << " To Name: " << data.get_to_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_link(const NFSOperation& operation)
{
    const LinkArgs& data = static_cast<const LinkArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " File: ";
    out << print_fh(data.get_file());
    out << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Name: " << data.get_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_readdir(const NFSOperation& operation)
{
    const ReadDirArgs& data = static_cast<const ReadDirArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Count: " << data.get_count() << std::endl;
    return true;
}

bool PrintAnalyzer::call_readdirplus(const NFSOperation& operation)
{
    const ReadDirPlusArgs& data = static_cast<const ReadDirPlusArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Dir Count: " << data.get_dir_count() << " Max Count: " << data.get_max_count() << std::endl;
    return true;
}

bool PrintAnalyzer::call_fsstat(const NFSOperation& operation)
{
    const FSStatArgs& data = static_cast<const FSStatArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " FS Root:";
    out << print_fh(data.get_fs_root()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_fsinfo(const NFSOperation& operation)
{
    const FSInfoArgs& data = static_cast<const FSInfoArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " FS Root:";
    out << print_fh(data.get_fs_root()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_pathconf(const NFSOperation& operation)
{
    const PathConfArgs& data = static_cast<const PathConfArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID : " << data.get_xid() << " Object: ";
    out << print_fh(data.get_object()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_commit(const NFSOperation& operation)
{
    const CommitArgs& data = static_cast<const CommitArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " File: ";
    out << print_fh(data.get_file());
    out << " Offset: " << data.get_offset() << " Count: " << data.get_count()  << std::endl;
    return true;
}

void PrintAnalyzer::print(std::ostream& out)
{
    return;
}

std::string PrintAnalyzer::print_fh(const OpaqueDyn& fh) const
{
    std::stringstream tmp;
    tmp << fh;
    std::string opaque = tmp.str();

    tmp.str("");
    for(int i = 0; i < 4; ++i)
    {
        tmp << opaque[i];
    }
    tmp << "...";
    int len = fh.data.size();
    for(int i = len - 4; i < len; ++i)
    {
        tmp << opaque[i];
    }
    return tmp.str();
}

std::string PrintAnalyzer::get_session(const NFSOperation::Session& session) const
{
    std::stringstream s(std::ios_base::out);
    s << session_addr(NFSOperation::Session::Source, session) << " --> " << session_addr(NFSOperation::Session::Destination, session);
    switch(session.type)
    {
        case NFSOperation::Session::TCP:
            s << " (TCP)";
            break;
        case NFSOperation::Session::UDP:
            s << " (UPD)";
            break;
    }
    return s.str();
}

std::string PrintAnalyzer::session_addr(NFSOperation::Session::Direction dir, const NFSOperation::Session& session) const
{
    std::stringstream s(std::ios_base::out);
    switch(session.ip_type)
    {
        case NFSOperation::Session::v4:
            s << ipv4_string(session.ip.v4.addr[dir]);
            break;
        case NFSOperation::Session::v6:
            s << ipv6_string(session.ip.v6.addr[dir]);
            break;
    }
    s << ":" << session.port[dir];
    return s.str();
}

std::string PrintAnalyzer::ipv6_string(const uint8_t ip[16]) const
{
    std::stringstream address(std::ios_base::out);
    address << "IPV6";
    return address.str();
}

std::string PrintAnalyzer::ipv4_string(const uint32_t ip) const
{
    std::stringstream address(std::ios_base::out);
    address << ((ip >> 24) & 0xFF);
    address << '.';
    address << ((ip >> 16) & 0xFF);
    address << '.';
    address << ((ip >> 8) & 0xFF);
    address << '.';
    address << ((ip >> 0) & 0xFF);
    return address.str();
}

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
