//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "print_analyzer.h"

namespace NST
{
namespace analyzer
{

bool PrintAnalyzer::call_null(const Session& session, const NFSOperation& operation)
{
    const NullArgs& data = static_cast<const NullArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] << ". XID: " << data.get_xid() << std::endl;
    return true;
}

bool PrintAnalyzer::call_getattr(const Session& session, const NFSOperation& operation)
{
    const GetAttrArgs& data = static_cast<const GetAttrArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] << ". XID: " << data.get_xid() << " File: ";
    out << print_fh(data.get_file()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_setattr(const Session& session, const NFSOperation& operation)
{
    out << get_session(session) << " -- Call " << Proc::titles[Proc::SETATTR] << "." << std::endl;
    return true;
}

bool PrintAnalyzer::call_lookup(const Session& session, const NFSOperation& operation)
{
    const LookUpArgs& data = static_cast<const LookUpArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Name: " << data.get_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_access(const Session& session, const NFSOperation& operation)
{
    const AccessArgs& data = static_cast<const AccessArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Object: ";
    out << print_fh(data.get_object());
    out << " Access: " << data.get_access() << std::endl;
    return true;
}

bool PrintAnalyzer::call_readlink(const Session& session, const NFSOperation& operation)
{
    const ReadLinkArgs& data = static_cast<const ReadLinkArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Symlink: ";
    out << print_fh(data.get_symlink()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_read(const Session& session, const NFSOperation& operation)
{
    const ReadArgs& data = static_cast<const ReadArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Offset: " << data.get_offset() << " Count: " << data.get_count() << std::endl;
    return true;
}

bool PrintAnalyzer::call_write(const Session& session, const NFSOperation& operation)
{
    const WriteArgs& data = static_cast<const WriteArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Offset: " << data.get_offset() << " Count: " << data.get_count() << " Type: ";
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

bool PrintAnalyzer::call_create(const Session& session, const NFSOperation& operation)
{
    out << get_session(session) << " -- Call " << Proc::titles[Proc::CREATE] <<"." << std::endl;
    return true;
}

bool PrintAnalyzer::call_mkdir(const Session& session, const NFSOperation& operation)
{
    out << get_session(session) << " -- Call " << Proc::titles[Proc::MKDIR] <<"." << std::endl;
    return true;
}

bool PrintAnalyzer::call_symlink(const Session& session, const NFSOperation& operation)
{
    out << get_session(session) << " -- Call " << Proc::titles[Proc::SYMLINK] <<"." << std::endl;
    return true;
}

bool PrintAnalyzer::call_mknod(const Session& session, const NFSOperation& operation)
{
    out << get_session(session) << " -- Call " << Proc::titles[Proc::MKNOD] <<"." << std::endl;
    return true;
}

bool PrintAnalyzer::call_remove(const Session& session, const NFSOperation& operation)
{
    const RemoveArgs& data = static_cast<const RemoveArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Name: " << data.get_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_rmdir(const Session& session, const NFSOperation& operation)
{
    const RmDirArgs& data = static_cast<const RmDirArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Name: " << data.get_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_rename(const Session& session, const NFSOperation& operation)
{
    const RenameArgs& data = static_cast<const RenameArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " From Dir: ";
    out << print_fh(data.get_from_dir());
    out << " From Name: " << data.get_from_name() << " To Dir: ";
    out << print_fh(data.get_to_dir());
    out << " To Name: " << data.get_to_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_link(const Session& session, const NFSOperation& operation)
{
    const LinkArgs& data = static_cast<const LinkArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " File: ";
    out << print_fh(data.get_file());
    out << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Name: " << data.get_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_readdir(const Session& session, const NFSOperation& operation)
{
    const ReadDirArgs& data = static_cast<const ReadDirArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Count: " << data.get_count() << std::endl;
    return true;
}

bool PrintAnalyzer::call_readdirplus(const Session& session, const NFSOperation& operation)
{
    const ReadDirPlusArgs& data = static_cast<const ReadDirPlusArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    out << print_fh(data.get_dir());
    out << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Dir Count: " << data.get_dir_count() << " Max Count: " << data.get_max_count() << std::endl;
    return true;
}

bool PrintAnalyzer::call_fsstat(const Session& session, const NFSOperation& operation)
{
    const FSStatArgs& data = static_cast<const FSStatArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " FS Root:";
    out << print_fh(data.get_fs_root()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_fsinfo(const Session& session, const NFSOperation& operation)
{
    const FSInfoArgs& data = static_cast<const FSInfoArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " FS Root:";
    out << print_fh(data.get_fs_root()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_pathconf(const Session& session, const NFSOperation& operation)
{
    const PathConfArgs& data = static_cast<const PathConfArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID : " << data.get_xid() << " Object: ";
    out << print_fh(data.get_object()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_commit(const Session& session, const NFSOperation& operation)
{
    const CommitArgs& data = static_cast<const CommitArgs&>(*operation.get_call());
    out << get_session(session) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " File: ";
    out << print_fh(data.get_file());
    out << " Offset: " << data.get_offset() << " Count: " << data.get_count()  << std::endl;
    return true;
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

std::string PrintAnalyzer::get_session(const Session& session) const
{
    std::stringstream s(std::ios_base::out);
    s << session_addr(NFSData::Session::Source, session) << " --> " << session_addr(NFSData::Session::Destination, session);
    switch(session.type)
    {
        case NFSData::Session::TCP:
            s << " (TCP)";
            break;
        case NFSData::Session::UDP:
            s << " (UPD)";
            break;
    }
    return s.str();
}

std::string PrintAnalyzer::session_addr(NFSData::Session::Direction dir, const Session& session) const
{
    std::stringstream s(std::ios_base::out);
    switch(session.ip_type)
    {
        case NFSData::Session::v4:
            s << ipv4_string(session.ip.v4.addr[dir]);
            break;
        case NFSData::Session::v6:
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

} // namespace analyzer
} // namespace NST
