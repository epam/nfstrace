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
    print_fh(out, data.get_file().get_data());
    out << std::endl;
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
    print_fh(out, data.get_what().get_dir().get_data());
    out << " Name: " << data.get_what().get_name() << std::endl;
    return true;
}

bool PrintAnalyzer::call_access(const NFSOperation& operation)
{
    const AccessArgs& data = static_cast<const AccessArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Object: ";
    print_fh(out, data.get_object().get_data());
    out << " Access: " << data.get_access() << std::endl;
    return true;
}

bool PrintAnalyzer::call_readlink(const NFSOperation& operation)
{
    const ReadLinkArgs& data = static_cast<const ReadLinkArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Symlink: ";
    print_fh(out, data.get_symlink().get_data()) << std::endl;
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
    out << operation << std::endl;
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
    print_fh(out, data.get_object().get_dir().get_data());
    out << " Name: " << data.get_object().get_name().get_string() << std::endl;
    return true;
}

bool PrintAnalyzer::call_rmdir(const NFSOperation& operation)
{
    const RmDirArgs& data = static_cast<const RmDirArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    print_fh(out, data.get_object().get_dir().get_data());
    out << " Name: " << data.get_object().get_name().get_string() << std::endl;
    return true;
}

bool PrintAnalyzer::call_rename(const NFSOperation& operation)
{
    const RenameArgs& data = static_cast<const RenameArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid();
    out << " from dir: "; print_fh(out, data.get_from().get_dir().get_data());
    out << " name: " << data.get_from().get_name().get_string();
    out << " to dir: "; print_fh(out, data.get_to().get_dir().get_data());
    out << " name: " << data.get_to().get_name().get_string();
    out << std::endl;
    return true;
}

bool PrintAnalyzer::call_link(const NFSOperation& operation)
{
    const LinkArgs& data = static_cast<const LinkArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid();
    out << " File: "; print_fh(out, data.get_file().get_data());
    out << " Dir: "; print_fh(out, data.get_link().get_dir().get_data());
    out << " Name: " << data.get_link().get_name().get_string() << std::endl;
    return true;
}

bool PrintAnalyzer::call_readdir(const NFSOperation& operation)
{
    const ReadDirArgs& data = static_cast<const ReadDirArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    print_fh(out, data.get_dir().get_data());
    out << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Count: " << data.get_count() << std::endl;
    return true;
}

bool PrintAnalyzer::call_readdirplus(const NFSOperation& operation)
{
    const ReadDirPlusArgs& data = static_cast<const ReadDirPlusArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " Dir: ";
    print_fh(out, data.get_dir().get_data());
    out << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Dir Count: " << data.get_dircount() << " Max Count: " << data.get_maxcount() << std::endl;
    return true;
}

bool PrintAnalyzer::call_fsstat(const NFSOperation& operation)
{
    const FSStatArgs& data = static_cast<const FSStatArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " FS Root:";
    print_fh(out, data.get_fsroot().get_data()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_fsinfo(const NFSOperation& operation)
{
    const FSInfoArgs& data = static_cast<const FSInfoArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid() << " FS Root:";
    print_fh(out, data.get_fsroot().get_data()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_pathconf(const NFSOperation& operation)
{
    const PathConfArgs& data = static_cast<const PathConfArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID : " << data.get_xid() << " Object: ";
    print_fh(out, data.get_object().get_data()) << std::endl;
    return true;
}

bool PrintAnalyzer::call_commit(const NFSOperation& operation)
{
    const CommitArgs& data = static_cast<const CommitArgs&>(*operation.get_call());
    out << get_session(*operation.get_session()) << " -- Call " << Proc::titles[data.get_proc()] <<". XID: " << data.get_xid();
    out << " File: ";
    print_fh(out, data.get_file().get_data());
    out << " Offset: " << data.get_offset();
    out << " Count: " << data.get_count()  << std::endl;
    return true;
}

void PrintAnalyzer::print(std::ostream& out)
{
    return;
}

std::ostream& PrintAnalyzer::print_fh(std::ostream& out, const Opaque& fh) const
{
    const uint8_t* data = fh.data();
    const uint32_t size = fh.size();

    static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
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
