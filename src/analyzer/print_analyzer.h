//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PRINT_ANALYZER_H
#define PRINT_ANALYZER_H
//------------------------------------------------------------------------------
#include <iostream>
#include <sstream>

#include "../filter/rpc/rpc_message.h"
#include "../filter/nfs/nfs_operation.h"
#include "../filter/nfs/nfs_struct.h"
#include "base_analyzer.h"
#include "nfs_data.h"
//------------------------------------------------------------------------------
using namespace NST::filter::NFS3;
using namespace NST::filter::rpc;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class PrintAnalyzer : public BaseAnalyzer
{
    typedef NFSData::Session Session;
public:
    PrintAnalyzer(std::ostream& o):out(o)
    {
    }
    virtual ~PrintAnalyzer()
    {
    }

    virtual bool call_null(const Session& session, const NFSOperation& operation)
    {
        const NullArgs& data = static_cast<const NullArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call Null. XID: " << data.get_xid() << std::endl;
        return true;
    }
    virtual bool call_getattr(const Session& session, const NFSOperation& operation)
    {
        const GetAttrArgs& data = static_cast<const GetAttrArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call GetAttr. XID: " << data.get_xid() << " File: ";
        std::cout << print_fh(data.get_file()) << std::endl;
        return true;
    }
    virtual bool call_setattr(const Session& session/*, const NFSOperation& operation*/)
    {
        std::cout << get_session(session) << " -- NFS Call SetAttr." << std::endl;
        return true;
    }
    virtual bool call_lookup(const Session& session, const NFSOperation& operation)
    {
        const LookUpArgs& data = static_cast<const LookUpArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call LookUp. XID: " << data.get_xid() << " Dir: ";
        std::cout << print_fh(data.get_dir());
        std::cout << " Name: " << data.get_name() << std::endl;
        return true;
    }
    virtual bool call_access(const Session& session, const NFSOperation& operation)
    {
        const AccessArgs& data = static_cast<const AccessArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call Access. XID: " << data.get_xid() << " Object: ";
        std::cout << print_fh(data.get_object());
        std::cout << " Access: " << data.get_access() << std::endl;
        return true;
    }
    virtual bool call_readlink(const Session& session, const NFSOperation& operation)
    {
        const ReadLinkArgs& data = static_cast<const ReadLinkArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call ReadLink. XID: " << data.get_xid() << " Symlink: ";
        std::cout << print_fh(data.get_symlink()) << std::endl;
        return true;
    }
    virtual bool call_read(const Session& session, const NFSOperation& operation)
    {
        const ReadArgs& data = static_cast<const ReadArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call Read. XID: " << data.get_xid() << " Offset: " << data.get_offset() << " Count: " << data.get_count() << std::endl;
        return true;
    }
    virtual bool call_write(const Session& session, const NFSOperation& operation)
    {
        const WriteArgs& data = static_cast<const WriteArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call Write. XID: " << data.get_xid() << " Offset: " << data.get_offset() << " Count: " << data.get_count() << " Type: ";
        switch(data.get_stable())
        {
        case 0:
            {
                std::cout << "Unstable";
            }
            break;
        case 1:
            {
                std::cout << "Data Sync";
            }
            break;
        case 2:
            {
                std::cout << "File Sync";
            }
            break;
        }
        std::cout << std::endl;
        return true;
    }
    virtual bool call_create(const Session& session/*, const NFSOperation& operation*/)
    {
        std::cout << get_session(session) << " -- NFS Call Create" << std::endl;
        return true;
    }
    virtual bool call_mkdir(const Session& session/*, const NFSOperation& operation*/)
    {
        std::cout << get_session(session) << " -- NFS Call MKDir" << std::endl;
        return true;
    }
    virtual bool call_symlink(const Session& session/*, const NFSOperation& operation*/)
    {
        std::cout << get_session(session) << " -- NFS Call SymLink" << std::endl;
        return true;
    }
    virtual bool call_mknod(const Session& session/*, const NFSOperation& operation*/)
    {
        std::cout << get_session(session) << " -- NFS Call MKNod" << std::endl;
        return true;
    }
    virtual bool call_remove(const Session& session, const NFSOperation& operation)
    {
        const RemoveArgs& data = static_cast<const RemoveArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call Remove. XID: " << data.get_xid() << " Dir: ";
        std::cout << print_fh(data.get_dir());
        std::cout << " Name: " << data.get_name() << std::endl;
        return true;
    }
    virtual bool call_rmdir(const Session& session, const NFSOperation& operation)
    {
        const RmDirArgs& data = static_cast<const RmDirArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call RMDir. XID: " << data.get_xid() << " Dir: ";
        std::cout << print_fh(data.get_dir());
        std::cout << " Name: " << data.get_name() << std::endl;
        return true;
    }
    virtual bool call_rename(const Session& session, const NFSOperation& operation)
    {
        const RenameArgs& data = static_cast<const RenameArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call Rename. XID: " << data.get_xid() << " From Dir: ";
        std::cout << print_fh(data.get_from_dir());
        std::cout << " From Name: " << data.get_from_name() << " To Dir: ";
        std::cout << print_fh(data.get_to_dir());
        std::cout << " To Name: " << data.get_to_name() << std::endl;
        return true;
    }
    virtual bool call_link(const Session& session, const NFSOperation& operation)
    {
        const LinkArgs& data = static_cast<const LinkArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call Link. XID: " << data.get_xid() << " File: ";
        std::cout << print_fh(data.get_file());
        std::cout << " Dir: ";
        std::cout << print_fh(data.get_dir());
        std::cout << " Name: " << data.get_name() << std::endl;
        return true;
    }
    virtual bool call_readdir(const Session& session, const NFSOperation& operation)
    {
        const ReadDirArgs& data = static_cast<const ReadDirArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call ReadDir. XID: " << data.get_xid() << " Dir: ";
        std::cout << print_fh(data.get_dir());
        std::cout << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Count: " << data.get_count() << std::endl;
        return true;
    }
    virtual bool call_readdirplus(const Session& session, const NFSOperation& operation)
    {
        const ReadDirPlusArgs& data = static_cast<const ReadDirPlusArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call ReadDirPlus. XID: " << data.get_xid() << " Dir: ";
        std::cout << print_fh(data.get_dir());
        std::cout << " Cookie: " << data.get_cookie() << " CookieVerf: " << data.get_cookieverf() << " Dir Count: " << data.get_dir_count() << " Max Count: " << data.get_max_count() << std::endl;
        return true;
    }
    virtual bool call_fsstat(const Session& session, const NFSOperation& operation)
    {
        const FSStatArgs& data = static_cast<const FSStatArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call FSStat. XID: " << data.get_xid() << " FS Root:";
        std::cout << print_fh(data.get_fs_root()) << std::endl;
        return true;
    }
    virtual bool call_fsinfo(const Session& session, const NFSOperation& operation)
    {
        const FSInfoArgs& data = static_cast<const FSInfoArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call FSInfo. XID: " << data.get_xid() << " FS Root:";
        std::cout << print_fh(data.get_fs_root()) << std::endl;
        return true;
    }
    virtual bool call_pathconf(const Session& session, const NFSOperation& operation)
    {
        const PathConfArgs& data = static_cast<const PathConfArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call PathConf. XID : " << data.get_xid() << " Object: ";
        std::cout << print_fh(data.get_object()) << std::endl;
        return true;
    }
    virtual bool call_commit(const Session& session, const NFSOperation& operation)
    {
        const CommitArgs& data = static_cast<const CommitArgs&>(*operation.get_call());
        std::cout << get_session(session) << " -- NFS Call Commit. XID: " << data.get_xid() << " File: ";
        std::cout << print_fh(data.get_file());
        std::cout << " Offset: " << data.get_offset() << " Count: " << data.get_count()  << std::endl;
        return true;
    }

private:
    std::string print_fh(const OpaqueDyn& fh)
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

    std::string get_session(const Session& session) const
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

    std::string session_addr(NFSData::Session::Direction dir, const Session& session) const
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

    std::string ipv6_string(const uint8_t ip[16]) const
    {
        std::stringstream address(std::ios_base::out);
        address << "IPV6";
        return address.str();
    }

    std::string ipv4_string(const uint32_t ip /*host byte order*/ ) const
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

    std::ostream& out;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PRINT_ANALYZER_H
//------------------------------------------------------------------------------
