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

//#include "../filter/rpc/rpc_message.h"
#include "../filter/nfs/nfs_operation.h"
#include "../filter/nfs/nfs_procedures.h"
#include "../filter/nfs/nfs_struct.h"
#include "base_analyzer.h"
//------------------------------------------------------------------------------
using namespace NST::filter::NFS3;
//using namespace NST::filter::rpc;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class PrintAnalyzer : public BaseAnalyzer
{
public:
    PrintAnalyzer(std::ostream& o):out(o)
    {
    }
    virtual ~PrintAnalyzer()
    {
    }

    virtual bool call_null       (const Session& session, const NFSOperation& operation);
    virtual bool call_getattr    (const Session& session, const NFSOperation& operation);
    virtual bool call_setattr    (const Session& session, const NFSOperation& operation);
    virtual bool call_lookup     (const Session& session, const NFSOperation& operation);
    virtual bool call_access     (const Session& session, const NFSOperation& operation);
    virtual bool call_readlink   (const Session& session, const NFSOperation& operation);
    virtual bool call_read       (const Session& session, const NFSOperation& operation);
    virtual bool call_write      (const Session& session, const NFSOperation& operation);
    virtual bool call_create     (const Session& session, const NFSOperation& operation);
    virtual bool call_mkdir      (const Session& session, const NFSOperation& operation);
    virtual bool call_symlink    (const Session& session, const NFSOperation& operation);
    virtual bool call_mknod      (const Session& session, const NFSOperation& operation);
    virtual bool call_remove     (const Session& session, const NFSOperation& operation);
    virtual bool call_rmdir      (const Session& session, const NFSOperation& operation);
    virtual bool call_rename     (const Session& session, const NFSOperation& operation);
    virtual bool call_link       (const Session& session, const NFSOperation& operation);
    virtual bool call_readdir    (const Session& session, const NFSOperation& operation);
    virtual bool call_readdirplus(const Session& session, const NFSOperation& operation);
    virtual bool call_fsstat     (const Session& session, const NFSOperation& operation);
    virtual bool call_fsinfo     (const Session& session, const NFSOperation& operation);
    virtual bool call_pathconf   (const Session& session, const NFSOperation& operation);
    virtual bool call_commit     (const Session& session, const NFSOperation& operation);

private:
    std::string print_fh(const OpaqueDyn& fh) const;
    std::string get_session(const Session& session) const;
    std::string session_addr(Session::Direction dir, const Session& session) const;
    std::string ipv6_string(const uint8_t ip[16]) const;
    std::string ipv4_string(const uint32_t ip) const;

    std::ostream& out;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PRINT_ANALYZER_H
//------------------------------------------------------------------------------
