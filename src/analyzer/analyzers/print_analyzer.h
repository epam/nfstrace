//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PRINT_ANALYZER_H
#define PRINT_ANALYZER_H
//------------------------------------------------------------------------------
#include <iostream>
#include <string>

#include "base_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
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

    virtual bool call_null       (const NFSOperation& operation);
    virtual bool call_getattr    (const NFSOperation& operation);
    virtual bool call_setattr    (const NFSOperation& operation);
    virtual bool call_lookup     (const NFSOperation& operation);
    virtual bool call_access     (const NFSOperation& operation);
    virtual bool call_readlink   (const NFSOperation& operation);
    virtual bool call_read       (const NFSOperation& operation);
    virtual bool call_write      (const NFSOperation& operation);
    virtual bool call_create     (const NFSOperation& operation);
    virtual bool call_mkdir      (const NFSOperation& operation);
    virtual bool call_symlink    (const NFSOperation& operation);
    virtual bool call_mknod      (const NFSOperation& operation);
    virtual bool call_remove     (const NFSOperation& operation);
    virtual bool call_rmdir      (const NFSOperation& operation);
    virtual bool call_rename     (const NFSOperation& operation);
    virtual bool call_link       (const NFSOperation& operation);
    virtual bool call_readdir    (const NFSOperation& operation);
    virtual bool call_readdirplus(const NFSOperation& operation);
    virtual bool call_fsstat     (const NFSOperation& operation);
    virtual bool call_fsinfo     (const NFSOperation& operation);
    virtual bool call_pathconf   (const NFSOperation& operation);
    virtual bool call_commit     (const NFSOperation& operation);
    virtual void print(std::ostream& out);

private:
    std::ostream& print_fh(std::ostream& out, const Opaque& fh) const;
    std::string get_session(const NFSOperation::Session& session) const;
    std::string session_addr(NFSOperation::Session::Direction dir, const NFSOperation::Session& session) const;
    std::string ipv6_string(const uint8_t ip[16]) const;
    std::string ipv4_string(const uint32_t ip) const;

    std::ostream& out;
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PRINT_ANALYZER_H
//------------------------------------------------------------------------------
