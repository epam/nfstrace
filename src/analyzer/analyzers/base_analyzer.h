//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base analyzer, which implement restoring rpc/nfs structures from plain rpc header.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BASE_ANALYZER_H
#define BASE_ANALYZER_H
//------------------------------------------------------------------------------
#include <ostream>

#include "../nfs3/nfs_operation.h"
//------------------------------------------------------------------------------
using NST::analyzer::RPC::RPCOperation;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

class BaseAnalyzer
{
public:
    BaseAnalyzer()
    {
    }
    virtual ~BaseAnalyzer()
    {
    }

    virtual bool call_null          (const RPCOperation& operation) = 0;
    virtual bool call_getattr       (const RPCOperation& operation) = 0;
    virtual bool call_setattr       (const RPCOperation& operation) = 0;
    virtual bool call_lookup        (const RPCOperation& operation) = 0;
    virtual bool call_access        (const RPCOperation& operation) = 0;
    virtual bool call_readlink      (const RPCOperation& operation) = 0;
    virtual bool call_read          (const RPCOperation& operation) = 0;
    virtual bool call_write         (const RPCOperation& operation) = 0;
    virtual bool call_create        (const RPCOperation& operation) = 0;
    virtual bool call_mkdir         (const RPCOperation& operation) = 0;
    virtual bool call_symlink       (const RPCOperation& operation) = 0;
    virtual bool call_mknod         (const RPCOperation& operation) = 0;
    virtual bool call_remove        (const RPCOperation& operation) = 0;
    virtual bool call_rmdir         (const RPCOperation& operation) = 0;
    virtual bool call_rename        (const RPCOperation& operation) = 0;
    virtual bool call_link          (const RPCOperation& operation) = 0;
    virtual bool call_readdir       (const RPCOperation& operation) = 0;
    virtual bool call_readdirplus   (const RPCOperation& operation) = 0;
    virtual bool call_fsstat        (const RPCOperation& operation) = 0;
    virtual bool call_fsinfo        (const RPCOperation& operation) = 0;
    virtual bool call_pathconf      (const RPCOperation& operation) = 0;
    virtual bool call_commit        (const RPCOperation& operation) = 0;
    virtual void print(std::ostream& out) = 0;
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_ANALYZER_H
//------------------------------------------------------------------------------
