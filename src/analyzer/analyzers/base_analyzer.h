//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Base analyzer, which implement restoring rpc/nfs structures from plain rpc header.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BASE_ANALYZER_H
#define BASE_ANALYZER_H
//------------------------------------------------------------------------------
#include <ostream>

#include "../../filter/nfs/nfs_operation.h"
//------------------------------------------------------------------------------
using NST::filter::NFS3::NFSOperation;
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

    virtual bool call_null          (const NFSOperation& operation) = 0;
    virtual bool call_getattr       (const NFSOperation& operation) = 0;
    virtual bool call_setattr       (const NFSOperation& operation) = 0;
    virtual bool call_lookup        (const NFSOperation& operation) = 0;
    virtual bool call_access        (const NFSOperation& operation) = 0;
    virtual bool call_readlink      (const NFSOperation& operation) = 0;
    virtual bool call_read          (const NFSOperation& operation) = 0;
    virtual bool call_write         (const NFSOperation& operation) = 0;
    virtual bool call_create        (const NFSOperation& operation) = 0;
    virtual bool call_mkdir         (const NFSOperation& operation) = 0;
    virtual bool call_symlink       (const NFSOperation& operation) = 0;
    virtual bool call_mknod         (const NFSOperation& operation) = 0;
    virtual bool call_remove        (const NFSOperation& operation) = 0;
    virtual bool call_rmdir         (const NFSOperation& operation) = 0;
    virtual bool call_rename        (const NFSOperation& operation) = 0;
    virtual bool call_link          (const NFSOperation& operation) = 0;
    virtual bool call_readdir       (const NFSOperation& operation) = 0;
    virtual bool call_readdirplus   (const NFSOperation& operation) = 0;
    virtual bool call_fsstat        (const NFSOperation& operation) = 0;
    virtual bool call_fsinfo        (const NFSOperation& operation) = 0;
    virtual bool call_pathconf      (const NFSOperation& operation) = 0;
    virtual bool call_commit        (const NFSOperation& operation) = 0;
    virtual void print(std::ostream& out) = 0;
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_ANALYZER_H
//------------------------------------------------------------------------------
