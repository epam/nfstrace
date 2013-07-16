//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Operation breakdown analyzer. Identify clients that are busier than others.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BREAKDOWN_ANALYZER_H
#define BREAKDOWN_ANALYZER_H
//------------------------------------------------------------------------------
#include <tr1/unordered_map>
#include <vector>

#include "../../auxiliary/session.h"
#include "../../filter/nfs/nfs_operation.h"
#include "../../filter/nfs/nfs_procedures.h"
#include "base_analyzer.h"
#include "breakdown.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Session;
using NST::filter::NFS3::NFSOperation;
using NST::filter::NFS3::Proc;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

class BreakdownAnalyzer : public BaseAnalyzer
{
    typedef std::tr1::unordered_map<Session, Breakdown*, Session::Hash> PerOpStat;
    typedef PerOpStat::value_type Pair;
    typedef PerOpStat::iterator Iterator;
    typedef PerOpStat::const_iterator ConstIterator;
    typedef std::pair<Iterator, bool> Inserted;
public:
    BreakdownAnalyzer() : total(0), ops_count(22, 0)
    {
    }
    virtual ~BreakdownAnalyzer()
    {
        Iterator i = per_op_stat.begin();
        Iterator end = per_op_stat.end();
        for(; i != end;)
        {
            i = per_op_stat.erase(i);
        }
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
    bool account(Proc::Ops op, const NFSOperation& operation);
    int total;
    std::vector<int> ops_count;
    PerOpStat per_op_stat; 
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BREAKDOWN_ANALYZER_H
//------------------------------------------------------------------------------
