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

#include "../rpc_sessions.h"
#include "../nfs3/nfs_operation.h"
#include "base_analyzer.h"
#include "breakdown.h"
//------------------------------------------------------------------------------
using NST::analyzer::RPC::RPCOperation;
//using NST::analyzer::RPCSession;
using NST::analyzer::NFS3::Proc;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

class BreakdownAnalyzer : public BaseAnalyzer
{
    typedef std::tr1::unordered_map<RPCSession::Session, Breakdown*, Session::Hash> PerOpStat;
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
            delete i->second;
            i = per_op_stat.erase(i);
        }
    }

    virtual bool call_null       (const RPCOperation& operation);
    virtual bool call_getattr    (const RPCOperation& operation);
    virtual bool call_setattr    (const RPCOperation& operation);
    virtual bool call_lookup     (const RPCOperation& operation);
    virtual bool call_access     (const RPCOperation& operation);
    virtual bool call_readlink   (const RPCOperation& operation);
    virtual bool call_read       (const RPCOperation& operation);
    virtual bool call_write      (const RPCOperation& operation);
    virtual bool call_create     (const RPCOperation& operation);
    virtual bool call_mkdir      (const RPCOperation& operation);
    virtual bool call_symlink    (const RPCOperation& operation);
    virtual bool call_mknod      (const RPCOperation& operation);
    virtual bool call_remove     (const RPCOperation& operation);
    virtual bool call_rmdir      (const RPCOperation& operation);
    virtual bool call_rename     (const RPCOperation& operation);
    virtual bool call_link       (const RPCOperation& operation);
    virtual bool call_readdir    (const RPCOperation& operation);
    virtual bool call_readdirplus(const RPCOperation& operation);
    virtual bool call_fsstat     (const RPCOperation& operation);
    virtual bool call_fsinfo     (const RPCOperation& operation);
    virtual bool call_pathconf   (const RPCOperation& operation);
    virtual bool call_commit     (const RPCOperation& operation);
    virtual void print(std::ostream& out);

private:
    bool account(NFS3::Proc::Enum op, const RPCOperation& operation);
    uint64_t total;
    std::vector<int> ops_count;
    PerOpStat per_op_stat;
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BREAKDOWN_ANALYZER_H
//------------------------------------------------------------------------------
