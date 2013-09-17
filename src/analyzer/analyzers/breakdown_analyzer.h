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

#include "base_analyzer.h"
#include "breakdown.h"
//------------------------------------------------------------------------------
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
    struct Hash
    {
        std::size_t operator() (const Session& s) const
        {
            return s.port[0] + s.port[1] + s.ip.v4.addr[0] + s.ip.v4.addr[1];
        }
    };

    struct Pred
    {
        bool operator() (const Session& a, const Session& b) const
        {
            return (a.port[0] == b.port[0]) &&
                    (a.port[1] == b.port[1]) &&
                    (a.ip.v4.addr[0] == b.ip.v4.addr[0]) &&
                    (a.ip.v4.addr[1] == b.ip.v4.addr[1]);
        }
    };

    typedef std::tr1::unordered_map<Session, Breakdown*, Hash, Pred> PerOpStat;
    typedef PerOpStat::value_type Pair;
//    typedef std::pair<Iterator, bool> Inserted;
public:
    BreakdownAnalyzer(std::ostream& o) : total(0), ops_count(22, 0), out(o)
    {
    }
    virtual ~BreakdownAnalyzer()
    {
        PerOpStat::iterator i = per_op_stat.begin();
        PerOpStat::iterator end = per_op_stat.end();
        for(; i != end;)
        {
            delete i->second;
            i = per_op_stat.erase(i);
        }
    }

    virtual void null(const struct RPCProcedure* proc,
            const struct NULLargs* args,
            const struct NULLres* res);
    virtual void getattr3(const struct RPCProcedure* proc,
            const struct GETATTR3args* args,
            const struct GETATTR3res* res);
    virtual void setattr3(const struct RPCProcedure* proc,
            const struct SETATTR3args* args,
            const struct SETATTR3res* res);
    virtual void lookup3(const struct RPCProcedure* proc,
            const struct LOOKUP3args* args,
            const struct LOOKUP3res* res);
    virtual void access3(const struct RPCProcedure* proc,
            const struct ACCESS3args* args,
            const struct ACCESS3res* res);
    virtual void readlink3(const struct RPCProcedure* proc,
            const struct READLINK3args* args,
            const struct READLINK3res* res);
    virtual void read3(const struct RPCProcedure* proc,
            const struct READ3args* args,
            const struct READ3res* res);
    virtual void write3(const struct RPCProcedure* proc,
            const struct WRITE3args* args,
            const struct WRITE3res* res);
    virtual void create3(const struct RPCProcedure* proc,
            const struct CREATE3args* args,
            const struct CREATE3res* res);
    virtual void mkdir3(const struct RPCProcedure* proc,
            const struct MKDIR3args* args,
            const struct MKDIR3res* res);
    virtual void symlink3(const struct RPCProcedure* proc,
            const struct SYMLINK3args* args,
            const struct SYMLINK3res* res);
    virtual void mknod3(const struct RPCProcedure* proc,
            const struct MKNOD3args* args,
            const struct MKNOD3res* res);
    virtual void remove3(const struct RPCProcedure* proc,
            const struct REMOVE3args* args,
            const struct REMOVE3res* res);
    virtual void rmdir3(const struct RPCProcedure* proc,
            const struct RMDIR3args* args,
            const struct RMDIR3res* res);
    virtual void rename3(const struct RPCProcedure* proc,
            const struct RENAME3args* args,
            const struct RENAME3res* res);
    virtual void link3(const struct RPCProcedure* proc,
            const struct LINK3args* args,
            const struct LINK3res* res);
    virtual void readdir3(const struct RPCProcedure* proc,
            const struct READDIR3args* args,
            const struct READDIR3res* res);
    virtual void readdirplus3(const struct RPCProcedure* proc,
            const struct READDIRPLUS3args* args,
            const struct READDIRPLUS3res* res);
    virtual void fsstat3(const struct RPCProcedure* proc,
            const struct FSSTAT3args* args,
            const struct FSSTAT3res* res);
    virtual void fsinfo3(const struct RPCProcedure* proc,
            const struct FSINFO3args* args,
            const struct FSINFO3res* res);
    virtual void pathconf3(const struct RPCProcedure* proc,
            const struct PATHCONF3args* args,
            const struct PATHCONF3res* res);
    virtual void commit3(const struct RPCProcedure* proc,
            const struct COMMIT3args* args,
            const struct COMMIT3res* res);

    virtual void flush_statistics();

private:
    void account(const struct RPCProcedure* proc);
    uint64_t total;
    std::vector<int> ops_count;
    PerOpStat per_op_stat;
    std::ostream& out;
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//BREAKDOWN_ANALYZER_H
//------------------------------------------------------------------------------
