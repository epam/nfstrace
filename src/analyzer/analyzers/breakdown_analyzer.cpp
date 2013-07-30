//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Operation breakdown analyzer. Identify clients that are busier than others.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "breakdown_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

bool BreakdownAnalyzer::call_null(const RPCOperation& operation)
{
    account(NFS3::Proc::NFS_NULL, operation);
    return true;
}

bool BreakdownAnalyzer::call_getattr(const RPCOperation& operation)
{
    account(NFS3::Proc::GETATTR, operation);
    return true;
}

bool BreakdownAnalyzer::call_setattr(const RPCOperation& operation)
{
    account(NFS3::Proc::SETATTR, operation);
    return true;
}

bool BreakdownAnalyzer::call_lookup(const RPCOperation& operation)
{
    account(NFS3::Proc::LOOKUP, operation);
    return true;
}

bool BreakdownAnalyzer::call_access(const RPCOperation& operation)
{
    account(NFS3::Proc::ACCESS, operation);
    return true;
}

bool BreakdownAnalyzer::call_readlink(const RPCOperation& operation)
{
    account(NFS3::Proc::READLINK, operation);
    return true;
}

bool BreakdownAnalyzer::call_read(const RPCOperation& operation)
{
    account(NFS3::Proc::READ, operation);
    return true;
}

bool BreakdownAnalyzer::call_write(const RPCOperation& operation)
{
    account(NFS3::Proc::WRITE, operation);
    return true;
}

bool BreakdownAnalyzer::call_create(const RPCOperation& operation)
{
    account(NFS3::Proc::CREATE, operation);
    return true;
}

bool BreakdownAnalyzer::call_mkdir(const RPCOperation& operation)
{
    account(NFS3::Proc::MKDIR, operation);
    return true;
}

bool BreakdownAnalyzer::call_symlink(const RPCOperation& operation)
{
    account(NFS3::Proc::SYMLINK, operation);
    return true;
}

bool BreakdownAnalyzer::call_mknod(const RPCOperation& operation)
{
    account(NFS3::Proc::MKNOD, operation);
    return true;
}

bool BreakdownAnalyzer::call_remove(const RPCOperation& operation)
{
    account(NFS3::Proc::REMOVE, operation);
    return true;
}

bool BreakdownAnalyzer::call_rmdir(const RPCOperation& operation)
{
    account(NFS3::Proc::RMDIR, operation);
    return true;
}

bool BreakdownAnalyzer::call_rename(const RPCOperation& operation)
{
    account(NFS3::Proc::RENAME, operation);
    return true;
}

bool BreakdownAnalyzer::call_link(const RPCOperation& operation)
{
    account(NFS3::Proc::LINK, operation);
    return true;
}

bool BreakdownAnalyzer::call_readdir(const RPCOperation& operation)
{
    account(NFS3::Proc::READDIR, operation);
    return true;
}

bool BreakdownAnalyzer::call_readdirplus(const RPCOperation& operation)
{
    account(NFS3::Proc::READDIRPLUS, operation);
    return true;
}

bool BreakdownAnalyzer::call_fsstat(const RPCOperation& operation)
{
    account(NFS3::Proc::FSSTAT, operation);
    return true;
}

bool BreakdownAnalyzer::call_fsinfo(const RPCOperation& operation)
{
    account(NFS3::Proc::FSINFO, operation);
    return true;
}

bool BreakdownAnalyzer::call_pathconf(const RPCOperation& operation)
{
    account(NFS3::Proc::PATHCONF, operation);
    return true;
}

bool BreakdownAnalyzer::call_commit(const RPCOperation& operation)
{
    account(NFS3::Proc::COMMIT, operation);
    return true;
}

void BreakdownAnalyzer::print(std::ostream& out)
{
    out << "###  Breakdown analyzer  ###" << std::endl;
    out << "Total calls: " << total << ". Per operation:" << std::endl;
    for(int i = 0; i < NFS3::Proc::num; ++i)
    {          
        out.width(12);
        out << std::left << NFS3::Proc::Titles[i];
        out.width(5);
        out << std::right << ops_count[i];
        out.width(7);
        out.precision(2);
        if(total)
            out << std::fixed << (double(ops_count[i]) / total) * 100;
        else
            out << 0;
        out << "%" << std::endl;
    }

    out << "Per connection info: " << std::endl;
    Iterator it = per_op_stat.begin();
    Iterator end = per_op_stat.end();
    for(; it != end; ++it)
    {
        out << "Session: " << it->first << std::endl;
        const Breakdown& current = *it->second;
        uint64_t s_total = 0;
        for(int i = 0; i < Proc::num; ++i)
        {
            s_total += current[i].get_count();
        }
        out << "Total: " << s_total << ". Per operation:" << std::endl;
        for(int i = 0; i < Proc::num; ++i)
        {
            out.width(14);
            out << std::left << NFS3::Proc::Titles[i];
            out.width(6);
            out << " Count:";
            out.width(5);
            out << std::right << current[i].get_count();
            out << " ";
            out.precision(2);
            out << "(";
            out.width(6);
            out << std::fixed << ((long double)(current[i].get_count()) / s_total) * 100;
            out << "%)";
            out << " Min: ";
            out.precision(3);
            out << std::fixed << Latencies::to_sec(current[i].get_min());
            out << " Max: ";
            out << std::fixed << Latencies::to_sec(current[i].get_max());
            out << " Avg: ";
            out << std::fixed << current[i].get_avg();
            out.precision(8);
            out << " StDev: ";
            out << std::fixed << current[i].get_st_dev() << std::endl;
        }
    }
}

bool BreakdownAnalyzer::account(NFS3::Proc::Enum op, const RPCOperation& operation)
{
    ++total;
    ++ops_count[op];

    const RPCSession& rpc_session = operation.get_session();
    const RPCSession::Session* session = rpc_session.get_session();
    Iterator el = per_op_stat.find(*session);
    if(el == per_op_stat.end())
    {
        Inserted res = per_op_stat.insert(Pair(*session, new Breakdown()));
        if(res.second == false)
            return false;
        el = res.first;
    }
    Latencies& lat = (*el->second)[op];
    lat.add(operation.latency());
    
    return true;
}

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
