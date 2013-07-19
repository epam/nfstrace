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

bool BreakdownAnalyzer::call_null(const NFSOperation& operation)
{
    account(Proc::NFS_NULL, operation);
    return true;
}

bool BreakdownAnalyzer::call_getattr(const NFSOperation& operation)
{
    account(Proc::GETATTR, operation);
    return true;
}

bool BreakdownAnalyzer::call_setattr(const NFSOperation& operation)
{
    account(Proc::SETATTR, operation);
    return true;
}

bool BreakdownAnalyzer::call_lookup(const NFSOperation& operation)
{
    account(Proc::LOOKUP, operation);
    return true;
}

bool BreakdownAnalyzer::call_access(const NFSOperation& operation)
{
    account(Proc::ACCESS, operation);
    return true;
}

bool BreakdownAnalyzer::call_readlink(const NFSOperation& operation)
{
    account(Proc::READLINK, operation);
    return true;
}

bool BreakdownAnalyzer::call_read(const NFSOperation& operation)
{
    account(Proc::READ, operation);
    return true;
}

bool BreakdownAnalyzer::call_write(const NFSOperation& operation)
{
    account(Proc::WRITE, operation);
    return true;
}

bool BreakdownAnalyzer::call_create(const NFSOperation& operation)
{
    account(Proc::CREATE, operation);
    return true;
}

bool BreakdownAnalyzer::call_mkdir(const NFSOperation& operation)
{
    account(Proc::MKDIR, operation);
    return true;
}

bool BreakdownAnalyzer::call_symlink(const NFSOperation& operation)
{
    account(Proc::SYMLINK, operation);
    return true;
}

bool BreakdownAnalyzer::call_mknod(const NFSOperation& operation)
{
    account(Proc::MKNOD, operation);
    return true;
}

bool BreakdownAnalyzer::call_remove(const NFSOperation& operation)
{
    account(Proc::REMOVE, operation);
    return true;
}

bool BreakdownAnalyzer::call_rmdir(const NFSOperation& operation)
{
    account(Proc::RMDIR, operation);
    return true;
}

bool BreakdownAnalyzer::call_rename(const NFSOperation& operation)
{
    account(Proc::RENAME, operation);
    return true;
}

bool BreakdownAnalyzer::call_link(const NFSOperation& operation)
{
    account(Proc::LINK, operation);
    return true;
}

bool BreakdownAnalyzer::call_readdir(const NFSOperation& operation)
{
    account(Proc::READDIR, operation);
    return true;
}

bool BreakdownAnalyzer::call_readdirplus(const NFSOperation& operation)
{
    account(Proc::READDIRPLUS, operation);
    return true;
}

bool BreakdownAnalyzer::call_fsstat(const NFSOperation& operation)
{
    account(Proc::FSSTAT, operation);
    return true;
}

bool BreakdownAnalyzer::call_fsinfo(const NFSOperation& operation)
{
    account(Proc::FSINFO, operation);
    return true;
}

bool BreakdownAnalyzer::call_pathconf(const NFSOperation& operation)
{
    account(Proc::PATHCONF, operation);
    return true;
}

bool BreakdownAnalyzer::call_commit(const NFSOperation& operation)
{
    account(Proc::COMMIT, operation);
    return true;
}

void BreakdownAnalyzer::print(std::ostream& out)
{
    out << "###  Breakdown analyzer  ###" << std::endl;
    out << "Total calls: " << total << ". Per operation:" << std::endl;
    for(int i = 0; i < Proc::num; ++i)
    {          
        out.width(12);
        out << std::left << Proc::titles[i];
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
            out << std::left << Proc::titles[i];
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

bool BreakdownAnalyzer::account(Proc::Ops op, const NFSOperation& operation)
{
    ++total;
    ++ops_count[op];

    const NFSOperation::Session* session = operation.get_session();
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
