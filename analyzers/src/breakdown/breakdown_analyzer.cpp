//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Operation breakdown analyzer. Identify clients that are busier than others.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "breakdown_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

void BreakdownAnalyzer::null(const struct RPCProcedure* proc,
                             const struct NULLargs* args,
                             const struct NULLres* res)
{
    account(proc);
}

void BreakdownAnalyzer::getattr3(const RPCProcedure* proc,
                                 const struct GETATTR3args* args,
                                 const struct GETATTR3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::setattr3(const RPCProcedure* proc,
                                 const struct SETATTR3args* args,
                                 const struct SETATTR3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::lookup3(const RPCProcedure* proc,
                                const struct LOOKUP3args* args,
                                const struct LOOKUP3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::access3(const struct RPCProcedure* proc,
                                const struct ACCESS3args* args,
                                const struct ACCESS3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::readlink3(const struct RPCProcedure* proc,
                                  const struct READLINK3args* args,
                                  const struct READLINK3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::read3(const struct RPCProcedure* proc,
                              const struct READ3args* args,
                              const struct READ3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::write3(const struct RPCProcedure* proc,
                               const struct WRITE3args* args,
                               const struct WRITE3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::create3(const struct RPCProcedure* proc,
                                const struct CREATE3args* args,
                                const struct CREATE3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::mkdir3(const struct RPCProcedure* proc,
                               const struct MKDIR3args* args,
                               const struct MKDIR3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::symlink3(const struct RPCProcedure* proc,
                                 const struct SYMLINK3args* args,
                                 const struct SYMLINK3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::mknod3(const struct RPCProcedure* proc,
                               const struct MKNOD3args* args,
                               const struct MKNOD3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::remove3(const struct RPCProcedure* proc,
                                const struct REMOVE3args* args,
                                const struct REMOVE3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::rmdir3(const struct RPCProcedure* proc,
                               const struct RMDIR3args* args,
                               const struct RMDIR3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::rename3(const struct RPCProcedure* proc,
                                const struct RENAME3args* args,
                                const struct RENAME3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::link3(const struct RPCProcedure* proc,
                              const struct LINK3args* args,
                              const struct LINK3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::readdir3(const struct RPCProcedure* proc,
                                 const struct READDIR3args* args,
                                 const struct READDIR3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::readdirplus3(const struct RPCProcedure* proc,
                                     const struct READDIRPLUS3args* args,
                                     const struct READDIRPLUS3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::fsstat3(const struct RPCProcedure* proc,
                                const struct FSSTAT3args* args,
                                const struct FSSTAT3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::fsinfo3(const struct RPCProcedure* proc,
                                const struct FSINFO3args* args,
                                const struct FSINFO3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::pathconf3(const struct RPCProcedure* proc,
                                  const struct PATHCONF3args* args,
                                  const struct PATHCONF3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::commit3(const struct RPCProcedure* proc,
                                const struct COMMIT3args* args,
                                const struct COMMIT3res* res)
{
    account(proc);
}

void BreakdownAnalyzer::flush_statistics()
{
    out << "###  Breakdown analyzer  ###" << std::endl;
    out << "Total calls: " << total << ". Per operation:" << std::endl;
    for(int i = 0; i < ProcEnum::count; ++i)
    {          
        out.width(12);
        out << std::left << static_cast<ProcEnum::NFSProcedure>(i);
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
    PerOpStat::iterator it = per_op_stat.begin();
    PerOpStat::iterator end = per_op_stat.end();
    for(; it != end; ++it)
    {
        out << "Session: " << it->first << std::endl;
        const Breakdown& current = *it->second;
        uint64_t s_total = 0;
        for(int i = 0; i < ProcEnum::count; ++i)
        {
            s_total += current[i].get_count();
        }
        out << "Total: " << s_total << ". Per operation:" << std::endl;
        for(int i = 0; i < ProcEnum::count; ++i)
        {
            out.width(14);
            out << std::left << static_cast<ProcEnum::NFSProcedure>(i);
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

void BreakdownAnalyzer::account(const struct RPCProcedure* proc)
{
    const int op = proc->call.proc;
    ++total;
    ++ops_count[op];

    PerOpStat::const_iterator i = per_op_stat.find(*(proc->session));
    if(i == per_op_stat.end())
    {
        std::pair<PerOpStat::iterator, bool> res = per_op_stat.insert(Pair(*(proc->session), new Breakdown()));
        if(res.second == false)
        {
            return;
        }
        i = res.first;
    }

    timeval latency;
    timersub(proc->rtimestamp, proc->ctimestamp, &latency); // reply - call timestamps

    Latencies& lat = (*i->second)[op];
    lat.add(latency);
}

extern "C"
{

BaseAnalyzer* create(const char* opts)
{
    return new BreakdownAnalyzer();
}

void destroy(BaseAnalyzer* context)
{
    delete context;
}

const char* usage()
{
    return "Do what you want!";
}

}

//------------------------------------------------------------------------------
