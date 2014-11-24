//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source file for WatchAnalyzer based on TestAnalyzer.cpp 
// Copyright (c) 2014 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#include <iostream>
#include <unistd.h>
#include <string>

#include <utils/log.h>
#include "watch_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
WatchAnalyzer::WatchAnalyzer(const char* opts)
: nfs3_proc_total {0}
, nfs3_proc_count (ProcEnumNFS3::count, 0)
, nfs4_proc_total {0}
, nfs4_ops_total  {0}
, nfs4_proc_count (ProcEnumNFS4::count, 0)
, write_number    {5}
, options         {opts}
, monitor_running {ATOMIC_FLAG_INIT}
, refresh_delta   {atol(opts) > 0 ? atol(opts) : 2000}
{
    sem_init(&read_sem, 0, write_number);
    monitor_running.test_and_set();
    monitor_thread = std::thread(&WatchAnalyzer::thread, this);
}

WatchAnalyzer::~WatchAnalyzer()
{

    if (monitor_thread.joinable()) {
        monitor_running.clear();
        monitor_thread.join();
    }
    sem_wait(&read_sem);
    sem_destroy(&read_sem);
}

void WatchAnalyzer::null(const struct RPCProcedure* proc,
          const struct rpcgen::NULL3args*,
          const struct rpcgen::NULL3res*) { account(proc); }
void WatchAnalyzer::getattr3(const struct RPCProcedure* proc,
              const struct rpcgen::GETATTR3args*,
              const struct rpcgen::GETATTR3res*) { account(proc); }
void WatchAnalyzer::setattr3(const struct RPCProcedure* proc,
              const struct rpcgen::SETATTR3args*,
              const struct rpcgen::SETATTR3res*) { account(proc); }
void WatchAnalyzer::lookup3(const struct RPCProcedure* proc,
             const struct rpcgen::LOOKUP3args*,
             const struct rpcgen::LOOKUP3res*) { account(proc); }
void WatchAnalyzer::access3(const struct RPCProcedure* proc,
             const struct rpcgen::ACCESS3args*,
             const struct rpcgen::ACCESS3res*) { account(proc); }
void WatchAnalyzer::readlink3(const struct RPCProcedure* proc,
               const struct rpcgen::READLINK3args*,
               const struct rpcgen::READLINK3res*) { account(proc); }
void WatchAnalyzer::read3(const struct RPCProcedure* proc,
           const struct rpcgen::READ3args*,
           const struct rpcgen::READ3res*) { account(proc); }
void WatchAnalyzer::write3(const struct RPCProcedure* proc,
            const struct rpcgen::WRITE3args*,
            const struct rpcgen::WRITE3res*) { account(proc); }
void WatchAnalyzer::create3(const struct RPCProcedure* proc,
             const struct rpcgen::CREATE3args*,
             const struct rpcgen::CREATE3res*) { account(proc); }
void WatchAnalyzer::mkdir3(const struct RPCProcedure* proc,
            const struct rpcgen::MKDIR3args*,
            const struct rpcgen::MKDIR3res*) { account(proc); }
void WatchAnalyzer::symlink3(const struct RPCProcedure* proc,
             const struct rpcgen::SYMLINK3args*,
             const struct rpcgen::SYMLINK3res*) { account(proc); }
void WatchAnalyzer::mknod3(const struct RPCProcedure* proc,
            const struct rpcgen::MKNOD3args*,
            const struct rpcgen::MKNOD3res*) { account(proc); }
void WatchAnalyzer::remove3(const struct RPCProcedure* proc,
             const struct rpcgen::REMOVE3args*,
             const struct rpcgen::REMOVE3res*) { account(proc); }
void WatchAnalyzer::rmdir3(const struct RPCProcedure* proc,
            const struct rpcgen::RMDIR3args*,
            const struct rpcgen::RMDIR3res*) { account(proc); }
void WatchAnalyzer::rename3(const struct RPCProcedure* proc,
             const struct rpcgen::RENAME3args*,
             const struct rpcgen::RENAME3res*) { account(proc); }
void WatchAnalyzer::link3(const struct RPCProcedure* proc,
           const struct rpcgen::LINK3args*,
           const struct rpcgen::LINK3res*) { account(proc); }
void WatchAnalyzer::readdir3(const struct RPCProcedure* proc,
              const struct rpcgen::READDIR3args*,
              const struct rpcgen::READDIR3res*) { account(proc); }
void WatchAnalyzer::readdirplus3(const struct RPCProcedure* proc,
                  const struct rpcgen::READDIRPLUS3args*,
                  const struct rpcgen::READDIRPLUS3res*) { account(proc); }
void WatchAnalyzer::fsstat3(const struct RPCProcedure* proc,
             const struct rpcgen::FSSTAT3args*,
             const struct rpcgen::FSSTAT3res*) { account(proc); }
void WatchAnalyzer::fsinfo3(const struct RPCProcedure* proc,
             const struct rpcgen::FSINFO3args*,
             const struct rpcgen::FSINFO3res*) { account(proc); }
void WatchAnalyzer::pathconf3(const struct RPCProcedure* proc,
               const struct rpcgen::PATHCONF3args*,
               const struct rpcgen::PATHCONF3res*) { account(proc); }
void WatchAnalyzer::commit3(const struct RPCProcedure* proc,
             const struct rpcgen::COMMIT3args*,
             const struct rpcgen::COMMIT3res*) { account(proc); }

void WatchAnalyzer::null(const struct RPCProcedure* proc,
          const struct rpcgen::NULL4args*,
          const struct rpcgen::NULL4res*) { account(proc); }
void WatchAnalyzer::compound4(const struct RPCProcedure*  proc,
               const struct rpcgen::COMPOUND4args*,
               const struct rpcgen::COMPOUND4res*  res) { account(proc, res); }

void WatchAnalyzer::flush_statistics()
{
}

void WatchAnalyzer::account(const struct RPCProcedure* proc,
                const struct rpcgen::COMPOUND4res* res)
{
    const u_int nfs_proc = proc->rpc_call.ru.RM_cmb.cb_proc;
    const u_int nfs_vers = proc->rpc_call.ru.RM_cmb.cb_vers;
    for(uint16_t i = 0; i < write_number; i++)
        sem_wait(&read_sem);
    if(nfs_vers == NFS_V4)
    {
        ++nfs4_proc_total;
        ++nfs4_proc_count[nfs_proc];
        if(res)
        {
            nfs4_ops_total += res->resarray.resarray_len;
            rpcgen::nfs_resop4* current_el = res->resarray.resarray_val;
            for(unsigned j = 0; j < (res->resarray.resarray_len); j++, current_el++)
            {
                // In all cases we suppose, that NFSv4 operation ILLEGAL(10044)
                // has the second position in ProcEnumNFS4
                u_int nfs_oper = current_el->resop;
                if(nfs_oper == ProcEnumNFS4::NFSProcedure::ILLEGAL) nfs_oper = 2;
                ++nfs4_proc_count[nfs_oper];
            }
        }
    }

    if(nfs_vers == NFS_V3)
    {
        ++nfs3_proc_total;
        ++nfs3_proc_count[nfs_proc];
    }
    for(uint16_t i = 0; i < write_number; i++)
        sem_post(&read_sem);
}

void WatchAnalyzer::getStatistic( uint64_t &nfs3_total, std::vector<int> nfs3_pr_count,
                   uint64_t &nfs4_total_ops, uint64_t &nfs4_pr_total,
                   std::vector<int> nfs4_pr_count)
{

    sem_wait(&read_sem);
    nfs3_total = nfs3_proc_total;
    nfs4_total_ops = nfs4_ops_total;
    nfs4_pr_total = nfs4_proc_total;
    nfs3_pr_count.insert(nfs3_pr_count.begin(), nfs3_proc_count.begin(), nfs3_proc_count.end());
    nfs3_pr_count.insert(nfs4_pr_count.begin(), nfs4_proc_count.begin(), nfs4_proc_count.end());
    sem_post(&read_sem);
}
//----------------------------------------------------------------------------
inline void WatchAnalyzer::thread()
{
    try
    {
        while (monitor_running.test_and_set())
        {
            pl.updatePlot(nfs3_proc_total, nfs3_proc_count, nfs4_ops_total, nfs4_proc_total, nfs4_proc_count);
            std::this_thread::sleep_for(std::chrono::milliseconds(refresh_delta));
        }
    } catch(...) {
        std::cerr << "Watch plugin Unidentifying exception.";
//        throw std::runtime_error("Watch plugin Unidentifying exception.");
    }
}
//------------------------------------------------------------------------------
extern "C"
{

const char* usage()
{
    return "User can set chrono output timeout in msec.";
}

IAnalyzer* create(const char* opts)
{
    return new WatchAnalyzer(opts);
}

void destroy(IAnalyzer* instance)
{
    delete instance;
}

/*
bool output()
{
    return false;
}
*/
NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)
}
//------------------------------------------------------------------------------
