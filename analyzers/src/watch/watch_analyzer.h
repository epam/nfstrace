//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for WatchAnalyzer based on TestAnalyzer.h 
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
#ifndef WATCH_ANALYZER_H
#define WATCH_ANALYZER_H 
//------------------------------------------------------------------------------
#include <cstdint>
#include <cstring>
#include <cmath>
#include <ctime>

#include <atomic>
#include <iostream>
#include <vector>
#include <semaphore.h>
#include <thread>

#include <api/plugin_api.h> // include plugin development definitions
#include <plotter.h>
//------------------------------------------------------------------------------

class WatchAnalyzer : public IAnalyzer
{
public:
    WatchAnalyzer(const char* opts);

    ~WatchAnalyzer();

   void flush_statistics();

    void null(const struct RPCProcedure* proc,
              const struct rpcgen::NULL3args*,
              const struct rpcgen::NULL3res*) override final ;
    void getattr3(const struct RPCProcedure* proc,
                  const struct rpcgen::GETATTR3args*,
                  const struct rpcgen::GETATTR3res*) override final ;
    void setattr3(const struct RPCProcedure* proc,
                  const struct rpcgen::SETATTR3args*,
                  const struct rpcgen::SETATTR3res*) override final ;
    void lookup3(const struct RPCProcedure* proc,
                 const struct rpcgen::LOOKUP3args*,
                 const struct rpcgen::LOOKUP3res*) override final ;
    void access3(const struct RPCProcedure* proc,
                 const struct rpcgen::ACCESS3args*,
                 const struct rpcgen::ACCESS3res*) override final ;
    void readlink3(const struct RPCProcedure* proc,
                   const struct rpcgen::READLINK3args*,
                   const struct rpcgen::READLINK3res*) override final ;
    void read3(const struct RPCProcedure* proc,
               const struct rpcgen::READ3args*,
               const struct rpcgen::READ3res*) override final ;
    void write3(const struct RPCProcedure* proc,
                const struct rpcgen::WRITE3args*,
                const struct rpcgen::WRITE3res*) override final ;
    void create3(const struct RPCProcedure* proc,
                 const struct rpcgen::CREATE3args*,
                 const struct rpcgen::CREATE3res*) override final ;
    void mkdir3(const struct RPCProcedure* proc,
                const struct rpcgen::MKDIR3args*,
                const struct rpcgen::MKDIR3res*) override final ;
    void symlink3(const struct RPCProcedure* proc,
                 const struct rpcgen::SYMLINK3args*,
                 const struct rpcgen::SYMLINK3res*) override final ;
    void mknod3(const struct RPCProcedure* proc,
                const struct rpcgen::MKNOD3args*,
                const struct rpcgen::MKNOD3res*) override final ;
    void remove3(const struct RPCProcedure* proc,
                 const struct rpcgen::REMOVE3args*,
                 const struct rpcgen::REMOVE3res*) override final ;
    void rmdir3(const struct RPCProcedure* proc,
                const struct rpcgen::RMDIR3args*,
                const struct rpcgen::RMDIR3res*) override final ;
    void rename3(const struct RPCProcedure* proc,
                 const struct rpcgen::RENAME3args*,
                 const struct rpcgen::RENAME3res*) override final ;
    void link3(const struct RPCProcedure* proc,
               const struct rpcgen::LINK3args*,
               const struct rpcgen::LINK3res*) override final ;
    void readdir3(const struct RPCProcedure* proc,
                  const struct rpcgen::READDIR3args*,
                  const struct rpcgen::READDIR3res*) override final ;
    void readdirplus3(const struct RPCProcedure* proc,
                      const struct rpcgen::READDIRPLUS3args*,
                      const struct rpcgen::READDIRPLUS3res*) override final ;
    void fsstat3(const struct RPCProcedure* proc,
                 const struct rpcgen::FSSTAT3args*,
                 const struct rpcgen::FSSTAT3res*) override final ;
    void fsinfo3(const struct RPCProcedure* proc,
                 const struct rpcgen::FSINFO3args*,
                 const struct rpcgen::FSINFO3res*) override final ;
    void pathconf3(const struct RPCProcedure* proc,
                   const struct rpcgen::PATHCONF3args*,
                   const struct rpcgen::PATHCONF3res*) override final ;
    void commit3(const struct RPCProcedure* proc,
                 const struct rpcgen::COMMIT3args*,
                 const struct rpcgen::COMMIT3res*) override final ;

    void null(const struct RPCProcedure* proc,
              const struct rpcgen::NULL4args*,
              const struct rpcgen::NULL4res*) override final ;
    void compound4(const struct RPCProcedure*  proc,
                   const struct rpcgen::COMPOUND4args*,
                   const struct rpcgen::COMPOUND4res*) override final ;
private:
    inline void thread();
    void count_proc(const struct RPCProcedure* proc);
    void account(const struct RPCProcedure*,
                 const struct rpcgen::COMPOUND4res* res = nullptr);

    void getStatistic( uint64_t &nfs3_total, std::vector<int> nfs3_pr_count,
                       uint64_t &nfs4_ops_total, uint64_t &nfs4_pr_total,
                       std::vector<int> nfs4_pr_count);

    uint64_t nfs3_proc_total;
    std::vector<int> nfs3_proc_count;

    uint64_t nfs4_proc_total;
    uint64_t nfs4_ops_total;
    std::vector<int> nfs4_proc_count;

    sem_t read_sem;

    const uint32_t write_number;

    std::string options;

    std::thread monitor_thread;
    std::atomic_flag monitor_running;

    long int refresh_delta=2000;

    Plotter pl;
};
//------------------------------------------------------------------------------
#endif //WATCH_ANALYZER_H
//------------------------------------------------------------------------------
