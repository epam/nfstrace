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
#include <atomic>
#include <condition_variable>

#include <api/plugin_api.h> // include plugin development definitions
#include "plotter.h"
//------------------------------------------------------------------------------
class WatchAnalyzer : public IAnalyzer
{
public:
    WatchAnalyzer(const char* opts);
    ~WatchAnalyzer();

    void flush_statistics() override final;
    void on_unix_signal(int signo) override final;

    void null(const RPCProcedure* proc,
              const struct NFS3::NULL3args*,
              const struct NFS3::NULL3res*) override final;
    void getattr3(const RPCProcedure* proc,
                  const struct NFS3::GETATTR3args*,
                  const struct NFS3::GETATTR3res*) override final;
    void setattr3(const RPCProcedure* proc,
                  const struct NFS3::SETATTR3args*,
                  const struct NFS3::SETATTR3res*) override final;
    void lookup3(const RPCProcedure* proc,
                 const struct NFS3::LOOKUP3args*,
                 const struct NFS3::LOOKUP3res*) override final;
    void access3(const RPCProcedure* proc,
                 const struct NFS3::ACCESS3args*,
                 const struct NFS3::ACCESS3res*) override final;
    void readlink3(const RPCProcedure* proc,
                   const struct NFS3::READLINK3args*,
                   const struct NFS3::READLINK3res*) override final;
    void read3(const RPCProcedure* proc,
               const struct NFS3::READ3args*,
               const struct NFS3::READ3res*) override final;
    void write3(const RPCProcedure* proc,
                const struct NFS3::WRITE3args*,
                const struct NFS3::WRITE3res*) override final;
    void create3(const RPCProcedure* proc,
                 const struct NFS3::CREATE3args*,
                 const struct NFS3::CREATE3res*) override final;
    void mkdir3(const RPCProcedure* proc,
                const struct NFS3::MKDIR3args*,
                const struct NFS3::MKDIR3res*) override final;
    void symlink3(const RPCProcedure* proc,
                 const struct NFS3::SYMLINK3args*,
                 const struct NFS3::SYMLINK3res*) override final;
    void mknod3(const RPCProcedure* proc,
                const struct NFS3::MKNOD3args*,
                const struct NFS3::MKNOD3res*) override final;
    void remove3(const RPCProcedure* proc,
                 const struct NFS3::REMOVE3args*,
                 const struct NFS3::REMOVE3res*) override final;
    void rmdir3(const RPCProcedure* proc,
                const struct NFS3::RMDIR3args*,
                const struct NFS3::RMDIR3res*) override final;
    void rename3(const RPCProcedure* proc,
                 const struct NFS3::RENAME3args*,
                 const struct NFS3::RENAME3res*) override final;
    void link3(const RPCProcedure* proc,
               const struct NFS3::LINK3args*,
               const struct NFS3::LINK3res*) override final;
    void readdir3(const RPCProcedure* proc,
                  const struct NFS3::READDIR3args*,
                  const struct NFS3::READDIR3res*) override final;
    void readdirplus3(const RPCProcedure* proc,
                      const struct NFS3::READDIRPLUS3args*,
                      const struct NFS3::READDIRPLUS3res*) override final;
    void fsstat3(const RPCProcedure* proc,
                 const struct NFS3::FSSTAT3args*,
                 const struct NFS3::FSSTAT3res*) override final;
    void fsinfo3(const RPCProcedure* proc,
                 const struct NFS3::FSINFO3args*,
                 const struct NFS3::FSINFO3res*) override final;
    void pathconf3(const RPCProcedure* proc,
                   const struct NFS3::PATHCONF3args*,
                   const struct NFS3::PATHCONF3res*) override final;
    void commit3(const RPCProcedure* proc,
                 const struct NFS3::COMMIT3args*,
                 const struct NFS3::COMMIT3res*) override final;

    void null(const RPCProcedure* proc,
              const struct NFS4::NULL4args*,
              const struct NFS4::NULL4res*) override final;
    void compound4(const RPCProcedure*  proc,
                   const struct NFS4::COMPOUND4args*,
                   const struct NFS4::COMPOUND4res*) override final;
private:
    inline void thread();
    void count_proc(const RPCProcedure* proc);
    void account(const RPCProcedure*,
                 const struct NFS4::COMPOUND4res* res = nullptr);

    void UpRead();
    void DownRead();

    uint64_t nfs3_proc_total;
    std::vector<int> nfs3_proc_count;

    uint64_t nfs4_proc_total;
    uint64_t nfs4_ops_total;
    std::vector<int> nfs4_proc_count;

//    std::thread monitor_thread;
//    std::atomic_flag monitor_running;

//    long int refresh_delta;

    const uint16_t max_read;
    std::atomic<uint16_t> read_counter;
    std::condition_variable cv;
    std::mutex mut;
//    std::atomic<bool> enable_update;
    UserGUI gui;
};
//------------------------------------------------------------------------------
#endif //WATCH_ANALYZER_H
//------------------------------------------------------------------------------
