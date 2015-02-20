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
#include <string>

#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>

#include "watch_analyzer.h"
//------------------------------------------------------------------------------
WatchAnalyzer::WatchAnalyzer(const char* opts)
: gui {opts}
{
}

WatchAnalyzer::~WatchAnalyzer()
{
}

void WatchAnalyzer::null(const RPCProcedure* proc,
          const struct NFS3::NULL3args*,
          const struct NFS3::NULL3res*) { account(proc);}
void WatchAnalyzer::getattr3(const RPCProcedure* proc,
              const struct NFS3::GETATTR3args*,
              const struct NFS3::GETATTR3res*) { account(proc);}
void WatchAnalyzer::setattr3(const RPCProcedure* proc,
              const struct NFS3::SETATTR3args*,
              const struct NFS3::SETATTR3res*) { account(proc);}
void WatchAnalyzer::lookup3(const RPCProcedure* proc,
             const struct NFS3::LOOKUP3args*,
             const struct NFS3::LOOKUP3res*) { account(proc);}
void WatchAnalyzer::access3(const RPCProcedure* proc,
             const struct NFS3::ACCESS3args*,
             const struct NFS3::ACCESS3res*) { account(proc);}
void WatchAnalyzer::readlink3(const RPCProcedure* proc,
               const struct NFS3::READLINK3args*,
               const struct NFS3::READLINK3res*) { account(proc);}
void WatchAnalyzer::read3(const RPCProcedure* proc,
           const struct NFS3::READ3args*,
           const struct NFS3::READ3res*) { account(proc);}
void WatchAnalyzer::write3(const RPCProcedure* proc,
            const struct NFS3::WRITE3args*,
            const struct NFS3::WRITE3res*) { account(proc);}
void WatchAnalyzer::create3(const RPCProcedure* proc,
             const struct NFS3::CREATE3args*,
             const struct NFS3::CREATE3res*) { account(proc);}
void WatchAnalyzer::mkdir3(const RPCProcedure* proc,
            const struct NFS3::MKDIR3args*,
            const struct NFS3::MKDIR3res*) { account(proc);}
void WatchAnalyzer::symlink3(const RPCProcedure* proc,
             const struct NFS3::SYMLINK3args*,
             const struct NFS3::SYMLINK3res*) { account(proc);}
void WatchAnalyzer::mknod3(const RPCProcedure* proc,
            const struct NFS3::MKNOD3args*,
            const struct NFS3::MKNOD3res*) { account(proc);}
void WatchAnalyzer::remove3(const RPCProcedure* proc,
             const struct NFS3::REMOVE3args*,
             const struct NFS3::REMOVE3res*) { account(proc);}
void WatchAnalyzer::rmdir3(const RPCProcedure* proc,
            const struct NFS3::RMDIR3args*,
            const struct NFS3::RMDIR3res*) { account(proc);}
void WatchAnalyzer::rename3(const RPCProcedure* proc,
             const struct NFS3::RENAME3args*,
             const struct NFS3::RENAME3res*) { account(proc);}
void WatchAnalyzer::link3(const RPCProcedure* proc,
           const struct NFS3::LINK3args*,
           const struct NFS3::LINK3res*) { account(proc);}
void WatchAnalyzer::readdir3(const RPCProcedure* proc,
              const struct NFS3::READDIR3args*,
              const struct NFS3::READDIR3res*) { account(proc);}
void WatchAnalyzer::readdirplus3(const RPCProcedure* proc,
                  const struct NFS3::READDIRPLUS3args*,
                  const struct NFS3::READDIRPLUS3res*) { account(proc);}
void WatchAnalyzer::fsstat3(const RPCProcedure* proc,
             const struct NFS3::FSSTAT3args*,
             const struct NFS3::FSSTAT3res*) { account(proc);}
void WatchAnalyzer::fsinfo3(const RPCProcedure* proc,
             const struct NFS3::FSINFO3args*,
             const struct NFS3::FSINFO3res*) { account(proc);}
void WatchAnalyzer::pathconf3(const RPCProcedure* proc,
               const struct NFS3::PATHCONF3args*,
               const struct NFS3::PATHCONF3res*) { account(proc);}
void WatchAnalyzer::commit3(const RPCProcedure* proc,
             const struct NFS3::COMMIT3args*,
             const struct NFS3::COMMIT3res*) { account(proc);}

void WatchAnalyzer::null(const RPCProcedure* proc,
          const struct NFS4::NULL4args*,
          const struct NFS4::NULL4res*) { account(proc);}
void WatchAnalyzer::compound4(const RPCProcedure*  proc,
               const struct NFS4::COMPOUND4args*,
               const struct NFS4::COMPOUND4res*  res) { account(proc, res);}

void WatchAnalyzer::flush_statistics()
{
}

void WatchAnalyzer::on_unix_signal(int signo)
{
    if (signo == SIGWINCH) {
        gui.setUpdate();
    }
}

void WatchAnalyzer::account(const RPCProcedure* proc,
                const struct NFS4::COMPOUND4res* res)
{
    const u_int nfs_proc = proc->call.ru.RM_cmb.cb_proc;
    const u_int nfs_vers = proc->call.ru.RM_cmb.cb_vers;

    uint64_t nfs3_proc_total = {0};
    std::vector<int> nfs3_proc_count (ProcEnumNFS3::count, 0);

    uint64_t nfs4_proc_total = {0};
    uint64_t nfs4_ops_total  = {0};
    std::vector<int> nfs4_proc_count (ProcEnumNFS4::count, 0);
    if(nfs_vers == NFS_V4)
    {
        ++nfs4_proc_total;
        ++nfs4_proc_count[nfs_proc];
        if(res)
        {
            nfs4_ops_total += res->resarray.resarray_len;
            NFS4::nfs_resop4* current_el = res->resarray.resarray_val;
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

    gui.updateCounters(nfs3_proc_total, nfs3_proc_count, nfs4_proc_total, nfs4_ops_total, nfs4_proc_count);
}
//------------------------------------------------------------------------------
extern "C"
{

const char* usage()
{
    return "User can set chrono output timeout in msec.\n"
           "You have to run nfstrace with verbosity level set to 0 (nfstrace -v 0 ...)";
}

IAnalyzer* create(const char* opts)
{
    try
    {
        return new WatchAnalyzer(opts);
    }
    catch(std::exception& e)
    {
        std::cerr << "Can't initalize plugin: " << e.what() << std::endl;
        return nullptr;
    }
}

void destroy(IAnalyzer* instance)
{
    delete instance;
}

NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)
}
//------------------------------------------------------------------------------
