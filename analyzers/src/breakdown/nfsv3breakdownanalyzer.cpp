//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: NFS v3 breakdown analyzer
// Copyright (c) 2015 EPAM Systems
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
#include "breakdowncounter.h"
#include "nfsv3breakdownanalyzer.h"
#include "nfsv3commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
NFSv3BreakdownAnalyzer::NFSv3BreakdownAnalyzer(std::ostream& o)
    : stats(NFSv3Commands().commands_count())
    , representer(o, new NFSv3Commands())
{

}

void NFSv3BreakdownAnalyzer::null(const RPCProcedure* proc, const NFS3::NULL3args*, const NFS3::NULL3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}

void NFSv3BreakdownAnalyzer::getattr3(const RPCProcedure* proc, const NFS3::GETATTR3args*, const NFS3::GETATTR3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::setattr3(const RPCProcedure* proc, const NFS3::SETATTR3args*, const NFS3::SETATTR3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::lookup3(const RPCProcedure* proc, const NFS3::LOOKUP3args*, const NFS3::LOOKUP3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::access3(const RPCProcedure* proc, const NFS3::ACCESS3args*, const NFS3::ACCESS3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::readlink3(const RPCProcedure* proc, const NFS3::READLINK3args*, const NFS3::READLINK3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::read3(const RPCProcedure* proc, const NFS3::READ3args*, const NFS3::READ3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::write3(const RPCProcedure* proc, const NFS3::WRITE3args*, const NFS3::WRITE3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::create3(const RPCProcedure* proc, const NFS3::CREATE3args*, const NFS3::CREATE3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::mkdir3(const RPCProcedure* proc, const NFS3::MKDIR3args*, const NFS3::MKDIR3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::symlink3(const RPCProcedure* proc, const NFS3::SYMLINK3args*, const NFS3::SYMLINK3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::mknod3(const RPCProcedure* proc, const NFS3::MKNOD3args*, const NFS3::MKNOD3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::remove3(const RPCProcedure* proc, const NFS3::REMOVE3args*, const NFS3::REMOVE3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::rmdir3(const RPCProcedure* proc, const NFS3::RMDIR3args*, const NFS3::RMDIR3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::rename3(const RPCProcedure* proc, const NFS3::RENAME3args*, const NFS3::RENAME3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::link3(const RPCProcedure* proc, const NFS3::LINK3args*, const NFS3::LINK3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::readdir3(const RPCProcedure* proc, const NFS3::READDIR3args*, const NFS3::READDIR3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::readdirplus3(const RPCProcedure* proc, const NFS3::READDIRPLUS3args*, const NFS3::READDIRPLUS3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::fsstat3(const RPCProcedure* proc, const NFS3::FSSTAT3args*, const NFS3::FSSTAT3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::fsinfo3(const RPCProcedure* proc, const NFS3::FSINFO3args*, const NFS3::FSINFO3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::pathconf3(const RPCProcedure* proc, const NFS3::PATHCONF3args*, const NFS3::PATHCONF3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}


void NFSv3BreakdownAnalyzer::commit3(const RPCProcedure* proc, const NFS3::COMMIT3args*, const NFS3::COMMIT3res*)
{
    stats.account(proc, proc->call.ru.RM_cmb.cb_proc);
}

void NFSv3BreakdownAnalyzer::flush_statistics()
{
    representer.flush_statistics(stats);
}
