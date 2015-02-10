//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: NFS v4 breakdown analyzer
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
#include "nfsv4breakdownanalyzer.h"
#include "nfsv4commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
static const size_t space_for_cmd_name = 22;
static const size_t count_of_compounds = 2;
//------------------------------------------------------------------------------

NFSv4BreakdownAnalyzer::NFSv4Representer::NFSv4Representer(std::ostream& o, CommandRepresenter* cmdRep, size_t space_for_cmd_name)
    : Representer(o, cmdRep, space_for_cmd_name)
{

}

void NFSv4BreakdownAnalyzer::NFSv4Representer::onProcedureInfoPrinted(std::ostream &o, const BreakdownCounter& breakdown, unsigned procedure) const
{
    if (procedure == 0)
    {
        o << "Procedures:" << std::endl;
    }
    if (procedure == count_of_compounds)
    {
        o << "Total operations: " << breakdown.get_total_count()
          << ". Per operation:"   << std::endl;
    }
}

NFSv4BreakdownAnalyzer::NFSv4BreakdownAnalyzer(std::ostream& o)
    : NFSv3BreakdownAnalyzer(o)
    , compound_stats(count_of_compounds)
    , stats(NFSv4Commands().commands_count())
    , representer(o, new NFSv4Commands(), space_for_cmd_name)
{

}

NFSv4BreakdownAnalyzer::~NFSv4BreakdownAnalyzer()
{

}

void NFSv4BreakdownAnalyzer::null(const RPCProcedure* proc, const NFS4::NULL4args*, const NFS4::NULL4res*)
{
    compound_stats.account(proc, NFS_V40);
}

void NFSv4BreakdownAnalyzer::compound4(const RPCProcedure* proc, const NFS4::COMPOUND4args*, const NFS4::COMPOUND4res*)
{
    compound_stats.account(proc, NFS_V40);
}

void NFSv4BreakdownAnalyzer::access40(const RPCProcedure* proc, const NFS4::ACCESS4args*, const NFS4::ACCESS4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::ACCESS);
    }
}

void NFSv4BreakdownAnalyzer::close40(const RPCProcedure* proc, const NFS4::CLOSE4args*, const NFS4::CLOSE4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::CLOSE);
    }
}

void NFSv4BreakdownAnalyzer::commit40(const RPCProcedure* proc, const NFS4::COMMIT4args*, const NFS4::COMMIT4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::COMMIT);
    }
}

void NFSv4BreakdownAnalyzer::create40(const RPCProcedure* proc, const NFS4::CREATE4args*, const NFS4::CREATE4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::CREATE);
    }
}

void NFSv4BreakdownAnalyzer::delegpurge40(const RPCProcedure* proc, const NFS4::DELEGPURGE4args*, const NFS4::DELEGPURGE4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::DELEGPURGE);
    }
}

void NFSv4BreakdownAnalyzer::delegreturn40(const RPCProcedure* proc, const NFS4::DELEGRETURN4args*, const NFS4::DELEGRETURN4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::DELEGRETURN);
    }
}

void NFSv4BreakdownAnalyzer::getattr40(const RPCProcedure* proc, const NFS4::GETATTR4args*, const NFS4::GETATTR4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::GETATTR);
    }
}

void NFSv4BreakdownAnalyzer::getfh40(const RPCProcedure* proc, const NFS4::GETFH4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::GETFH);
    }
}

void NFSv4BreakdownAnalyzer::link40(const RPCProcedure* proc, const NFS4::LINK4args*, const NFS4::LINK4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::LINK);
    }
}

void NFSv4BreakdownAnalyzer::lock40(const RPCProcedure* proc, const NFS4::LOCK4args*, const NFS4::LOCK4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::LOCK);
    }
}

void NFSv4BreakdownAnalyzer::lockt40(const RPCProcedure* proc, const NFS4::LOCKT4args*, const NFS4::LOCKT4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::LOCKT);
    }
}

void NFSv4BreakdownAnalyzer::locku40(const RPCProcedure* proc, const NFS4::LOCKU4args*, const NFS4::LOCKU4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::LOCKU);
    }
}

void NFSv4BreakdownAnalyzer::lookup40(const RPCProcedure* proc, const NFS4::LOOKUP4args*, const NFS4::LOOKUP4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::LOOKUP);
    }
}

void NFSv4BreakdownAnalyzer::lookupp40(const RPCProcedure* proc, const NFS4::LOOKUPP4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::LOOKUPP);
    }
}

void NFSv4BreakdownAnalyzer::nverify40(const RPCProcedure* proc, const NFS4::NVERIFY4args*, const NFS4::NVERIFY4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::NVERIFY);
    }
}

void NFSv4BreakdownAnalyzer::open40(const RPCProcedure* proc, const NFS4::OPEN4args*, const NFS4::OPEN4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::OPEN);
    }
}

void NFSv4BreakdownAnalyzer::openattr40(const RPCProcedure* proc, const NFS4::OPENATTR4args*, const NFS4::OPENATTR4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::OPENATTR);
    }
}

void NFSv4BreakdownAnalyzer::open_confirm40(const RPCProcedure* proc, const NFS4::OPEN_CONFIRM4args*, const NFS4::OPEN_CONFIRM4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::OPEN_CONFIRM);
    }
}

void NFSv4BreakdownAnalyzer::open_downgrade40(const RPCProcedure* proc, const NFS4::OPEN_DOWNGRADE4args*, const NFS4::OPEN_DOWNGRADE4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::OPEN_DOWNGRADE);
    }
}

void NFSv4BreakdownAnalyzer::putfh40(const RPCProcedure* proc, const NFS4::PUTFH4args*, const NFS4::PUTFH4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::PUTFH);
    }
}

void NFSv4BreakdownAnalyzer::putpubfh40(const RPCProcedure* proc, const NFS4::PUTPUBFH4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::PUTPUBFH);
    }
}

void NFSv4BreakdownAnalyzer::putrootfh40(const RPCProcedure* proc, const NFS4::PUTROOTFH4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::PUTROOTFH);
    }
}

void NFSv4BreakdownAnalyzer::read40(const RPCProcedure* proc, const NFS4::READ4args*, const NFS4::READ4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::READ);
    }
}

void NFSv4BreakdownAnalyzer::readdir40(const RPCProcedure* proc, const NFS4::READDIR4args*, const NFS4::READDIR4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::READDIR);
    }
}

void NFSv4BreakdownAnalyzer::readlink40(const RPCProcedure* proc, const NFS4::READLINK4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::READLINK);
    }
}

void NFSv4BreakdownAnalyzer::remove40(const RPCProcedure* proc, const NFS4::REMOVE4args*, const NFS4::REMOVE4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::REMOVE);
    }
}

void NFSv4BreakdownAnalyzer::rename40(const RPCProcedure* proc, const NFS4::RENAME4args*, const NFS4::RENAME4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::RENAME);
    }
}

void NFSv4BreakdownAnalyzer::renew40(const RPCProcedure* proc, const NFS4::RENEW4args*, const NFS4::RENEW4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::RENEW);
    }
}

void NFSv4BreakdownAnalyzer::restorefh40(const RPCProcedure* proc, const NFS4::RESTOREFH4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::RESTOREFH);
    }
}

void NFSv4BreakdownAnalyzer::savefh40(const RPCProcedure* proc, const NFS4::SAVEFH4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::SAVEFH);
    }
}

void NFSv4BreakdownAnalyzer::secinfo40(const RPCProcedure* proc, const NFS4::SECINFO4args*, const NFS4::SECINFO4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::SECINFO);
    }
}

void NFSv4BreakdownAnalyzer::setattr40(const RPCProcedure* proc, const NFS4::SETATTR4args*, const NFS4::SETATTR4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::SETATTR);
    }
}

void NFSv4BreakdownAnalyzer::setclientid40(const RPCProcedure* proc, const NFS4::SETCLIENTID4args*, const NFS4::SETCLIENTID4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::SETCLIENTID);
    }
}

void NFSv4BreakdownAnalyzer::setclientid_confirm40(const RPCProcedure* proc, const NFS4::SETCLIENTID_CONFIRM4args*, const NFS4::SETCLIENTID_CONFIRM4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::SETCLIENTID_CONFIRM);
    }
}

void NFSv4BreakdownAnalyzer::verify40(const RPCProcedure* proc, const NFS4::VERIFY4args*, const NFS4::VERIFY4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::VERIFY);
    }
}

void NFSv4BreakdownAnalyzer::write40(const RPCProcedure* proc, const NFS4::WRITE4args*, const NFS4::WRITE4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::WRITE);
    }
}

void NFSv4BreakdownAnalyzer::release_lockowner40(const RPCProcedure* proc, const NFS4::RELEASE_LOCKOWNER4args*, const NFS4::RELEASE_LOCKOWNER4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::RELEASE_LOCKOWNER);
    }
}

void NFSv4BreakdownAnalyzer::get_dir_delegation40(const RPCProcedure* proc, const NFS4::GET_DIR_DELEGATION4args*, const NFS4::GET_DIR_DELEGATION4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::GET_DIR_DELEGATION);
    }
}

void NFSv4BreakdownAnalyzer::illegal40(const RPCProcedure* proc, const NFS4::ILLEGAL4res* res)
{
    if (res)
    {
        stats.account(proc, ProcEnumNFS4::NFSProcedure::ILLEGAL);
    }
}

void NFSv4BreakdownAnalyzer::flush_statistics()
{
    NFSv3BreakdownAnalyzer::flush_statistics();
    representer.flush_statistics(stats);
}


