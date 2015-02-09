//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: NFS v4.1 breakdown analyzer
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
#include "nfsv41breakdownanalyzer.h"
#include "nfsv41commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
NFSv41BreakdownAnalyzer::NFSv41BreakdownAnalyzer(std::ostream &o)
    : NFSv4BreakdownAnalyzer(o)
    , stats(NFSv41Commands().commands_count())
    , representer(o, new NFSv41Commands())
{

}

void NFSv41BreakdownAnalyzer::null41(const RPCProcedure *proc, const NFS41::NULL4args *, const NFS41::NULL4res *)
{
    account(proc, NFS_V41, stats);
}

void NFSv41BreakdownAnalyzer::compound41(const RPCProcedure *proc, const NFS41::COMPOUND4args *, const NFS41::COMPOUND4res *)
{
    account(proc, NFS_V41, stats);
}

void NFSv41BreakdownAnalyzer::access41(const RPCProcedure *proc, const NFS41::ACCESS4args *, const NFS41::ACCESS4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::ACCESS, stats);
    }
}

void NFSv41BreakdownAnalyzer::close41(const RPCProcedure *proc, const NFS41::CLOSE4args *, const NFS41::CLOSE4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::CLOSE, stats);
    }
}

void NFSv41BreakdownAnalyzer::commit41(const RPCProcedure *proc, const NFS41::COMMIT4args *, const NFS41::COMMIT4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::COMMIT, stats);
    }
}

void NFSv41BreakdownAnalyzer::create41(const RPCProcedure *proc, const NFS41::CREATE4args *, const NFS41::CREATE4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::CREATE, stats);
    }
}

void NFSv41BreakdownAnalyzer::delegpurge41(const RPCProcedure *proc, const NFS41::DELEGPURGE4args *, const NFS41::DELEGPURGE4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::DELEGPURGE, stats);
    }
}

void NFSv41BreakdownAnalyzer::delegreturn41(const RPCProcedure *proc, const NFS41::DELEGRETURN4args *, const NFS41::DELEGRETURN4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::DELEGRETURN, stats);
    }
}

void NFSv41BreakdownAnalyzer::getattr41(const RPCProcedure *proc, const NFS41::GETATTR4args *, const NFS41::GETATTR4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::GETATTR, stats);
    }
}

void NFSv41BreakdownAnalyzer::getfh41(const RPCProcedure *proc, const NFS41::GETFH4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::GETFH, stats);
    }
}

void NFSv41BreakdownAnalyzer::link41(const RPCProcedure *proc, const NFS41::LINK4args *, const NFS41::LINK4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::LINK, stats);
    }
}

void NFSv41BreakdownAnalyzer::lock41(const RPCProcedure *proc, const NFS41::LOCK4args *, const NFS41::LOCK4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::LOCK, stats);
    }
}

void NFSv41BreakdownAnalyzer::lockt41(const RPCProcedure *proc, const NFS41::LOCKT4args *, const NFS41::LOCKT4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::LOCKT, stats);
    }
}

void NFSv41BreakdownAnalyzer::locku41(const RPCProcedure *proc, const NFS41::LOCKU4args *, const NFS41::LOCKU4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::LOCKU, stats);
    }
}

void NFSv41BreakdownAnalyzer::lookup41(const RPCProcedure *proc, const NFS41::LOOKUP4args *, const NFS41::LOOKUP4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::LOOKUP, stats);
    }
}

void NFSv41BreakdownAnalyzer::lookupp41(const RPCProcedure *proc, const NFS41::LOOKUPP4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::LOOKUPP, stats);
    }
}

void NFSv41BreakdownAnalyzer::nverify41(const RPCProcedure *proc, const NFS41::NVERIFY4args *, const NFS41::NVERIFY4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::NVERIFY, stats);
    }
}

void NFSv41BreakdownAnalyzer::open41(const RPCProcedure *proc, const NFS41::OPEN4args *, const NFS41::OPEN4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::OPEN, stats);
    }
}

void NFSv41BreakdownAnalyzer::openattr41(const RPCProcedure *proc, const NFS41::OPENATTR4args *, const NFS41::OPENATTR4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::OPENATTR, stats);
    }
}

void NFSv41BreakdownAnalyzer::open_confirm41(const RPCProcedure *proc, const NFS41::OPEN_CONFIRM4args *, const NFS41::OPEN_CONFIRM4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::OPEN_CONFIRM, stats);
    }
}

void NFSv41BreakdownAnalyzer::open_downgrade41(const RPCProcedure *proc, const NFS41::OPEN_DOWNGRADE4args *, const NFS41::OPEN_DOWNGRADE4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::OPEN_DOWNGRADE, stats);
    }
}

void NFSv41BreakdownAnalyzer::putfh41(const RPCProcedure *proc, const NFS41::PUTFH4args *, const NFS41::PUTFH4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::PUTFH, stats);
    }
}

void NFSv41BreakdownAnalyzer::putpubfh41(const RPCProcedure *proc, const NFS41::PUTPUBFH4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::PUTPUBFH, stats);
    }
}

void NFSv41BreakdownAnalyzer::putrootfh41(const RPCProcedure *proc, const NFS41::PUTROOTFH4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::PUTROOTFH, stats);
    }
}

void NFSv41BreakdownAnalyzer::read41(const RPCProcedure *proc, const NFS41::READ4args *, const NFS41::READ4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::READ, stats);
    }
}

void NFSv41BreakdownAnalyzer::readdir41(const RPCProcedure *proc, const NFS41::READDIR4args *, const NFS41::READDIR4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::READDIR, stats);
    }
}

void NFSv41BreakdownAnalyzer::readlink41(const RPCProcedure *proc, const NFS41::READLINK4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::READLINK, stats);
    }
}

void NFSv41BreakdownAnalyzer::remove41(const RPCProcedure *proc, const NFS41::REMOVE4args *, const NFS41::REMOVE4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::REMOVE, stats);
    }
}

void NFSv41BreakdownAnalyzer::rename41(const RPCProcedure *proc, const NFS41::RENAME4args *, const NFS41::RENAME4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::RENAME, stats);
    }
}

void NFSv41BreakdownAnalyzer::renew41(const RPCProcedure *proc, const NFS41::RENEW4args *, const NFS41::RENEW4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::RENEW, stats);
    }
}

void NFSv41BreakdownAnalyzer::restorefh41(const RPCProcedure *proc, const NFS41::RESTOREFH4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::RESTOREFH, stats);
    }
}

void NFSv41BreakdownAnalyzer::savefh41(const RPCProcedure *proc, const NFS41::SAVEFH4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::SAVEFH, stats);
    }
}

void NFSv41BreakdownAnalyzer::secinfo41(const RPCProcedure *proc, const NFS41::SECINFO4args *, const NFS41::SECINFO4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::SECINFO, stats);
    }
}

void NFSv41BreakdownAnalyzer::setattr41(const RPCProcedure *proc, const NFS41::SETATTR4args *, const NFS41::SETATTR4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::SETATTR, stats);
    }
}

void NFSv41BreakdownAnalyzer::setclientid41(const RPCProcedure *proc, const NFS41::SETCLIENTID4args *, const NFS41::SETCLIENTID4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::SETCLIENTID, stats);
    }
}

void NFSv41BreakdownAnalyzer::setclientid_confirm41(const RPCProcedure *proc, const NFS41::SETCLIENTID_CONFIRM4args *, const NFS41::SETCLIENTID_CONFIRM4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::SETCLIENTID_CONFIRM, stats);
    }
}

void NFSv41BreakdownAnalyzer::verify41(const RPCProcedure *proc, const NFS41::VERIFY4args *, const NFS41::VERIFY4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::VERIFY, stats);
    }
}

void NFSv41BreakdownAnalyzer::write41(const RPCProcedure *proc, const NFS41::WRITE4args *, const NFS41::WRITE4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::WRITE, stats);
    }
}

void NFSv41BreakdownAnalyzer::release_lockowner41(const RPCProcedure *proc, const NFS41::RELEASE_LOCKOWNER4args *, const NFS41::RELEASE_LOCKOWNER4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::RELEASE_LOCKOWNER, stats);
    }
}

void NFSv41BreakdownAnalyzer::backchannel_ctl41(const RPCProcedure *proc, const NFS41::BACKCHANNEL_CTL4args *, const NFS41::BACKCHANNEL_CTL4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::BACKCHANNEL_CTL, stats);
    }
}

void NFSv41BreakdownAnalyzer::bind_conn_to_session41(const RPCProcedure *proc, const NFS41::BIND_CONN_TO_SESSION4args *, const NFS41::BIND_CONN_TO_SESSION4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::BIND_CONN_TO_SESSION, stats);
    }
}

void NFSv41BreakdownAnalyzer::exchange_id41(const RPCProcedure *proc, const NFS41::EXCHANGE_ID4args *, const NFS41::EXCHANGE_ID4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::EXCHANGE_ID, stats);
    }
}

void NFSv41BreakdownAnalyzer::create_session41(const RPCProcedure *proc, const NFS41::CREATE_SESSION4args *, const NFS41::CREATE_SESSION4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::CREATE_SESSION, stats);
    }
}

void NFSv41BreakdownAnalyzer::destroy_session41(const RPCProcedure *proc, const NFS41::DESTROY_SESSION4args *, const NFS41::DESTROY_SESSION4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::DESTROY_SESSION, stats);
    }
}

void NFSv41BreakdownAnalyzer::free_stateid41(const RPCProcedure *proc, const NFS41::FREE_STATEID4args *, const NFS41::FREE_STATEID4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::FREE_STATEID, stats);
    }
}

void NFSv41BreakdownAnalyzer::get_dir_delegation41(const RPCProcedure *proc, const NFS41::GET_DIR_DELEGATION4args *, const NFS41::GET_DIR_DELEGATION4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::GET_DIR_DELEGATION, stats);
    }
}

void NFSv41BreakdownAnalyzer::getdeviceinfo41(const RPCProcedure *proc, const NFS41::GETDEVICEINFO4args *, const NFS41::GETDEVICEINFO4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::GETDEVICEINFO, stats);
    }
}

void NFSv41BreakdownAnalyzer::getdevicelist41(const RPCProcedure *proc, const NFS41::GETDEVICELIST4args *, const NFS41::GETDEVICELIST4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::GETDEVICELIST, stats);
    }
}

void NFSv41BreakdownAnalyzer::layoutcommit41(const RPCProcedure *proc, const NFS41::LAYOUTCOMMIT4args *, const NFS41::LAYOUTCOMMIT4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::LAYOUTCOMMIT, stats);
    }
}

void NFSv41BreakdownAnalyzer::layoutget41(const RPCProcedure *proc, const NFS41::LAYOUTGET4args *, const NFS41::LAYOUTGET4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::LAYOUTGET, stats);
    }
}

void NFSv41BreakdownAnalyzer::layoutreturn41(const RPCProcedure *proc, const NFS41::LAYOUTRETURN4args *, const NFS41::LAYOUTRETURN4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::LAYOUTRETURN, stats);
    }
}

void NFSv41BreakdownAnalyzer::secinfo_no_name41(const RPCProcedure *proc, const NFS41::SECINFO_NO_NAME4args *, const NFS41::SECINFO_NO_NAME4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::SECINFO_NO_NAME, stats);
    }
}

void NFSv41BreakdownAnalyzer::sequence41(const RPCProcedure *proc, const NFS41::SEQUENCE4args *, const NFS41::SEQUENCE4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::SEQUENCE, stats);
    }
}

void NFSv41BreakdownAnalyzer::set_ssv41(const RPCProcedure *proc, const NFS41::SET_SSV4args *, const NFS41::SET_SSV4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::SET_SSV, stats);
    }
}

void NFSv41BreakdownAnalyzer::test_stateid41(const RPCProcedure *proc, const NFS41::TEST_STATEID4args *, const NFS41::TEST_STATEID4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::TEST_STATEID, stats);
    }
}

void NFSv41BreakdownAnalyzer::want_delegation41(const RPCProcedure *proc, const NFS41::WANT_DELEGATION4args *, const NFS41::WANT_DELEGATION4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::WANT_DELEGATION, stats);
    }
}

void NFSv41BreakdownAnalyzer::destroy_clientid41(const RPCProcedure *proc, const NFS41::DESTROY_CLIENTID4args *, const NFS41::DESTROY_CLIENTID4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::DESTROY_CLIENTID, stats);
    }
}

void NFSv41BreakdownAnalyzer::reclaim_complete41(const RPCProcedure *proc, const NFS41::RECLAIM_COMPLETE4args *, const NFS41::RECLAIM_COMPLETE4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::RECLAIM_COMPLETE, stats);
    }
}

void NFSv41BreakdownAnalyzer::illegal41(const RPCProcedure *proc, const NFS41::ILLEGAL4res *res)
{
    if(res)
    {
        account(proc, ProcEnumNFS41::NFSProcedure::ILLEGAL, stats);
    }
}

void NFSv41BreakdownAnalyzer::flush_statistics()
{
    NFSv4BreakdownAnalyzer::flush_statistics();
    representer.flush_statistics(stats);
}
