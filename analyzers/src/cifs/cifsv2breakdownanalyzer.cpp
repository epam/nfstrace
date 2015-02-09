//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: CIFS v2 breakdown analyzer
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
#include "cifsv2breakdownanalyzer.h"
#include "cifsv2commands.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
CIFSv2BreakdownAnalyzer::CIFSv2BreakdownAnalyzer(std::ostream& o)
    : CIFSBreakdownAnalyzer(o)
    , cifs2Representer(o, new SMBv2Commands())
{
}

void CIFSv2BreakdownAnalyzer::closeFileSMBv2(const SMBv2::CloseFileCommand* cmd, const SMBv2::CloseRequest*, const SMBv2::CloseResponse*)
{
    account(cmd, SMBv2Commands::CLOSE, smbv2);
}

void CIFSv2BreakdownAnalyzer::negotiateSMBv2(const SMBv2::NegotiateCommand* cmd, const SMBv2::NegotiateRequest*, const SMBv2::NegotiateResponse*)
{
    account(cmd, SMBv2Commands::NEGOTIATE, smbv2);
}

void CIFSv2BreakdownAnalyzer::sessionSetupSMBv2(const SMBv2::SessionSetupCommand* cmd, const SMBv2::SessionSetupRequest*, const SMBv2::SessionSetupResponse*)
{
    account(cmd, SMBv2Commands::SESSION_SETUP, smbv2);
}

void CIFSv2BreakdownAnalyzer::logOffSMBv2(const SMBv2::LogOffCommand* cmd, const SMBv2::LogOffRequest*, const SMBv2::LogOffResponse*)
{
    account(cmd, SMBv2Commands::LOGOFF, smbv2);
}

void CIFSv2BreakdownAnalyzer::treeConnectSMBv2(const SMBv2::TreeConnectCommand* cmd, const SMBv2::TreeConnectRequest*, const SMBv2::TreeConnectResponse*)
{
    account(cmd, SMBv2Commands::TREE_CONNECT, smbv2);
}

void CIFSv2BreakdownAnalyzer::treeDisconnectSMBv2(const SMBv2::TreeDisconnectCommand* cmd, const SMBv2::TreeDisconnectRequest*, const SMBv2::TreeDisconnectResponse*)
{
    account(cmd, SMBv2Commands::TREE_DISCONNECT, smbv2);
}

void CIFSv2BreakdownAnalyzer::createSMBv2(const SMBv2::CreateCommand* cmd, const SMBv2::CreateRequest*, const SMBv2::CreateResponse*)
{
    account(cmd, SMBv2Commands::CREATE, smbv2);
}

void CIFSv2BreakdownAnalyzer::flushSMBv2(const SMBv2::FlushCommand* cmd, const SMBv2::FlushRequest*, const SMBv2::FlushResponse*)
{
    account(cmd, SMBv2Commands::FLUSH, smbv2);
}

void CIFSv2BreakdownAnalyzer::readSMBv2(const SMBv2::ReadCommand* cmd, const SMBv2::ReadRequest*, const SMBv2::ReadResponse*)
{
    account(cmd, SMBv2Commands::READ, smbv2);
}

void CIFSv2BreakdownAnalyzer::writeSMBv2(const SMBv2::WriteCommand* cmd, const SMBv2::WriteRequest*, const SMBv2::WriteResponse*)
{
    account(cmd, SMBv2Commands::WRITE, smbv2);
}

void CIFSv2BreakdownAnalyzer::lockSMBv2(const SMBv2::LockCommand* cmd, const SMBv2::LockRequest*, const SMBv2::LockResponse*)
{
    account(cmd, SMBv2Commands::LOCK, smbv2);
}

void CIFSv2BreakdownAnalyzer::ioctlSMBv2(const SMBv2::IoctlCommand* cmd, const SMBv2::IoCtlRequest*, const SMBv2::IoCtlResponse*)
{
    account(cmd, SMBv2Commands::IOCTL, smbv2);
}

void CIFSv2BreakdownAnalyzer::cancelSMBv2(const SMBv2::CancelCommand* cmd, const SMBv2::CancelRequest*, const SMBv2::CancelResponce*)
{
    account(cmd, SMBv2Commands::CANCEL, smbv2);
}

void CIFSv2BreakdownAnalyzer::echoSMBv2(const SMBv2::EchoCommand* cmd, const SMBv2::EchoRequest*, const SMBv2::EchoResponse*)
{
    account(cmd, SMBv2Commands::ECHO, smbv2);
}

void CIFSv2BreakdownAnalyzer::queryDirSMBv2(const SMBv2::QueryDirCommand* cmd, const SMBv2::QueryDirRequest*, const SMBv2::QueryDirResponse*)
{
    account(cmd, SMBv2Commands::QUERY_DIRECTORY, smbv2);
}

void CIFSv2BreakdownAnalyzer::changeNotifySMBv2(const SMBv2::ChangeNotifyCommand* cmd, const SMBv2::ChangeNotifyRequest*, const SMBv2::ChangeNotifyResponse*)
{
    account(cmd, SMBv2Commands::CHANGE_NOTIFY, smbv2);
}

void CIFSv2BreakdownAnalyzer::queryInfoSMBv2(const SMBv2::QueryInfoCommand* cmd, const SMBv2::QueryInfoRequest*, const SMBv2::QueryInfoResponse*)
{
    account(cmd, SMBv2Commands::QUERY_INFO, smbv2);
}

void CIFSv2BreakdownAnalyzer::setInfoSMBv2(const SMBv2::SetInfoCommand* cmd, const SMBv2::SetInfoRequest*, const SMBv2::SetInfoResponse*)
{
    account(cmd, SMBv2Commands::SET_INFO, smbv2);
}

void CIFSv2BreakdownAnalyzer::breakOplockSMBv2(const SMBv2::BreakOpLockCommand* cmd, const SMBv2::OplockAcknowledgment*, const SMBv2::OplockResponse*)
{
    account(cmd, SMBv2Commands::OPLOCK_BREAK, smbv2);
}

void CIFSv2BreakdownAnalyzer::flush_statistics()
{
    CIFSBreakdownAnalyzer::flush_statistics();//FIXME: use observer
    cifs2Representer.flush_statistics(smbv2);
}
//------------------------------------------------------------------------------
