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
#ifndef CIFSV2BREAKDOWNANALYZER_H
#define CIFSV2BREAKDOWNANALYZER_H
//------------------------------------------------------------------------------
#include <api/plugin_api.h>

#include "representer.h"
#include "statistics.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
/*! \class Analyzer for CIFS v2
 * Handles CIFS v2 commands
 */
class CIFSv2BreakdownAnalyzer : virtual public IAnalyzer
{
    Statistics stats; //!< Statistics
    Representer cifs2Representer; //!< Class for statistics representation
public:
    CIFSv2BreakdownAnalyzer(std::ostream& o = std::cout);
    void closeFileSMBv2(const SMBv2::CloseFileCommand* cmd, const SMBv2::CloseRequest*, const SMBv2::CloseResponse*) override final;
    void negotiateSMBv2(const SMBv2::NegotiateCommand* cmd, const SMBv2::NegotiateRequest*, const SMBv2::NegotiateResponse*) override final;
    void sessionSetupSMBv2(const SMBv2::SessionSetupCommand* cmd, const SMBv2::SessionSetupRequest*, const SMBv2::SessionSetupResponse*) override final;
    void logOffSMBv2(const SMBv2::LogOffCommand* cmd, const SMBv2::LogOffRequest*, const SMBv2::LogOffResponse*) override final;
    void treeConnectSMBv2(const SMBv2::TreeConnectCommand* cmd, const SMBv2::TreeConnectRequest*, const SMBv2::TreeConnectResponse*) override final;
    void treeDisconnectSMBv2(const SMBv2::TreeDisconnectCommand* cmd, const SMBv2::TreeDisconnectRequest*, const SMBv2::TreeDisconnectResponse*) override final;
    void createSMBv2(const SMBv2::CreateCommand* cmd, const SMBv2::CreateRequest*, const SMBv2::CreateResponse*) override final;
    void flushSMBv2(const SMBv2::FlushCommand* cmd, const SMBv2::FlushRequest*, const SMBv2::FlushResponse*) override final;
    void readSMBv2(const SMBv2::ReadCommand* cmd, const SMBv2::ReadRequest*, const SMBv2::ReadResponse*) override final;
    void writeSMBv2(const SMBv2::WriteCommand* cmd, const SMBv2::WriteRequest*, const SMBv2::WriteResponse*) override final;
    void lockSMBv2(const SMBv2::LockCommand* cmd, const SMBv2::LockRequest*, const SMBv2::LockResponse*) override final;
    void ioctlSMBv2(const SMBv2::IoctlCommand* cmd, const SMBv2::IoCtlRequest*, const SMBv2::IoCtlResponse*) override final;
    void cancelSMBv2(const SMBv2::CancelCommand* cmd, const SMBv2::CancelRequest*, const SMBv2::CancelResponce*) override final;
    void echoSMBv2(const SMBv2::EchoCommand* cmd, const SMBv2::EchoRequest*, const SMBv2::EchoResponse*) override final;
    void queryDirSMBv2(const SMBv2::QueryDirCommand* cmd, const SMBv2::QueryDirRequest*, const SMBv2::QueryDirResponse*) override final;
    void changeNotifySMBv2(const SMBv2::ChangeNotifyCommand* cmd, const SMBv2::ChangeNotifyRequest*, const SMBv2::ChangeNotifyResponse*) override final;
    void queryInfoSMBv2(const SMBv2::QueryInfoCommand* cmd, const SMBv2::QueryInfoRequest*, const SMBv2::QueryInfoResponse*) override final;
    void setInfoSMBv2(const SMBv2::SetInfoCommand* cmd, const SMBv2::SetInfoRequest*, const SMBv2::SetInfoResponse*) override final;
    void breakOplockSMBv2(const SMBv2::BreakOpLockCommand* cmd, const SMBv2::OplockAcknowledgment*, const SMBv2::OplockResponse*) override final;
protected:
    void flush_statistics() override;
};
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // CIFSV2BREAKDOWNANALYZER_H
//------------------------------------------------------------------------------
