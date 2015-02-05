//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: CIFS breakdown analyzer
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
#ifndef CIFSBREAKDOWNANALYZER_H
#define CIFSBREAKDOWNANALYZER_H
//------------------------------------------------------------------------------
#include <map>

#include <api/plugin_api.h>

#include "breakdowncounter.h"
#include "cifs_commands.h"
#include "cifs_representer.h"
#include "statistic.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
//------------------------------------------------------------------------------
/*! \class Analyzer for CIFS v1
 */
class CIFSBreakdownAnalyzer : public IAnalyzer
{
    Statistic smbv1;//!< Statistic
    Representer<SMBv1Commands> representer;//!< Class for statistic representation
public:
    CIFSBreakdownAnalyzer(std::ostream& o = std::cout);

    void createDirectorySMBv1(const SMBv1::CreateDirectoryCommand* cmd, const SMBv1::CreateDirectoryArgumentType*, const SMBv1::CreateDirectoryResultType*) override final;
    void deleteDirectorySMBv1(const SMBv1::DeleteDirectoryCommand* cmd, const SMBv1::DeleteDirectoryArgumentType*, const SMBv1::DeleteDirectoryResultType*) override final;
    void openSMBv1(const SMBv1::OpenCommand* cmd, const SMBv1::OpenArgumentType*, const SMBv1::OpenResultType*) override final;
    void createSMBv1(const SMBv1::CreateCommand* cmd, const SMBv1::CreateArgumentType*, const SMBv1::CreateResultType*) override final;
    void closeSMBv1(const SMBv1::CloseCommand* cmd, const SMBv1::CloseArgumentType*, const SMBv1::CloseResultType*) override final;
    void flushSMBv1(const SMBv1::FlushCommand* cmd, const SMBv1::FlushArgumentType*, const SMBv1::FlushResultType*) override final;
    void deleteSMBv1(const SMBv1::DeleteCommand* cmd, const SMBv1::DeleteArgumentType*, const SMBv1::DeleteResultType*) override final;
    void renameSMBv1(const SMBv1::RenameCommand* cmd, const SMBv1::RenameArgumentType*, const SMBv1::RenameResultType*) override final;
    void queryInfoSMBv1(const SMBv1::QueryInformationCommand* cmd, const SMBv1::QueryInformationArgumentType*, const SMBv1::QueryInformationResultType*) override final;
    void setInfoSMBv1(const SMBv1::SetInformationCommand* cmd, const SMBv1::SetInformationArgumentType*, const SMBv1::SetInformationResultType*) override final;
    void readSMBv1(const SMBv1::ReadCommand* cmd, const SMBv1::ReadArgumentType*, const SMBv1::ReadResultType*) override final;
    void writeSMBv1(const SMBv1::WriteCommand* cmd, const SMBv1::WriteArgumentType*, const SMBv1::WriteResultType*) override final;
    void lockByteRangeSMBv1(const SMBv1::LockByteRangeCommand* cmd, const SMBv1::LockByteRangeArgumentType*, const SMBv1::LockByteRangeResultType*) override final;
    void unlockByteRangeSMBv1(const SMBv1::UnlockByteRangeCommand* cmd, const SMBv1::UnlockByteRangeArgumentType*, const SMBv1::UnlockByteRangeResultType*) override final;
    void createTmpSMBv1(const SMBv1::CreateTemporaryCommand* cmd, const SMBv1::CreateTemporaryArgumentType*, const SMBv1::CreateTemporaryResultType*) override final;
    void createNewSMBv1(const SMBv1::CreateNewCommand* cmd, const SMBv1::CreateNewArgumentType*, const SMBv1::CreateNewResultType*) override final;
    void checkDirectorySMBv1(const SMBv1::CheckDirectoryCommand* cmd, const SMBv1::CheckDirectoryArgumentType*, const SMBv1::CheckDirectoryResultType*) override final;
    void processExitSMBv1(const SMBv1::ProcessExitCommand* cmd, const SMBv1::ProcessExitArgumentType*, const SMBv1::ProcessExitResultType*) override final;
    void seekSMBv1(const SMBv1::SeekCommand* cmd, const SMBv1::SeekArgumentType*, const SMBv1::SeekResultType*) override final;
    void lockAndReadSMBv1(const SMBv1::LockAndReadCommand* cmd, const SMBv1::LockAndReadArgumentType*, const SMBv1::LockAndReadResultType*) override final;
    void writeAndUnlockSMBv1(const SMBv1::WriteAndUnlockCommand* cmd, const SMBv1::WriteAndUnlockArgumentType*, const SMBv1::WriteAndUnlockResultType*) override final;
    void readRawSMBv1(const SMBv1::ReadRawCommand* cmd, const SMBv1::ReadRawArgumentType*, const SMBv1::ReadRawResultType*) override final;
    void readMpxSMBv1(const SMBv1::ReadMpxCommand* cmd, const SMBv1::ReadMpxArgumentType*, const SMBv1::ReadMpxResultType*) override final;
    void readMpxSecondarySMBv1(const SMBv1::ReadMpxSecondaryCommand* cmd, const SMBv1::ReadMpxSecondaryArgumentType*, const SMBv1::ReadMpxSecondaryResultType*) override final;
    void writeRawSMBv1(const SMBv1::WriteRawCommand* cmd, const SMBv1::WriteRawArgumentType*, const SMBv1::WriteRawResultType*) override final;
    void writeMpxSMBv1(const SMBv1::WriteMpxCommand* cmd, const SMBv1::WriteMpxArgumentType*, const SMBv1::WriteMpxResultType*) override final;
    void writeMpxSecondarySMBv1(const SMBv1::WriteMpxSecondaryCommand* cmd, const SMBv1::WriteMpxSecondaryArgumentType*, const SMBv1::WriteMpxSecondaryResultType*) override final;
    void writeCompleteSMBv1(const SMBv1::WriteCompleteCommand* cmd, const SMBv1::WriteCompleteArgumentType*, const SMBv1::WriteCompleteResultType*) override final;
    void queryServerSMBv1(const SMBv1::QueryServerCommand* cmd, const SMBv1::QueryServerArgumentType*, const SMBv1::QueryServerResultType*) override final;
    void setInfo2SMBv1(const SMBv1::SetInformation2Command* cmd, const SMBv1::SetInformation2ArgumentType*, const SMBv1::SetInformation2ResultType*) override final;
    void queryInfo2SMBv1(const SMBv1::QueryInformation2Command* cmd, const SMBv1::QueryInformation2ArgumentType*, const SMBv1::QueryInformation2ResultType*) override final;
    void lockingAndxSMBv1(const SMBv1::LockingAndxCommand* cmd, const SMBv1::LockingAndxArgumentType*, const SMBv1::LockingAndxResultType*) override final;
    void transactionSMBv1(const SMBv1::TransactionCommand* cmd, const SMBv1::TransactionArgumentType*, const SMBv1::TransactionResultType*) override final;
    void transactionSecondarySMBv1(const SMBv1::TransactionSecondaryCommand* cmd, const SMBv1::TransactionSecondaryArgumentType*, const SMBv1::TransactionSecondaryResultType*) override final;
    void ioctlSMBv1(const SMBv1::IoctlCommand* cmd, const SMBv1::IoctlArgumentType*, const SMBv1::IoctlResultType*) override final;
    void ioctlSecondarySMBv1(const SMBv1::IoctlSecondaryCommand* cmd, const SMBv1::IoctlSecondaryArgumentType*, const SMBv1::IoctlSecondaryResultType*) override final;
    void copySMBv1(const SMBv1::CopyCommand* cmd, const SMBv1::CopyArgumentType*, const SMBv1::CopyResultType*) override final;
    void moveSMBv1(const SMBv1::MoveCommand* cmd, const SMBv1::MoveArgumentType*, const SMBv1::MoveResultType*) override final;
    void echoSMBv1(const SMBv1::EchoCommand* cmd, const SMBv1::EchoArgumentType*, const SMBv1::EchoResultType*) override final;
    void writeAndCloseSMBv1(const SMBv1::WriteAndCloseCommand* cmd, const SMBv1::WriteAndCloseArgumentType*, const SMBv1::WriteAndCloseResultType*) override final;
    void openAndxSMBv1(const SMBv1::OpenAndxCommand* cmd, const SMBv1::OpenAndxArgumentType*, const SMBv1::OpenAndxResultType*) override final;
    void readAndxSMBv1(const SMBv1::ReadAndxCommand* cmd, const SMBv1::ReadAndxArgumentType*, const SMBv1::ReadAndxResultType*) override final;
    void writeAndxSMBv1(const SMBv1::WriteAndxCommand* cmd, const SMBv1::WriteAndxArgumentType*, const SMBv1::WriteAndxResultType*) override final;
    void newFileSizeSMBv1(const SMBv1::NewFileSizeCommand* cmd, const SMBv1::NewFileSizeArgumentType*, const SMBv1::NewFileSizeResultType*) override final;
    void closeAndTreeDiscSMBv1(const SMBv1::CloseAndTreeDiscCommand* cmd, const SMBv1::CloseAndTreeDiscArgumentType*, const SMBv1::CloseAndTreeDiscResultType*) override final;
    void transaction2SMBv1(const SMBv1::Transaction2Command* cmd, const SMBv1::Transaction2ArgumentType*, const SMBv1::Transaction2ResultType*) override final;
    void transaction2SecondarySMBv1(const SMBv1::Transaction2SecondaryCommand* cmd, const SMBv1::Transaction2SecondaryArgumentType*, const SMBv1::Transaction2SecondaryResultType*) override final;
    void findClose2SMBv1(const SMBv1::FindClose2Command* cmd, const SMBv1::FindClose2ArgumentType*, const SMBv1::FindClose2ResultType*) override final;
    void findNotifyCloseSMBv1(const SMBv1::FindNotifyCloseCommand* cmd, const SMBv1::FindNotifyCloseArgumentType*, const SMBv1::FindNotifyCloseResultType*) override final;
    void treeConnectSMBv1(const SMBv1::TreeConnectCommand* cmd, const SMBv1::TreeConnectArgumentType*, const SMBv1::TreeConnectResultType*) override final;
    void treeDisconnectSMBv1(const SMBv1::TreeDisconnectCommand* cmd, const SMBv1::TreeDisconnectArgumentType*, const SMBv1::TreeDisconnectResultType*) override final;
    void negotiateSMBv1(const SMBv1::NegotiateCommand* cmd, const SMBv1::NegotiateArgumentType*, const SMBv1::NegotiateResultType*) override final;
    void sessionSetupAndxSMBv1(const SMBv1::SessionSetupAndxCommand* cmd, const SMBv1::SessionSetupAndxArgumentType*, const SMBv1::SessionSetupAndxResultType*) override final;
    void logoffAndxSMBv1(const SMBv1::LogoffAndxCommand* cmd, const SMBv1::LogoffAndxArgumentType*, const SMBv1::LogoffAndxResultType*) override final;
    void treeConnectAndxSMBv1(const SMBv1::TreeConnectAndxCommand* cmd, const SMBv1::TreeConnectAndxArgumentType*, const SMBv1::TreeConnectAndxResultType*) override final;
    void securityPackageAndxSMBv1(const SMBv1::SecurityPackageAndxCommand* cmd, const SMBv1::SecurityPackageAndxArgumentType*, const SMBv1::SecurityPackageAndxResultType*) override final;
    void queryInformationDiskSMBv1(const SMBv1::QueryInformationDiskCommand* cmd, const SMBv1::QueryInformationDiskArgumentType*, const SMBv1::QueryInformationDiskResultType*) override final;
    void searchSMBv1(const SMBv1::SearchCommand* cmd, const SMBv1::SearchArgumentType*, const SMBv1::SearchResultType*) override final;
    void findSMBv1(const SMBv1::FindCommand* cmd, const SMBv1::FindArgumentType*, const SMBv1::FindResultType*) override final;
    void findUniqueSMBv1(const SMBv1::FindUniqueCommand* cmd, const SMBv1::FindUniqueArgumentType*, const SMBv1::FindUniqueResultType*) override final;
    void findCloseSMBv1(const SMBv1::FindCloseCommand* cmd, const SMBv1::FindCloseArgumentType*, const SMBv1::FindCloseResultType*) override final;
    void ntTransactSMBv1(const SMBv1::NtTransactCommand* cmd, const SMBv1::NtTransactArgumentType*, const SMBv1::NtTransactResultType*) override final;
    void ntTransactSecondarySMBv1(const SMBv1::NtTransactSecondaryCommand* cmd, const SMBv1::NtTransactSecondaryArgumentType*, const SMBv1::NtTransactSecondaryResultType*) override final;
    void ntCreateAndxSMBv1(const SMBv1::NtCreateAndxCommand* cmd, const SMBv1::NtCreateAndxArgumentType*, const SMBv1::NtCreateAndxResultType*) override final;
    void ntCancelSMBv1(const SMBv1::NtCancelCommand* cmd, const SMBv1::NtCancelArgumentType*, const SMBv1::NtCancelResultType*) override final;
    void ntRenameSMBv1(const SMBv1::NtRenameCommand* cmd, const SMBv1::NtRenameArgumentType*, const SMBv1::NtRenameResultType*) override final;
    void openPrintFileSMBv1(const SMBv1::OpenPrintFileCommand* cmd, const SMBv1::OpenPrintFileArgumentType*, const SMBv1::OpenPrintFileResultType*) override final;
    void writePrintFileSMBv1(const SMBv1::WritePrintFileCommand* cmd, const SMBv1::WritePrintFileArgumentType*, const SMBv1::WritePrintFileResultType*) override final;
    void closePrintFileSMBv1(const SMBv1::ClosePrintFileCommand* cmd, const SMBv1::ClosePrintFileArgumentType*, const SMBv1::ClosePrintFileResultType*) override final;
    void getPrintQueueSMBv1(const SMBv1::GetPrintQueueCommand* cmd, const SMBv1::GetPrintQueueArgumentType*, const SMBv1::GetPrintQueueResultType*) override final;
    void readBulkSMBv1(const SMBv1::ReadBulkCommand* cmd, const SMBv1::ReadBulkArgumentType*, const SMBv1::ReadBulkResultType*) override final;
    void writeBulkSMBv1(const SMBv1::WriteBulkCommand* cmd, const SMBv1::WriteBulkArgumentType*, const SMBv1::WriteBulkResultType*) override final;
    void writeBulkDataSMBv1(const SMBv1::WriteBulkDataCommand* cmd, const SMBv1::WriteBulkDataArgumentType*, const SMBv1::WriteBulkDataResultType*) override final;
    void invalidSMBv1(const SMBv1::InvalidCommand* cmd, const SMBv1::InvalidArgumentType*, const SMBv1::InvalidResultType*) override final;
    void noAndxCommandSMBv1(const SMBv1::NoAndxCommand* cmd, const SMBv1::NoAndxCmdArgumentType*, const SMBv1::NoAndxCmdResultType*) override final;
    virtual void flush_statistics();
protected:
};
//------------------------------------------------------------------------------
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // CIFSBREAKDOWNANALYZER_H
//------------------------------------------------------------------------------

