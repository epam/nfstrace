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
#include "cifsbreakdownanalyzer.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
bool CIFSBreakdownAnalyzer::Less::operator()(const Session &a, const Session &b) const
{
    return ((a.port[0] < b.port[0]) && (a.port[1] <= b.port[1])) ||
            ((a.ip.v4.addr[0] < b.ip.v4.addr[0]) && (a.ip.v4.addr[1] <= b.ip.v4.addr[1]));
}


CIFSBreakdownAnalyzer::Statistic::Statistic() : procedures_total_count {0} {}


CIFSBreakdownAnalyzer::CIFSBreakdownAnalyzer(std::ostream &o)
    : representer(o)
{
}

void CIFSBreakdownAnalyzer::createDirectorySMBv1(const SMBv1::CreateDirectoryCommand *cmd, const SMBv1::CreateDirectoryArgumentType *, const SMBv1::CreateDirectoryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_CREATE_DIRECTORY, smbv1);
}

void CIFSBreakdownAnalyzer::deleteDirectorySMBv1(const SMBv1::DeleteDirectoryCommand *cmd, const SMBv1::DeleteDirectoryArgumentType *, const SMBv1::DeleteDirectoryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_DELETE_DIRECTORY, smbv1);
}

void CIFSBreakdownAnalyzer::openSMBv1(const SMBv1::OpenCommand *cmd, const SMBv1::OpenArgumentType *, const SMBv1::OpenResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_OPEN, smbv1);
}

void CIFSBreakdownAnalyzer::createSMBv1(const SMBv1::CreateCommand *cmd, const SMBv1::CreateArgumentType *, const SMBv1::CreateResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_CREATE, smbv1);
}

void CIFSBreakdownAnalyzer::closeSMBv1(const SMBv1::CloseCommand *cmd, const SMBv1::CloseArgumentType *, const SMBv1::CloseResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_CLOSE, smbv1);
}

void CIFSBreakdownAnalyzer::flushSMBv1(const SMBv1::FlushCommand *cmd, const SMBv1::FlushArgumentType *, const SMBv1::FlushResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_FLUSH, smbv1);
}

void CIFSBreakdownAnalyzer::deleteSMBv1(const SMBv1::DeleteCommand *cmd, const SMBv1::DeleteArgumentType *, const SMBv1::DeleteResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_DELETE, smbv1);
}

void CIFSBreakdownAnalyzer::renameSMBv1(const SMBv1::RenameCommand *cmd, const SMBv1::RenameArgumentType *, const SMBv1::RenameResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_RENAME, smbv1);
}

void CIFSBreakdownAnalyzer::queryInfoSMBv1(const SMBv1::QueryInformationCommand *cmd, const SMBv1::QueryInformationArgumentType *, const SMBv1::QueryInformationResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_QUERY_INFORMATION, smbv1);
}

void CIFSBreakdownAnalyzer::setInfoSMBv1(const SMBv1::SetInformationCommand *cmd, const SMBv1::SetInformationArgumentType *, const SMBv1::SetInformationResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_SET_INFORMATION, smbv1);
}

void CIFSBreakdownAnalyzer::readSMBv1(const SMBv1::ReadCommand *cmd, const SMBv1::ReadArgumentType *, const SMBv1::ReadResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_READ, smbv1);
}

void CIFSBreakdownAnalyzer::writeSMBv1(const SMBv1::WriteCommand *cmd, const SMBv1::WriteArgumentType *, const SMBv1::WriteResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE, smbv1);
}

void CIFSBreakdownAnalyzer::lockByteRangeSMBv1(const SMBv1::LockByteRangeCommand *cmd, const SMBv1::LockByteRangeArgumentType *, const SMBv1::LockByteRangeResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_LOCK_BYTE_RANGE, smbv1);
}

void CIFSBreakdownAnalyzer::unlockByteRangeSMBv1(const SMBv1::UnlockByteRangeCommand *cmd, const SMBv1::UnlockByteRangeArgumentType *, const SMBv1::UnlockByteRangeResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_UNLOCK_BYTE_RANGE, smbv1);
}

void CIFSBreakdownAnalyzer::createTmpSMBv1(const SMBv1::CreateTemporaryCommand *cmd, const SMBv1::CreateTemporaryArgumentType *, const SMBv1::CreateTemporaryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_CREATE_TEMPORARY, smbv1);
}

void CIFSBreakdownAnalyzer::createNewSMBv1(const SMBv1::CreateNewCommand *cmd, const SMBv1::CreateNewArgumentType *, const SMBv1::CreateNewResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_CREATE_NEW, smbv1);
}

void CIFSBreakdownAnalyzer::checkDirectorySMBv1(const SMBv1::CheckDirectoryCommand *cmd, const SMBv1::CheckDirectoryArgumentType *, const SMBv1::CheckDirectoryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_CHECK_DIRECTORY, smbv1);
}

void CIFSBreakdownAnalyzer::processExitSMBv1(const SMBv1::ProcessExitCommand *cmd, const SMBv1::ProcessExitArgumentType *, const SMBv1::ProcessExitResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_PROCESS_EXIT, smbv1);
}

void CIFSBreakdownAnalyzer::seekSMBv1(const SMBv1::SeekCommand *cmd, const SMBv1::SeekArgumentType *, const SMBv1::SeekResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_SEEK, smbv1);
}

void CIFSBreakdownAnalyzer::lockAndReadSMBv1(const SMBv1::LockAndReadCommand *cmd, const SMBv1::LockAndReadArgumentType *, const SMBv1::LockAndReadResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_LOCK_AND_READ, smbv1);
}

void CIFSBreakdownAnalyzer::writeAndUnlockSMBv1(const SMBv1::WriteAndUnlockCommand *cmd, const SMBv1::WriteAndUnlockArgumentType *, const SMBv1::WriteAndUnlockResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_AND_UNLOCK, smbv1);
}

void CIFSBreakdownAnalyzer::readRawSMBv1(const SMBv1::ReadRawCommand *cmd, const SMBv1::ReadRawArgumentType *, const SMBv1::ReadRawResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_READ_RAW, smbv1);
}

void CIFSBreakdownAnalyzer::readMpxSMBv1(const SMBv1::ReadMpxCommand *cmd, const SMBv1::ReadMpxArgumentType *, const SMBv1::ReadMpxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_READ_MPX, smbv1);
}

void CIFSBreakdownAnalyzer::readMpxSecondarySMBv1(const SMBv1::ReadMpxSecondaryCommand *cmd, const SMBv1::ReadMpxSecondaryArgumentType *, const SMBv1::ReadMpxSecondaryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_READ_MPX_SECONDARY, smbv1);
}

void CIFSBreakdownAnalyzer::writeRawSMBv1(const SMBv1::WriteRawCommand *cmd, const SMBv1::WriteRawArgumentType *, const SMBv1::WriteRawResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_RAW, smbv1);
}

void CIFSBreakdownAnalyzer::writeMpxSMBv1(const SMBv1::WriteMpxCommand *cmd, const SMBv1::WriteMpxArgumentType *, const SMBv1::WriteMpxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_MPX, smbv1);
}

void CIFSBreakdownAnalyzer::writeMpxSecondarySMBv1(const SMBv1::WriteMpxSecondaryCommand *cmd, const SMBv1::WriteMpxSecondaryArgumentType *, const SMBv1::WriteMpxSecondaryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_MPX_SECONDARY, smbv1);
}

void CIFSBreakdownAnalyzer::writeCompleteSMBv1(const SMBv1::WriteCompleteCommand *cmd, const SMBv1::WriteCompleteArgumentType *, const SMBv1::WriteCompleteResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_COMPLETE, smbv1);
}

void CIFSBreakdownAnalyzer::queryServerSMBv1(const SMBv1::QueryServerCommand *cmd, const SMBv1::QueryServerArgumentType *, const SMBv1::QueryServerResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_QUERY_SERVER, smbv1);
}

void CIFSBreakdownAnalyzer::setInfo2SMBv1(const SMBv1::SetInformation2Command *cmd, const SMBv1::SetInformation2ArgumentType *, const SMBv1::SetInformation2ResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_SET_INFORMATION2, smbv1);
}

void CIFSBreakdownAnalyzer::queryInfo2SMBv1(const SMBv1::QueryInformation2Command *cmd, const SMBv1::QueryInformation2ArgumentType *, const SMBv1::QueryInformation2ResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_QUERY_INFORMATION2, smbv1);
}

void CIFSBreakdownAnalyzer::lockingAndxSMBv1(const SMBv1::LockingAndxCommand *cmd, const SMBv1::LockingAndxArgumentType *, const SMBv1::LockingAndxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_LOCKING_ANDX, smbv1);
}

void CIFSBreakdownAnalyzer::transactionSMBv1(const SMBv1::TransactionCommand *cmd, const SMBv1::TransactionArgumentType *, const SMBv1::TransactionResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_TRANSACTION, smbv1);
}

void CIFSBreakdownAnalyzer::transactionSecondarySMBv1(const SMBv1::TransactionSecondaryCommand *cmd, const SMBv1::TransactionSecondaryArgumentType *, const SMBv1::TransactionSecondaryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_TRANSACTION_SECONDARY, smbv1);
}

void CIFSBreakdownAnalyzer::ioctlSMBv1(const SMBv1::IoctlCommand *cmd, const SMBv1::IoctlArgumentType *, const SMBv1::IoctlResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_IOCTL, smbv1);
}

void CIFSBreakdownAnalyzer::ioctlSecondarySMBv1(const SMBv1::IoctlSecondaryCommand *cmd, const SMBv1::IoctlSecondaryArgumentType *, const SMBv1::IoctlSecondaryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_IOCTL_SECONDARY, smbv1);
}

void CIFSBreakdownAnalyzer::copySMBv1(const SMBv1::CopyCommand *cmd, const SMBv1::CopyArgumentType *, const SMBv1::CopyResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_COPY, smbv1);
}

void CIFSBreakdownAnalyzer::moveSMBv1(const SMBv1::MoveCommand *cmd, const SMBv1::MoveArgumentType *, const SMBv1::MoveResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_MOVE, smbv1);
}

void CIFSBreakdownAnalyzer::echoSMBv1(const SMBv1::EchoCommand *cmd, const SMBv1::EchoArgumentType *, const SMBv1::EchoResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_ECHO, smbv1);
}

void CIFSBreakdownAnalyzer::writeAndCloseSMBv1(const SMBv1::WriteAndCloseCommand *cmd, const SMBv1::WriteAndCloseArgumentType *, const SMBv1::WriteAndCloseResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_AND_CLOSE, smbv1);
}

void CIFSBreakdownAnalyzer::openAndxSMBv1(const SMBv1::OpenAndxCommand *cmd, const SMBv1::OpenAndxArgumentType *, const SMBv1::OpenAndxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_OPEN_ANDX, smbv1);
}

void CIFSBreakdownAnalyzer::readAndxSMBv1(const SMBv1::ReadAndxCommand *cmd, const SMBv1::ReadAndxArgumentType *, const SMBv1::ReadAndxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_READ_ANDX, smbv1);
}

void CIFSBreakdownAnalyzer::writeAndxSMBv1(const SMBv1::WriteAndxCommand *cmd, const SMBv1::WriteAndxArgumentType *, const SMBv1::WriteAndxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_ANDX, smbv1);
}

void CIFSBreakdownAnalyzer::newFileSizeSMBv1(const SMBv1::NewFileSizeCommand *cmd, const SMBv1::NewFileSizeArgumentType *, const SMBv1::NewFileSizeResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_NEW_FILE_SIZE, smbv1);
}

void CIFSBreakdownAnalyzer::closeAndTreeDiscSMBv1(const SMBv1::CloseAndTreeDiscCommand *cmd, const SMBv1::CloseAndTreeDiscArgumentType *, const SMBv1::CloseAndTreeDiscResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_CLOSE_AND_TREE_DISC, smbv1);
}

void CIFSBreakdownAnalyzer::transaction2SMBv1(const SMBv1::Transaction2Command *cmd, const SMBv1::Transaction2ArgumentType *, const SMBv1::Transaction2ResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_TRANSACTION2, smbv1);
}

void CIFSBreakdownAnalyzer::transaction2SecondarySMBv1(const SMBv1::Transaction2SecondaryCommand *cmd, const SMBv1::Transaction2SecondaryArgumentType *, const SMBv1::Transaction2SecondaryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_TRANSACTION2_SECONDARY, smbv1);
}

void CIFSBreakdownAnalyzer::findClose2SMBv1(const SMBv1::FindClose2Command *cmd, const SMBv1::FindClose2ArgumentType *, const SMBv1::FindClose2ResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_FIND_CLOSE2, smbv1);
}

void CIFSBreakdownAnalyzer::findNotifyCloseSMBv1(const SMBv1::FindNotifyCloseCommand *cmd, const SMBv1::FindNotifyCloseArgumentType *, const SMBv1::FindNotifyCloseResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_FIND_NOTIFY_CLOSE, smbv1);
}

void CIFSBreakdownAnalyzer::treeConnectSMBv1(const SMBv1::TreeConnectCommand *cmd, const SMBv1::TreeConnectArgumentType *, const SMBv1::TreeConnectResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_TREE_CONNECT, smbv1);
}

void CIFSBreakdownAnalyzer::treeDisconnectSMBv1(const SMBv1::TreeDisconnectCommand *cmd, const SMBv1::TreeDisconnectArgumentType *, const SMBv1::TreeDisconnectResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_TREE_DISCONNECT, smbv1);
}

void CIFSBreakdownAnalyzer::negotiateSMBv1(const SMBv1::NegotiateCommand *cmd, const SMBv1::NegotiateArgumentType *, const SMBv1::NegotiateResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_NEGOTIATE, smbv1);
}

void CIFSBreakdownAnalyzer::sessionSetupAndxSMBv1(const SMBv1::SessionSetupAndxCommand *cmd, const SMBv1::SessionSetupAndxArgumentType *, const SMBv1::SessionSetupAndxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_SESSION_SETUP_ANDX, smbv1);
}

void CIFSBreakdownAnalyzer::logoffAndxSMBv1(const SMBv1::LogoffAndxCommand *cmd, const SMBv1::LogoffAndxArgumentType *, const SMBv1::LogoffAndxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_LOGOFF_ANDX, smbv1);
}

void CIFSBreakdownAnalyzer::treeConnectAndxSMBv1(const SMBv1::TreeConnectAndxCommand *cmd, const SMBv1::TreeConnectAndxArgumentType *, const SMBv1::TreeConnectAndxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_TREE_CONNECT_ANDX, smbv1);
}

void CIFSBreakdownAnalyzer::securityPackageAndxSMBv1(const SMBv1::SecurityPackageAndxCommand *cmd, const SMBv1::SecurityPackageAndxArgumentType *, const SMBv1::SecurityPackageAndxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_SECURITY_PACKAGE_ANDX, smbv1);
}

void CIFSBreakdownAnalyzer::queryInformationDiskSMBv1(const SMBv1::QueryInformationDiskCommand *cmd, const SMBv1::QueryInformationDiskArgumentType *, const SMBv1::QueryInformationDiskResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_QUERY_INFORMATION_DISK, smbv1);
}

void CIFSBreakdownAnalyzer::searchSMBv1(const SMBv1::SearchCommand *cmd, const SMBv1::SearchArgumentType *, const SMBv1::SearchResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_SEARCH, smbv1);
}

void CIFSBreakdownAnalyzer::findSMBv1(const SMBv1::FindCommand *cmd, const SMBv1::FindArgumentType *, const SMBv1::FindResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_FIND, smbv1);
}

void CIFSBreakdownAnalyzer::findUniqueSMBv1(const SMBv1::FindUniqueCommand *cmd, const SMBv1::FindUniqueArgumentType *, const SMBv1::FindUniqueResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_FIND_UNIQUE, smbv1);
}

void CIFSBreakdownAnalyzer::findCloseSMBv1(const SMBv1::FindCloseCommand *cmd, const SMBv1::FindCloseArgumentType *, const SMBv1::FindCloseResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_FIND_CLOSE, smbv1);
}

void CIFSBreakdownAnalyzer::ntTransactSMBv1(const SMBv1::NtTransactCommand *cmd, const SMBv1::NtTransactArgumentType *, const SMBv1::NtTransactResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_NT_TRANSACT, smbv1);
}

void CIFSBreakdownAnalyzer::ntTransactSecondarySMBv1(const SMBv1::NtTransactSecondaryCommand *cmd, const SMBv1::NtTransactSecondaryArgumentType *, const SMBv1::NtTransactSecondaryResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_NT_TRANSACT_SECONDARY, smbv1);
}

void CIFSBreakdownAnalyzer::ntCreateAndxSMBv1(const SMBv1::NtCreateAndxCommand *cmd, const SMBv1::NtCreateAndxArgumentType *, const SMBv1::NtCreateAndxResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_NT_CREATE_ANDX, smbv1);
}

void CIFSBreakdownAnalyzer::ntCancelSMBv1(const SMBv1::NtCancelCommand *cmd, const SMBv1::NtCancelArgumentType *, const SMBv1::NtCancelResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_NT_CANCEL, smbv1);
}

void CIFSBreakdownAnalyzer::ntRenameSMBv1(const SMBv1::NtRenameCommand *cmd, const SMBv1::NtRenameArgumentType *, const SMBv1::NtRenameResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_NT_RENAME, smbv1);
}

void CIFSBreakdownAnalyzer::openPrintFileSMBv1(const SMBv1::OpenPrintFileCommand *cmd, const SMBv1::OpenPrintFileArgumentType *, const SMBv1::OpenPrintFileResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_OPEN_PRINT_FILE, smbv1);
}

void CIFSBreakdownAnalyzer::writePrintFileSMBv1(const SMBv1::WritePrintFileCommand *cmd, const SMBv1::WritePrintFileArgumentType *, const SMBv1::WritePrintFileResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_PRINT_FILE, smbv1);
}

void CIFSBreakdownAnalyzer::closePrintFileSMBv1(const SMBv1::ClosePrintFileCommand *cmd, const SMBv1::ClosePrintFileArgumentType *, const SMBv1::ClosePrintFileResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_CLOSE_PRINT_FILE, smbv1);
}

void CIFSBreakdownAnalyzer::getPrintQueueSMBv1(const SMBv1::GetPrintQueueCommand *cmd, const SMBv1::GetPrintQueueArgumentType *, const SMBv1::GetPrintQueueResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_GET_PRINT_QUEUE, smbv1);
}

void CIFSBreakdownAnalyzer::readBulkSMBv1(const SMBv1::ReadBulkCommand *cmd, const SMBv1::ReadBulkArgumentType *, const SMBv1::ReadBulkResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_READ_BULK, smbv1);
}

void CIFSBreakdownAnalyzer::writeBulkSMBv1(const SMBv1::WriteBulkCommand *cmd, const SMBv1::WriteBulkArgumentType *, const SMBv1::WriteBulkResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_BULK, smbv1);
}

void CIFSBreakdownAnalyzer::writeBulkDataSMBv1(const SMBv1::WriteBulkDataCommand *cmd, const SMBv1::WriteBulkDataArgumentType *, const SMBv1::WriteBulkDataResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_WRITE_BULK_DATA, smbv1);
}

void CIFSBreakdownAnalyzer::invalidSMBv1(const SMBv1::InvalidCommand *cmd, const SMBv1::InvalidArgumentType *, const SMBv1::InvalidResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_INVALID, smbv1);
}

void CIFSBreakdownAnalyzer::noAndxCommandSMBv1(const SMBv1::NoAndxCommand *cmd, const SMBv1::NoAndxCmdArgumentType *, const SMBv1::NoAndxCmdResultType *)
{
    account(cmd, SMBv1Commands::SMB_COM_NO_ANDX_COMMAND, smbv1);
}

void CIFSBreakdownAnalyzer::flush_statistics()
{
    representer.flush_statistics(smbv1);
}
//------------------------------------------------------------------------------
