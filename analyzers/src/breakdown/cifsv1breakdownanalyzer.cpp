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
#include "cifsv1commands.h"
#include "cifsv1breakdownanalyzer.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
static const size_t space_for_cmd_name = 22;
//------------------------------------------------------------------------------
CIFSBreakdownAnalyzer::CIFSBreakdownAnalyzer(std::ostream& o)
    : stats(SMBv1Commands().commands_count())
    , representer(o, new SMBv1Commands(), space_for_cmd_name)
{
}

void CIFSBreakdownAnalyzer::createDirectorySMBv1(const SMBv1::CreateDirectoryCommand* cmd, const SMBv1::CreateDirectoryArgumentType*, const SMBv1::CreateDirectoryResultType*)
{
    stats.account(cmd, SMBv1Commands::CREATE_DIRECTORY);
}

void CIFSBreakdownAnalyzer::deleteDirectorySMBv1(const SMBv1::DeleteDirectoryCommand* cmd, const SMBv1::DeleteDirectoryArgumentType*, const SMBv1::DeleteDirectoryResultType*)
{
    stats.account(cmd, SMBv1Commands::DELETE_DIRECTORY);
}

void CIFSBreakdownAnalyzer::openSMBv1(const SMBv1::OpenCommand* cmd, const SMBv1::OpenArgumentType*, const SMBv1::OpenResultType*)
{
    stats.account(cmd, SMBv1Commands::OPEN);
}

void CIFSBreakdownAnalyzer::createSMBv1(const SMBv1::CreateCommand* cmd, const SMBv1::CreateArgumentType*, const SMBv1::CreateResultType*)
{
    stats.account(cmd, SMBv1Commands::CREATE);
}

void CIFSBreakdownAnalyzer::closeSMBv1(const SMBv1::CloseCommand* cmd, const SMBv1::CloseArgumentType*, const SMBv1::CloseResultType*)
{
    stats.account(cmd, SMBv1Commands::CLOSE);
}

void CIFSBreakdownAnalyzer::flushSMBv1(const SMBv1::FlushCommand* cmd, const SMBv1::FlushArgumentType*, const SMBv1::FlushResultType*)
{
    stats.account(cmd, SMBv1Commands::FLUSH);
}

void CIFSBreakdownAnalyzer::deleteSMBv1(const SMBv1::DeleteCommand* cmd, const SMBv1::DeleteArgumentType*, const SMBv1::DeleteResultType*)
{
    stats.account(cmd, SMBv1Commands::DELETE);
}

void CIFSBreakdownAnalyzer::renameSMBv1(const SMBv1::RenameCommand* cmd, const SMBv1::RenameArgumentType*, const SMBv1::RenameResultType*)
{
    stats.account(cmd, SMBv1Commands::RENAME);
}

void CIFSBreakdownAnalyzer::queryInfoSMBv1(const SMBv1::QueryInformationCommand* cmd, const SMBv1::QueryInformationArgumentType*, const SMBv1::QueryInformationResultType*)
{
    stats.account(cmd, SMBv1Commands::QUERY_INFORMATION);
}

void CIFSBreakdownAnalyzer::setInfoSMBv1(const SMBv1::SetInformationCommand* cmd, const SMBv1::SetInformationArgumentType*, const SMBv1::SetInformationResultType*)
{
    stats.account(cmd, SMBv1Commands::SET_INFORMATION);
}

void CIFSBreakdownAnalyzer::readSMBv1(const SMBv1::ReadCommand* cmd, const SMBv1::ReadArgumentType*, const SMBv1::ReadResultType*)
{
    stats.account(cmd, SMBv1Commands::READ);
}

void CIFSBreakdownAnalyzer::writeSMBv1(const SMBv1::WriteCommand* cmd, const SMBv1::WriteArgumentType*, const SMBv1::WriteResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE);
}

void CIFSBreakdownAnalyzer::lockByteRangeSMBv1(const SMBv1::LockByteRangeCommand* cmd, const SMBv1::LockByteRangeArgumentType*, const SMBv1::LockByteRangeResultType*)
{
    stats.account(cmd, SMBv1Commands::LOCK_BYTE_RANGE);
}

void CIFSBreakdownAnalyzer::unlockByteRangeSMBv1(const SMBv1::UnlockByteRangeCommand* cmd, const SMBv1::UnlockByteRangeArgumentType*, const SMBv1::UnlockByteRangeResultType*)
{
    stats.account(cmd, SMBv1Commands::UNLOCK_BYTE_RANGE);
}

void CIFSBreakdownAnalyzer::createTmpSMBv1(const SMBv1::CreateTemporaryCommand* cmd, const SMBv1::CreateTemporaryArgumentType*, const SMBv1::CreateTemporaryResultType*)
{
    stats.account(cmd, SMBv1Commands::CREATE_TEMPORARY);
}

void CIFSBreakdownAnalyzer::createNewSMBv1(const SMBv1::CreateNewCommand* cmd, const SMBv1::CreateNewArgumentType*, const SMBv1::CreateNewResultType*)
{
    stats.account(cmd, SMBv1Commands::CREATE_NEW);
}

void CIFSBreakdownAnalyzer::checkDirectorySMBv1(const SMBv1::CheckDirectoryCommand* cmd, const SMBv1::CheckDirectoryArgumentType*, const SMBv1::CheckDirectoryResultType*)
{
    stats.account(cmd, SMBv1Commands::CHECK_DIRECTORY);
}

void CIFSBreakdownAnalyzer::processExitSMBv1(const SMBv1::ProcessExitCommand* cmd, const SMBv1::ProcessExitArgumentType*, const SMBv1::ProcessExitResultType*)
{
    stats.account(cmd, SMBv1Commands::PROCESS_EXIT);
}

void CIFSBreakdownAnalyzer::seekSMBv1(const SMBv1::SeekCommand* cmd, const SMBv1::SeekArgumentType*, const SMBv1::SeekResultType*)
{
    stats.account(cmd, SMBv1Commands::SEEK);
}

void CIFSBreakdownAnalyzer::lockAndReadSMBv1(const SMBv1::LockAndReadCommand* cmd, const SMBv1::LockAndReadArgumentType*, const SMBv1::LockAndReadResultType*)
{
    stats.account(cmd, SMBv1Commands::LOCK_AND_READ);
}

void CIFSBreakdownAnalyzer::writeAndUnlockSMBv1(const SMBv1::WriteAndUnlockCommand* cmd, const SMBv1::WriteAndUnlockArgumentType*, const SMBv1::WriteAndUnlockResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_AND_UNLOCK);
}

void CIFSBreakdownAnalyzer::readRawSMBv1(const SMBv1::ReadRawCommand* cmd, const SMBv1::ReadRawArgumentType*, const SMBv1::ReadRawResultType*)
{
    stats.account(cmd, SMBv1Commands::READ_RAW);
}

void CIFSBreakdownAnalyzer::readMpxSMBv1(const SMBv1::ReadMpxCommand* cmd, const SMBv1::ReadMpxArgumentType*, const SMBv1::ReadMpxResultType*)
{
    stats.account(cmd, SMBv1Commands::READ_MPX);
}

void CIFSBreakdownAnalyzer::readMpxSecondarySMBv1(const SMBv1::ReadMpxSecondaryCommand* cmd, const SMBv1::ReadMpxSecondaryArgumentType*, const SMBv1::ReadMpxSecondaryResultType*)
{
    stats.account(cmd, SMBv1Commands::READ_MPX_SECONDARY);
}

void CIFSBreakdownAnalyzer::writeRawSMBv1(const SMBv1::WriteRawCommand* cmd, const SMBv1::WriteRawArgumentType*, const SMBv1::WriteRawResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_RAW);
}

void CIFSBreakdownAnalyzer::writeMpxSMBv1(const SMBv1::WriteMpxCommand* cmd, const SMBv1::WriteMpxArgumentType*, const SMBv1::WriteMpxResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_MPX);
}

void CIFSBreakdownAnalyzer::writeMpxSecondarySMBv1(const SMBv1::WriteMpxSecondaryCommand* cmd, const SMBv1::WriteMpxSecondaryArgumentType*, const SMBv1::WriteMpxSecondaryResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_MPX_SECONDARY);
}

void CIFSBreakdownAnalyzer::writeCompleteSMBv1(const SMBv1::WriteCompleteCommand* cmd, const SMBv1::WriteCompleteArgumentType*, const SMBv1::WriteCompleteResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_COMPLETE);
}

void CIFSBreakdownAnalyzer::queryServerSMBv1(const SMBv1::QueryServerCommand* cmd, const SMBv1::QueryServerArgumentType*, const SMBv1::QueryServerResultType*)
{
    stats.account(cmd, SMBv1Commands::QUERY_SERVER);
}

void CIFSBreakdownAnalyzer::setInfo2SMBv1(const SMBv1::SetInformation2Command* cmd, const SMBv1::SetInformation2ArgumentType*, const SMBv1::SetInformation2ResultType*)
{
    stats.account(cmd, SMBv1Commands::SET_INFORMATION2);
}

void CIFSBreakdownAnalyzer::queryInfo2SMBv1(const SMBv1::QueryInformation2Command* cmd, const SMBv1::QueryInformation2ArgumentType*, const SMBv1::QueryInformation2ResultType*)
{
    stats.account(cmd, SMBv1Commands::QUERY_INFORMATION2);
}

void CIFSBreakdownAnalyzer::lockingAndxSMBv1(const SMBv1::LockingAndxCommand* cmd, const SMBv1::LockingAndxArgumentType*, const SMBv1::LockingAndxResultType*)
{
    stats.account(cmd, SMBv1Commands::LOCKING_ANDX);
}

void CIFSBreakdownAnalyzer::transactionSMBv1(const SMBv1::TransactionCommand* cmd, const SMBv1::TransactionArgumentType*, const SMBv1::TransactionResultType*)
{
    stats.account(cmd, SMBv1Commands::TRANSACTION);
}

void CIFSBreakdownAnalyzer::transactionSecondarySMBv1(const SMBv1::TransactionSecondaryCommand* cmd, const SMBv1::TransactionSecondaryArgumentType*, const SMBv1::TransactionSecondaryResultType*)
{
    stats.account(cmd, SMBv1Commands::TRANSACTION_SECONDARY);
}

void CIFSBreakdownAnalyzer::ioctlSMBv1(const SMBv1::IoctlCommand* cmd, const SMBv1::IoctlArgumentType*, const SMBv1::IoctlResultType*)
{
    stats.account(cmd, SMBv1Commands::IOCTL);
}

void CIFSBreakdownAnalyzer::ioctlSecondarySMBv1(const SMBv1::IoctlSecondaryCommand* cmd, const SMBv1::IoctlSecondaryArgumentType*, const SMBv1::IoctlSecondaryResultType*)
{
    stats.account(cmd, SMBv1Commands::IOCTL_SECONDARY);
}

void CIFSBreakdownAnalyzer::copySMBv1(const SMBv1::CopyCommand* cmd, const SMBv1::CopyArgumentType*, const SMBv1::CopyResultType*)
{
    stats.account(cmd, SMBv1Commands::COPY);
}

void CIFSBreakdownAnalyzer::moveSMBv1(const SMBv1::MoveCommand* cmd, const SMBv1::MoveArgumentType*, const SMBv1::MoveResultType*)
{
    stats.account(cmd, SMBv1Commands::MOVE);
}

void CIFSBreakdownAnalyzer::echoSMBv1(const SMBv1::EchoCommand* cmd, const SMBv1::EchoArgumentType*, const SMBv1::EchoResultType*)
{
    stats.account(cmd, SMBv1Commands::ECHO);
}

void CIFSBreakdownAnalyzer::writeAndCloseSMBv1(const SMBv1::WriteAndCloseCommand* cmd, const SMBv1::WriteAndCloseArgumentType*, const SMBv1::WriteAndCloseResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_AND_CLOSE);
}

void CIFSBreakdownAnalyzer::openAndxSMBv1(const SMBv1::OpenAndxCommand* cmd, const SMBv1::OpenAndxArgumentType*, const SMBv1::OpenAndxResultType*)
{
    stats.account(cmd, SMBv1Commands::OPEN_ANDX);
}

void CIFSBreakdownAnalyzer::readAndxSMBv1(const SMBv1::ReadAndxCommand* cmd, const SMBv1::ReadAndxArgumentType*, const SMBv1::ReadAndxResultType*)
{
    stats.account(cmd, SMBv1Commands::READ_ANDX);
}

void CIFSBreakdownAnalyzer::writeAndxSMBv1(const SMBv1::WriteAndxCommand* cmd, const SMBv1::WriteAndxArgumentType*, const SMBv1::WriteAndxResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_ANDX);
}

void CIFSBreakdownAnalyzer::newFileSizeSMBv1(const SMBv1::NewFileSizeCommand* cmd, const SMBv1::NewFileSizeArgumentType*, const SMBv1::NewFileSizeResultType*)
{
    stats.account(cmd, SMBv1Commands::NEW_FILE_SIZE);
}

void CIFSBreakdownAnalyzer::closeAndTreeDiscSMBv1(const SMBv1::CloseAndTreeDiscCommand* cmd, const SMBv1::CloseAndTreeDiscArgumentType*, const SMBv1::CloseAndTreeDiscResultType*)
{
    stats.account(cmd, SMBv1Commands::CLOSE_AND_TREE_DISC);
}

void CIFSBreakdownAnalyzer::transaction2SMBv1(const SMBv1::Transaction2Command* cmd, const SMBv1::Transaction2ArgumentType*, const SMBv1::Transaction2ResultType*)
{
    stats.account(cmd, SMBv1Commands::TRANSACTION2);
}

void CIFSBreakdownAnalyzer::transaction2SecondarySMBv1(const SMBv1::Transaction2SecondaryCommand* cmd, const SMBv1::Transaction2SecondaryArgumentType*, const SMBv1::Transaction2SecondaryResultType*)
{
    stats.account(cmd, SMBv1Commands::TRANSACTION2_SECONDARY);
}

void CIFSBreakdownAnalyzer::findClose2SMBv1(const SMBv1::FindClose2Command* cmd, const SMBv1::FindClose2ArgumentType*, const SMBv1::FindClose2ResultType*)
{
    stats.account(cmd, SMBv1Commands::FIND_CLOSE2);
}

void CIFSBreakdownAnalyzer::findNotifyCloseSMBv1(const SMBv1::FindNotifyCloseCommand* cmd, const SMBv1::FindNotifyCloseArgumentType*, const SMBv1::FindNotifyCloseResultType*)
{
    stats.account(cmd, SMBv1Commands::FIND_NOTIFY_CLOSE);
}

void CIFSBreakdownAnalyzer::treeConnectSMBv1(const SMBv1::TreeConnectCommand* cmd, const SMBv1::TreeConnectArgumentType*, const SMBv1::TreeConnectResultType*)
{
    stats.account(cmd, SMBv1Commands::TREE_CONNECT);
}

void CIFSBreakdownAnalyzer::treeDisconnectSMBv1(const SMBv1::TreeDisconnectCommand* cmd, const SMBv1::TreeDisconnectArgumentType*, const SMBv1::TreeDisconnectResultType*)
{
    stats.account(cmd, SMBv1Commands::TREE_DISCONNECT);
}

void CIFSBreakdownAnalyzer::negotiateSMBv1(const SMBv1::NegotiateCommand* cmd, const SMBv1::NegotiateArgumentType*, const SMBv1::NegotiateResultType*)
{
    stats.account(cmd, SMBv1Commands::NEGOTIATE);
}

void CIFSBreakdownAnalyzer::sessionSetupAndxSMBv1(const SMBv1::SessionSetupAndxCommand* cmd, const SMBv1::SessionSetupAndxArgumentType*, const SMBv1::SessionSetupAndxResultType*)
{
    stats.account(cmd, SMBv1Commands::SESSION_SETUP_ANDX);
}

void CIFSBreakdownAnalyzer::logoffAndxSMBv1(const SMBv1::LogoffAndxCommand* cmd, const SMBv1::LogoffAndxArgumentType*, const SMBv1::LogoffAndxResultType*)
{
    stats.account(cmd, SMBv1Commands::LOGOFF_ANDX);
}

void CIFSBreakdownAnalyzer::treeConnectAndxSMBv1(const SMBv1::TreeConnectAndxCommand* cmd, const SMBv1::TreeConnectAndxArgumentType*, const SMBv1::TreeConnectAndxResultType*)
{
    stats.account(cmd, SMBv1Commands::TREE_CONNECT_ANDX);
}

void CIFSBreakdownAnalyzer::securityPackageAndxSMBv1(const SMBv1::SecurityPackageAndxCommand* cmd, const SMBv1::SecurityPackageAndxArgumentType*, const SMBv1::SecurityPackageAndxResultType*)
{
    stats.account(cmd, SMBv1Commands::SECURITY_PACKAGE_ANDX);
}

void CIFSBreakdownAnalyzer::queryInformationDiskSMBv1(const SMBv1::QueryInformationDiskCommand* cmd, const SMBv1::QueryInformationDiskArgumentType*, const SMBv1::QueryInformationDiskResultType*)
{
    stats.account(cmd, SMBv1Commands::QUERY_INFORMATION_DISK);
}

void CIFSBreakdownAnalyzer::searchSMBv1(const SMBv1::SearchCommand* cmd, const SMBv1::SearchArgumentType*, const SMBv1::SearchResultType*)
{
    stats.account(cmd, SMBv1Commands::SEARCH);
}

void CIFSBreakdownAnalyzer::findSMBv1(const SMBv1::FindCommand* cmd, const SMBv1::FindArgumentType*, const SMBv1::FindResultType*)
{
    stats.account(cmd, SMBv1Commands::FIND);
}

void CIFSBreakdownAnalyzer::findUniqueSMBv1(const SMBv1::FindUniqueCommand* cmd, const SMBv1::FindUniqueArgumentType*, const SMBv1::FindUniqueResultType*)
{
    stats.account(cmd, SMBv1Commands::FIND_UNIQUE);
}

void CIFSBreakdownAnalyzer::findCloseSMBv1(const SMBv1::FindCloseCommand* cmd, const SMBv1::FindCloseArgumentType*, const SMBv1::FindCloseResultType*)
{
    stats.account(cmd, SMBv1Commands::FIND_CLOSE);
}

void CIFSBreakdownAnalyzer::ntTransactSMBv1(const SMBv1::NtTransactCommand* cmd, const SMBv1::NtTransactArgumentType*, const SMBv1::NtTransactResultType*)
{
    stats.account(cmd, SMBv1Commands::NT_TRANSACT);
}

void CIFSBreakdownAnalyzer::ntTransactSecondarySMBv1(const SMBv1::NtTransactSecondaryCommand* cmd, const SMBv1::NtTransactSecondaryArgumentType*, const SMBv1::NtTransactSecondaryResultType*)
{
    stats.account(cmd, SMBv1Commands::NT_TRANSACT_SECONDARY);
}

void CIFSBreakdownAnalyzer::ntCreateAndxSMBv1(const SMBv1::NtCreateAndxCommand* cmd, const SMBv1::NtCreateAndxArgumentType*, const SMBv1::NtCreateAndxResultType*)
{
    stats.account(cmd, SMBv1Commands::NT_CREATE_ANDX);
}

void CIFSBreakdownAnalyzer::ntCancelSMBv1(const SMBv1::NtCancelCommand* cmd, const SMBv1::NtCancelArgumentType*, const SMBv1::NtCancelResultType*)
{
    stats.account(cmd, SMBv1Commands::NT_CANCEL);
}

void CIFSBreakdownAnalyzer::ntRenameSMBv1(const SMBv1::NtRenameCommand* cmd, const SMBv1::NtRenameArgumentType*, const SMBv1::NtRenameResultType*)
{
    stats.account(cmd, SMBv1Commands::NT_RENAME);
}

void CIFSBreakdownAnalyzer::openPrintFileSMBv1(const SMBv1::OpenPrintFileCommand* cmd, const SMBv1::OpenPrintFileArgumentType*, const SMBv1::OpenPrintFileResultType*)
{
    stats.account(cmd, SMBv1Commands::OPEN_PRINT_FILE);
}

void CIFSBreakdownAnalyzer::writePrintFileSMBv1(const SMBv1::WritePrintFileCommand* cmd, const SMBv1::WritePrintFileArgumentType*, const SMBv1::WritePrintFileResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_PRINT_FILE);
}

void CIFSBreakdownAnalyzer::closePrintFileSMBv1(const SMBv1::ClosePrintFileCommand* cmd, const SMBv1::ClosePrintFileArgumentType*, const SMBv1::ClosePrintFileResultType*)
{
    stats.account(cmd, SMBv1Commands::CLOSE_PRINT_FILE);
}

void CIFSBreakdownAnalyzer::getPrintQueueSMBv1(const SMBv1::GetPrintQueueCommand* cmd, const SMBv1::GetPrintQueueArgumentType*, const SMBv1::GetPrintQueueResultType*)
{
    stats.account(cmd, SMBv1Commands::GET_PRINT_QUEUE);
}

void CIFSBreakdownAnalyzer::readBulkSMBv1(const SMBv1::ReadBulkCommand* cmd, const SMBv1::ReadBulkArgumentType*, const SMBv1::ReadBulkResultType*)
{
    stats.account(cmd, SMBv1Commands::READ_BULK);
}

void CIFSBreakdownAnalyzer::writeBulkSMBv1(const SMBv1::WriteBulkCommand* cmd, const SMBv1::WriteBulkArgumentType*, const SMBv1::WriteBulkResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_BULK);
}

void CIFSBreakdownAnalyzer::writeBulkDataSMBv1(const SMBv1::WriteBulkDataCommand* cmd, const SMBv1::WriteBulkDataArgumentType*, const SMBv1::WriteBulkDataResultType*)
{
    stats.account(cmd, SMBv1Commands::WRITE_BULK_DATA);
}

void CIFSBreakdownAnalyzer::invalidSMBv1(const SMBv1::InvalidCommand* cmd, const SMBv1::InvalidArgumentType*, const SMBv1::InvalidResultType*)
{
    stats.account(cmd, SMBv1Commands::INVALID);
}

void CIFSBreakdownAnalyzer::noAndxCommandSMBv1(const SMBv1::NoAndxCommand* cmd, const SMBv1::NoAndxCmdArgumentType*, const SMBv1::NoAndxCmdResultType*)
{
    stats.account(cmd, SMBv1Commands::NO_ANDX_COMMAND);
}

void CIFSBreakdownAnalyzer::flush_statistics()
{
    representer.flush_statistics(stats);
}
//------------------------------------------------------------------------------
