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
    : statistics(SMBv1Commands().commands_count())
    , representer(o, new SMBv1Commands(), space_for_cmd_name)
{
}

void CIFSBreakdownAnalyzer::createDirectorySMBv1(const SMBv1::CreateDirectoryCommand* cmd, const SMBv1::CreateDirectoryArgumentType*, const SMBv1::CreateDirectoryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_CREATE_DIRECTORY);
}

void CIFSBreakdownAnalyzer::deleteDirectorySMBv1(const SMBv1::DeleteDirectoryCommand* cmd, const SMBv1::DeleteDirectoryArgumentType*, const SMBv1::DeleteDirectoryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_DELETE_DIRECTORY);
}

void CIFSBreakdownAnalyzer::openSMBv1(const SMBv1::OpenCommand* cmd, const SMBv1::OpenArgumentType*, const SMBv1::OpenResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_OPEN);
}

void CIFSBreakdownAnalyzer::createSMBv1(const SMBv1::CreateCommand* cmd, const SMBv1::CreateArgumentType*, const SMBv1::CreateResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_CREATE);
}

void CIFSBreakdownAnalyzer::closeSMBv1(const SMBv1::CloseCommand* cmd, const SMBv1::CloseArgumentType*, const SMBv1::CloseResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_CLOSE);
}

void CIFSBreakdownAnalyzer::flushSMBv1(const SMBv1::FlushCommand* cmd, const SMBv1::FlushArgumentType*, const SMBv1::FlushResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_FLUSH);
}

void CIFSBreakdownAnalyzer::deleteSMBv1(const SMBv1::DeleteCommand* cmd, const SMBv1::DeleteArgumentType*, const SMBv1::DeleteResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_DELETE);
}

void CIFSBreakdownAnalyzer::renameSMBv1(const SMBv1::RenameCommand* cmd, const SMBv1::RenameArgumentType*, const SMBv1::RenameResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_RENAME);
}

void CIFSBreakdownAnalyzer::queryInfoSMBv1(const SMBv1::QueryInformationCommand* cmd, const SMBv1::QueryInformationArgumentType*, const SMBv1::QueryInformationResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_QUERY_INFORMATION);
}

void CIFSBreakdownAnalyzer::setInfoSMBv1(const SMBv1::SetInformationCommand* cmd, const SMBv1::SetInformationArgumentType*, const SMBv1::SetInformationResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_SET_INFORMATION);
}

void CIFSBreakdownAnalyzer::readSMBv1(const SMBv1::ReadCommand* cmd, const SMBv1::ReadArgumentType*, const SMBv1::ReadResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_READ);
}

void CIFSBreakdownAnalyzer::writeSMBv1(const SMBv1::WriteCommand* cmd, const SMBv1::WriteArgumentType*, const SMBv1::WriteResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE);
}

void CIFSBreakdownAnalyzer::lockByteRangeSMBv1(const SMBv1::LockByteRangeCommand* cmd, const SMBv1::LockByteRangeArgumentType*, const SMBv1::LockByteRangeResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_LOCK_BYTE_RANGE);
}

void CIFSBreakdownAnalyzer::unlockByteRangeSMBv1(const SMBv1::UnlockByteRangeCommand* cmd, const SMBv1::UnlockByteRangeArgumentType*, const SMBv1::UnlockByteRangeResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_UNLOCK_BYTE_RANGE);
}

void CIFSBreakdownAnalyzer::createTmpSMBv1(const SMBv1::CreateTemporaryCommand* cmd, const SMBv1::CreateTemporaryArgumentType*, const SMBv1::CreateTemporaryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_CREATE_TEMPORARY);
}

void CIFSBreakdownAnalyzer::createNewSMBv1(const SMBv1::CreateNewCommand* cmd, const SMBv1::CreateNewArgumentType*, const SMBv1::CreateNewResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_CREATE_NEW);
}

void CIFSBreakdownAnalyzer::checkDirectorySMBv1(const SMBv1::CheckDirectoryCommand* cmd, const SMBv1::CheckDirectoryArgumentType*, const SMBv1::CheckDirectoryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_CHECK_DIRECTORY);
}

void CIFSBreakdownAnalyzer::processExitSMBv1(const SMBv1::ProcessExitCommand* cmd, const SMBv1::ProcessExitArgumentType*, const SMBv1::ProcessExitResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_PROCESS_EXIT);
}

void CIFSBreakdownAnalyzer::seekSMBv1(const SMBv1::SeekCommand* cmd, const SMBv1::SeekArgumentType*, const SMBv1::SeekResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_SEEK);
}

void CIFSBreakdownAnalyzer::lockAndReadSMBv1(const SMBv1::LockAndReadCommand* cmd, const SMBv1::LockAndReadArgumentType*, const SMBv1::LockAndReadResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_LOCK_AND_READ);
}

void CIFSBreakdownAnalyzer::writeAndUnlockSMBv1(const SMBv1::WriteAndUnlockCommand* cmd, const SMBv1::WriteAndUnlockArgumentType*, const SMBv1::WriteAndUnlockResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_AND_UNLOCK);
}

void CIFSBreakdownAnalyzer::readRawSMBv1(const SMBv1::ReadRawCommand* cmd, const SMBv1::ReadRawArgumentType*, const SMBv1::ReadRawResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_READ_RAW);
}

void CIFSBreakdownAnalyzer::readMpxSMBv1(const SMBv1::ReadMpxCommand* cmd, const SMBv1::ReadMpxArgumentType*, const SMBv1::ReadMpxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_READ_MPX);
}

void CIFSBreakdownAnalyzer::readMpxSecondarySMBv1(const SMBv1::ReadMpxSecondaryCommand* cmd, const SMBv1::ReadMpxSecondaryArgumentType*, const SMBv1::ReadMpxSecondaryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_READ_MPX_SECONDARY);
}

void CIFSBreakdownAnalyzer::writeRawSMBv1(const SMBv1::WriteRawCommand* cmd, const SMBv1::WriteRawArgumentType*, const SMBv1::WriteRawResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_RAW);
}

void CIFSBreakdownAnalyzer::writeMpxSMBv1(const SMBv1::WriteMpxCommand* cmd, const SMBv1::WriteMpxArgumentType*, const SMBv1::WriteMpxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_MPX);
}

void CIFSBreakdownAnalyzer::writeMpxSecondarySMBv1(const SMBv1::WriteMpxSecondaryCommand* cmd, const SMBv1::WriteMpxSecondaryArgumentType*, const SMBv1::WriteMpxSecondaryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_MPX_SECONDARY);
}

void CIFSBreakdownAnalyzer::writeCompleteSMBv1(const SMBv1::WriteCompleteCommand* cmd, const SMBv1::WriteCompleteArgumentType*, const SMBv1::WriteCompleteResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_COMPLETE);
}

void CIFSBreakdownAnalyzer::queryServerSMBv1(const SMBv1::QueryServerCommand* cmd, const SMBv1::QueryServerArgumentType*, const SMBv1::QueryServerResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_QUERY_SERVER);
}

void CIFSBreakdownAnalyzer::setInfo2SMBv1(const SMBv1::SetInformation2Command* cmd, const SMBv1::SetInformation2ArgumentType*, const SMBv1::SetInformation2ResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_SET_INFORMATION2);
}

void CIFSBreakdownAnalyzer::queryInfo2SMBv1(const SMBv1::QueryInformation2Command* cmd, const SMBv1::QueryInformation2ArgumentType*, const SMBv1::QueryInformation2ResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_QUERY_INFORMATION2);
}

void CIFSBreakdownAnalyzer::lockingAndxSMBv1(const SMBv1::LockingAndxCommand* cmd, const SMBv1::LockingAndxArgumentType*, const SMBv1::LockingAndxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_LOCKING_ANDX);
}

void CIFSBreakdownAnalyzer::transactionSMBv1(const SMBv1::TransactionCommand* cmd, const SMBv1::TransactionArgumentType*, const SMBv1::TransactionResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_TRANSACTION);
}

void CIFSBreakdownAnalyzer::transactionSecondarySMBv1(const SMBv1::TransactionSecondaryCommand* cmd, const SMBv1::TransactionSecondaryArgumentType*, const SMBv1::TransactionSecondaryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_TRANSACTION_SECONDARY);
}

void CIFSBreakdownAnalyzer::ioctlSMBv1(const SMBv1::IoctlCommand* cmd, const SMBv1::IoctlArgumentType*, const SMBv1::IoctlResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_IOCTL);
}

void CIFSBreakdownAnalyzer::ioctlSecondarySMBv1(const SMBv1::IoctlSecondaryCommand* cmd, const SMBv1::IoctlSecondaryArgumentType*, const SMBv1::IoctlSecondaryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_IOCTL_SECONDARY);
}

void CIFSBreakdownAnalyzer::copySMBv1(const SMBv1::CopyCommand* cmd, const SMBv1::CopyArgumentType*, const SMBv1::CopyResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_COPY);
}

void CIFSBreakdownAnalyzer::moveSMBv1(const SMBv1::MoveCommand* cmd, const SMBv1::MoveArgumentType*, const SMBv1::MoveResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_MOVE);
}

void CIFSBreakdownAnalyzer::echoSMBv1(const SMBv1::EchoCommand* cmd, const SMBv1::EchoArgumentType*, const SMBv1::EchoResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_ECHO);
}

void CIFSBreakdownAnalyzer::writeAndCloseSMBv1(const SMBv1::WriteAndCloseCommand* cmd, const SMBv1::WriteAndCloseArgumentType*, const SMBv1::WriteAndCloseResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_AND_CLOSE);
}

void CIFSBreakdownAnalyzer::openAndxSMBv1(const SMBv1::OpenAndxCommand* cmd, const SMBv1::OpenAndxArgumentType*, const SMBv1::OpenAndxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_OPEN_ANDX);
}

void CIFSBreakdownAnalyzer::readAndxSMBv1(const SMBv1::ReadAndxCommand* cmd, const SMBv1::ReadAndxArgumentType*, const SMBv1::ReadAndxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_READ_ANDX);
}

void CIFSBreakdownAnalyzer::writeAndxSMBv1(const SMBv1::WriteAndxCommand* cmd, const SMBv1::WriteAndxArgumentType*, const SMBv1::WriteAndxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_ANDX);
}

void CIFSBreakdownAnalyzer::newFileSizeSMBv1(const SMBv1::NewFileSizeCommand* cmd, const SMBv1::NewFileSizeArgumentType*, const SMBv1::NewFileSizeResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_NEW_FILE_SIZE);
}

void CIFSBreakdownAnalyzer::closeAndTreeDiscSMBv1(const SMBv1::CloseAndTreeDiscCommand* cmd, const SMBv1::CloseAndTreeDiscArgumentType*, const SMBv1::CloseAndTreeDiscResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_CLOSE_AND_TREE_DISC);
}

void CIFSBreakdownAnalyzer::transaction2SMBv1(const SMBv1::Transaction2Command* cmd, const SMBv1::Transaction2ArgumentType*, const SMBv1::Transaction2ResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_TRANSACTION2);
}

void CIFSBreakdownAnalyzer::transaction2SecondarySMBv1(const SMBv1::Transaction2SecondaryCommand* cmd, const SMBv1::Transaction2SecondaryArgumentType*, const SMBv1::Transaction2SecondaryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_TRANSACTION2_SECONDARY);
}

void CIFSBreakdownAnalyzer::findClose2SMBv1(const SMBv1::FindClose2Command* cmd, const SMBv1::FindClose2ArgumentType*, const SMBv1::FindClose2ResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_FIND_CLOSE2);
}

void CIFSBreakdownAnalyzer::findNotifyCloseSMBv1(const SMBv1::FindNotifyCloseCommand* cmd, const SMBv1::FindNotifyCloseArgumentType*, const SMBv1::FindNotifyCloseResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_FIND_NOTIFY_CLOSE);
}

void CIFSBreakdownAnalyzer::treeConnectSMBv1(const SMBv1::TreeConnectCommand* cmd, const SMBv1::TreeConnectArgumentType*, const SMBv1::TreeConnectResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_TREE_CONNECT);
}

void CIFSBreakdownAnalyzer::treeDisconnectSMBv1(const SMBv1::TreeDisconnectCommand* cmd, const SMBv1::TreeDisconnectArgumentType*, const SMBv1::TreeDisconnectResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_TREE_DISCONNECT);
}

void CIFSBreakdownAnalyzer::negotiateSMBv1(const SMBv1::NegotiateCommand* cmd, const SMBv1::NegotiateArgumentType*, const SMBv1::NegotiateResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_NEGOTIATE);
}

void CIFSBreakdownAnalyzer::sessionSetupAndxSMBv1(const SMBv1::SessionSetupAndxCommand* cmd, const SMBv1::SessionSetupAndxArgumentType*, const SMBv1::SessionSetupAndxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_SESSION_SETUP_ANDX);
}

void CIFSBreakdownAnalyzer::logoffAndxSMBv1(const SMBv1::LogoffAndxCommand* cmd, const SMBv1::LogoffAndxArgumentType*, const SMBv1::LogoffAndxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_LOGOFF_ANDX);
}

void CIFSBreakdownAnalyzer::treeConnectAndxSMBv1(const SMBv1::TreeConnectAndxCommand* cmd, const SMBv1::TreeConnectAndxArgumentType*, const SMBv1::TreeConnectAndxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_TREE_CONNECT_ANDX);
}

void CIFSBreakdownAnalyzer::securityPackageAndxSMBv1(const SMBv1::SecurityPackageAndxCommand* cmd, const SMBv1::SecurityPackageAndxArgumentType*, const SMBv1::SecurityPackageAndxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_SECURITY_PACKAGE_ANDX);
}

void CIFSBreakdownAnalyzer::queryInformationDiskSMBv1(const SMBv1::QueryInformationDiskCommand* cmd, const SMBv1::QueryInformationDiskArgumentType*, const SMBv1::QueryInformationDiskResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_QUERY_INFORMATION_DISK);
}

void CIFSBreakdownAnalyzer::searchSMBv1(const SMBv1::SearchCommand* cmd, const SMBv1::SearchArgumentType*, const SMBv1::SearchResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_SEARCH);
}

void CIFSBreakdownAnalyzer::findSMBv1(const SMBv1::FindCommand* cmd, const SMBv1::FindArgumentType*, const SMBv1::FindResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_FIND);
}

void CIFSBreakdownAnalyzer::findUniqueSMBv1(const SMBv1::FindUniqueCommand* cmd, const SMBv1::FindUniqueArgumentType*, const SMBv1::FindUniqueResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_FIND_UNIQUE);
}

void CIFSBreakdownAnalyzer::findCloseSMBv1(const SMBv1::FindCloseCommand* cmd, const SMBv1::FindCloseArgumentType*, const SMBv1::FindCloseResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_FIND_CLOSE);
}

void CIFSBreakdownAnalyzer::ntTransactSMBv1(const SMBv1::NtTransactCommand* cmd, const SMBv1::NtTransactArgumentType*, const SMBv1::NtTransactResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_NT_TRANSACT);
}

void CIFSBreakdownAnalyzer::ntTransactSecondarySMBv1(const SMBv1::NtTransactSecondaryCommand* cmd, const SMBv1::NtTransactSecondaryArgumentType*, const SMBv1::NtTransactSecondaryResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_NT_TRANSACT_SECONDARY);
}

void CIFSBreakdownAnalyzer::ntCreateAndxSMBv1(const SMBv1::NtCreateAndxCommand* cmd, const SMBv1::NtCreateAndxArgumentType*, const SMBv1::NtCreateAndxResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_NT_CREATE_ANDX);
}

void CIFSBreakdownAnalyzer::ntCancelSMBv1(const SMBv1::NtCancelCommand* cmd, const SMBv1::NtCancelArgumentType*, const SMBv1::NtCancelResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_NT_CANCEL);
}

void CIFSBreakdownAnalyzer::ntRenameSMBv1(const SMBv1::NtRenameCommand* cmd, const SMBv1::NtRenameArgumentType*, const SMBv1::NtRenameResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_NT_RENAME);
}

void CIFSBreakdownAnalyzer::openPrintFileSMBv1(const SMBv1::OpenPrintFileCommand* cmd, const SMBv1::OpenPrintFileArgumentType*, const SMBv1::OpenPrintFileResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_OPEN_PRINT_FILE);
}

void CIFSBreakdownAnalyzer::writePrintFileSMBv1(const SMBv1::WritePrintFileCommand* cmd, const SMBv1::WritePrintFileArgumentType*, const SMBv1::WritePrintFileResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_PRINT_FILE);
}

void CIFSBreakdownAnalyzer::closePrintFileSMBv1(const SMBv1::ClosePrintFileCommand* cmd, const SMBv1::ClosePrintFileArgumentType*, const SMBv1::ClosePrintFileResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_CLOSE_PRINT_FILE);
}

void CIFSBreakdownAnalyzer::getPrintQueueSMBv1(const SMBv1::GetPrintQueueCommand* cmd, const SMBv1::GetPrintQueueArgumentType*, const SMBv1::GetPrintQueueResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_GET_PRINT_QUEUE);
}

void CIFSBreakdownAnalyzer::readBulkSMBv1(const SMBv1::ReadBulkCommand* cmd, const SMBv1::ReadBulkArgumentType*, const SMBv1::ReadBulkResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_READ_BULK);
}

void CIFSBreakdownAnalyzer::writeBulkSMBv1(const SMBv1::WriteBulkCommand* cmd, const SMBv1::WriteBulkArgumentType*, const SMBv1::WriteBulkResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_BULK);
}

void CIFSBreakdownAnalyzer::writeBulkDataSMBv1(const SMBv1::WriteBulkDataCommand* cmd, const SMBv1::WriteBulkDataArgumentType*, const SMBv1::WriteBulkDataResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_WRITE_BULK_DATA);
}

void CIFSBreakdownAnalyzer::invalidSMBv1(const SMBv1::InvalidCommand* cmd, const SMBv1::InvalidArgumentType*, const SMBv1::InvalidResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_INVALID);
}

void CIFSBreakdownAnalyzer::noAndxCommandSMBv1(const SMBv1::NoAndxCommand* cmd, const SMBv1::NoAndxCmdArgumentType*, const SMBv1::NoAndxCmdResultType*)
{
    statistics.account(cmd, NST::API::SMBv1::SMBv1Commands::SMB_COM_NO_ANDX_COMMAND);
}

void CIFSBreakdownAnalyzer::flush_statistics()
{
    representer.flush_statistics(statistics);
}
//------------------------------------------------------------------------------
