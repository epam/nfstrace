//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Parser of filtrated CIFS Procedures.
// Copyright (c) 2014 EPAM Systems
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

#include "analysis/cifs_parser.h"
#include "api/cifs_types.h"
#include "protocols/cifs/cifs.h"
#include "protocols/cifs2/cifs2.h"
//------------------------------------------------------------------------------
using namespace NST::protocols;
using namespace NST::analysis;

CIFSParser::CIFSParser(Analyzers& a) :
    analyzers(a)
{
}

void CIFSParser::parse_data(NST::utils::FilteredDataQueue::Ptr&& data)
{
    //FIXME: code smells
    if (const CIFSv1::MessageHeader* header = CIFSv1::get_header(data->data))
    {
        using namespace NST::API::SMBv1;
        using namespace NST::protocols::CIFSv1;

        switch (header->cmd_code)
        {
        case Commands::CREATE_DIRECTORY:       return analyzers(&IAnalyzer::ISMBv1::createDirectorySMBv1,      command<CreateDirectoryCommand>(header));
        case Commands::DELETE_DIRECTORY:       return analyzers(&IAnalyzer::ISMBv1::deleteDirectorySMBv1,      command<DeleteDirectoryCommand>(header));
        case Commands::OPEN:                   return analyzers(&IAnalyzer::ISMBv1::openSMBv1,                 command<OpenCommand>(header));
        case Commands::CREATE:                 return analyzers(&IAnalyzer::ISMBv1::createSMBv1,               command<CreateCommand>(header));
        case Commands::CLOSE:                  return analyzers(&IAnalyzer::ISMBv1::closeSMBv1,                command<CloseCommand>(header));
        case Commands::FLUSH:                  return analyzers(&IAnalyzer::ISMBv1::flushSMBv1,                command<FlushCommand>(header));
        case Commands::DELETE:                 return analyzers(&IAnalyzer::ISMBv1::deleteSMBv1,               command<DeleteCommand>(header));
        case Commands::RENAME:                 return analyzers(&IAnalyzer::ISMBv1::renameSMBv1,               command<RenameCommand>(header));
        case Commands::QUERY_INFORMATION:      return analyzers(&IAnalyzer::ISMBv1::queryInfoSMBv1,            command<QueryInformationCommand>(header));
        case Commands::SET_INFORMATION:        return analyzers(&IAnalyzer::ISMBv1::setInfoSMBv1,              command<SetInformationCommand>(header));
        case Commands::READ:                   return analyzers(&IAnalyzer::ISMBv1::readSMBv1,                 command<ReadCommand>(header));
        case Commands::WRITE:                  return analyzers(&IAnalyzer::ISMBv1::writeSMBv1,                command<WriteCommand>(header));
        case Commands::LOCK_BYTE_RANGE:        return analyzers(&IAnalyzer::ISMBv1::lockByteRangeSMBv1,        command<LockByteRangeCommand>(header));
        case Commands::UNLOCK_BYTE_RANGE:      return analyzers(&IAnalyzer::ISMBv1::unlockByteRangeSMBv1,      command<UnlockByteRangeCommand>(header));
        case Commands::CREATE_TEMPORARY:       return analyzers(&IAnalyzer::ISMBv1::createTmpSMBv1,            command<CreateTemporaryCommand>(header));
        case Commands::CREATE_NEW:             return analyzers(&IAnalyzer::ISMBv1::createNewSMBv1,            command<CreateNewCommand>(header));
        case Commands::CHECK_DIRECTORY:        return analyzers(&IAnalyzer::ISMBv1::checkDirectorySMBv1,       command<CheckDirectoryCommand>(header));
        case Commands::PROCESS_EXIT:           return analyzers(&IAnalyzer::ISMBv1::processExitSMBv1,          command<ProcessExitCommand>(header));
        case Commands::SEEK:                   return analyzers(&IAnalyzer::ISMBv1::seekSMBv1,                 command<SeekCommand>(header));
        case Commands::LOCK_AND_READ:          return analyzers(&IAnalyzer::ISMBv1::lockAndReadSMBv1,          command<LockAndReadCommand>(header));
        case Commands::WRITE_AND_UNLOCK:       return analyzers(&IAnalyzer::ISMBv1::writeAndUnlockSMBv1,       command<WriteAndUnlockCommand>(header));
        case Commands::READ_RAW:               return analyzers(&IAnalyzer::ISMBv1::readRawSMBv1,              command<ReadRawCommand>(header));
        case Commands::READ_MPX:               return analyzers(&IAnalyzer::ISMBv1::readMpxSMBv1,              command<ReadMpxCommand>(header));
        case Commands::READ_MPX_SECONDARY:     return analyzers(&IAnalyzer::ISMBv1::readMpxSecondarySMBv1,     command<ReadMpxSecondaryCommand>(header));
        case Commands::WRITE_RAW:              return analyzers(&IAnalyzer::ISMBv1::writeRawSMBv1,             command<WriteRawCommand>(header));
        case Commands::WRITE_MPX:              return analyzers(&IAnalyzer::ISMBv1::writeMpxSMBv1,             command<WriteMpxCommand>(header));
        case Commands::WRITE_MPX_SECONDARY:    return analyzers(&IAnalyzer::ISMBv1::writeMpxSecondarySMBv1,    command<WriteMpxSecondaryCommand>(header));
        case Commands::WRITE_COMPLETE:         return analyzers(&IAnalyzer::ISMBv1::writeCompleteSMBv1,        command<WriteCompleteCommand>(header));
        case Commands::QUERY_SERVER:           return analyzers(&IAnalyzer::ISMBv1::queryServerSMBv1,          command<QueryServerCommand>(header));
        case Commands::SET_INFORMATION2:       return analyzers(&IAnalyzer::ISMBv1::setInfo2SMBv1,             command<SetInformation2Command>(header));
        case Commands::QUERY_INFORMATION2:     return analyzers(&IAnalyzer::ISMBv1::queryInfo2SMBv1,           command<QueryInformation2Command>(header));
        case Commands::LOCKING_ANDX:           return analyzers(&IAnalyzer::ISMBv1::lockingAndxSMBv1,          command<LockingAndxCommand>(header));
        case Commands::TRANSACTION:            return analyzers(&IAnalyzer::ISMBv1::transactionSMBv1,          command<TransactionCommand>(header));
        case Commands::TRANSACTION_SECONDARY:  return analyzers(&IAnalyzer::ISMBv1::transactionSecondarySMBv1, command<TransactionSecondaryCommand>(header));
        case Commands::IOCTL:                  return analyzers(&IAnalyzer::ISMBv1::ioctlSMBv1,                command<IoctlCommand>(header));
        case Commands::IOCTL_SECONDARY:        return analyzers(&IAnalyzer::ISMBv1::ioctlSecondarySMBv1,       command<IoctlSecondaryCommand>(header));
        case Commands::COPY:                   return analyzers(&IAnalyzer::ISMBv1::copySMBv1,                 command<CopyCommand>(header));
        case Commands::MOVE:                   return analyzers(&IAnalyzer::ISMBv1::moveSMBv1,                 command<MoveCommand>(header));
        case Commands::ECHO:                   return analyzers(&IAnalyzer::ISMBv1::echoSMBv1,                 command<EchoCommand>(header));
        case Commands::WRITE_AND_CLOSE:        return analyzers(&IAnalyzer::ISMBv1::writeAndCloseSMBv1,        command<WriteAndCloseCommand>(header));
        case Commands::OPEN_ANDX:              return analyzers(&IAnalyzer::ISMBv1::openAndxSMBv1,             command<OpenAndxCommand>(header));
        case Commands::READ_ANDX:              return analyzers(&IAnalyzer::ISMBv1::readAndxSMBv1,             command<ReadAndxCommand>(header));
        case Commands::WRITE_ANDX:             return analyzers(&IAnalyzer::ISMBv1::writeAndxSMBv1,            command<WriteAndxCommand>(header));
        case Commands::NEW_FILE_SIZE:          return analyzers(&IAnalyzer::ISMBv1::newFileSizeSMBv1,          command<NewFileSizeCommand>(header));
        case Commands::CLOSE_AND_TREE_DISC:    return analyzers(&IAnalyzer::ISMBv1::closeAndTreeDiscSMBv1,     command<CloseAndTreeDiscCommand>(header));
        case Commands::TRANSACTION2:           return analyzers(&IAnalyzer::ISMBv1::transaction2SMBv1,         command<Transaction2Command>(header));
        case Commands::TRANSACTION2_SECONDARY: return analyzers(&IAnalyzer::ISMBv1::transaction2SecondarySMBv1,command<Transaction2SecondaryCommand>(header));
        case Commands::FIND_CLOSE2:            return analyzers(&IAnalyzer::ISMBv1::findClose2SMBv1,           command<FindClose2Command>(header));
        case Commands::FIND_NOTIFY_CLOSE:      return analyzers(&IAnalyzer::ISMBv1::findNotifyCloseSMBv1,      command<FindNotifyCloseCommand>(header));
        case Commands::TREE_CONNECT:           return analyzers(&IAnalyzer::ISMBv1::treeConnectSMBv1,          command<TreeConnectCommand>(header));
        case Commands::TREE_DISCONNECT:        return analyzers(&IAnalyzer::ISMBv1::treeDisconnectSMBv1,       command<TreeDisconnectCommand>(header));
        case Commands::NEGOTIATE:              return analyzers(&IAnalyzer::ISMBv1::negotiateSMBv1,            command<NegotiateCommand>(header));
        case Commands::SESSION_SETUP_ANDX:     return analyzers(&IAnalyzer::ISMBv1::sessionSetupAndxSMBv1,     command<SessionSetupAndxCommand>(header));
        case Commands::LOGOFF_ANDX:            return analyzers(&IAnalyzer::ISMBv1::logoffAndxSMBv1,           command<LogoffAndxCommand>(header));
        case Commands::TREE_CONNECT_ANDX:      return analyzers(&IAnalyzer::ISMBv1::treeConnectAndxSMBv1,      command<TreeConnectAndxCommand>(header));
        case Commands::SECURITY_PACKAGE_ANDX:  return analyzers(&IAnalyzer::ISMBv1::securityPackageAndxSMBv1,  command<SecurityPackageAndxCommand>(header));
        case Commands::QUERY_INFORMATION_DISK: return analyzers(&IAnalyzer::ISMBv1::queryInformationDiskSMBv1, command<QueryInformationDiskCommand>(header));
        case Commands::SEARCH:                 return analyzers(&IAnalyzer::ISMBv1::searchSMBv1,               command<SearchCommand>(header));
        case Commands::FIND:                   return analyzers(&IAnalyzer::ISMBv1::findSMBv1,                 command<FindCommand>(header));
        case Commands::FIND_UNIQUE:            return analyzers(&IAnalyzer::ISMBv1::findUniqueSMBv1,           command<FindUniqueCommand>(header));
        case Commands::FIND_CLOSE:             return analyzers(&IAnalyzer::ISMBv1::findCloseSMBv1,            command<FindCloseCommand>(header));
        case Commands::NT_TRANSACT:            return analyzers(&IAnalyzer::ISMBv1::ntTransactSMBv1,           command<NtTransactCommand>(header));
        case Commands::NT_TRANSACT_SECONDARY:  return analyzers(&IAnalyzer::ISMBv1::ntTransactSecondarySMBv1,  command<NtTransactSecondaryCommand>(header));
        case Commands::NT_CREATE_ANDX:         return analyzers(&IAnalyzer::ISMBv1::ntCreateAndxSMBv1,         command<NtCreateAndxCommand>(header));
        case Commands::NT_CANCEL:              return analyzers(&IAnalyzer::ISMBv1::ntCancelSMBv1,             command<NtCancelCommand>(header));
        case Commands::NT_RENAME:              return analyzers(&IAnalyzer::ISMBv1::ntRenameSMBv1,             command<NtRenameCommand>(header));
        case Commands::OPEN_PRINT_FILE:        return analyzers(&IAnalyzer::ISMBv1::openPrintFileSMBv1,        command<OpenPrintFileCommand>(header));
        case Commands::WRITE_PRINT_FILE:       return analyzers(&IAnalyzer::ISMBv1::writePrintFileSMBv1,       command<WritePrintFileCommand>(header));
        case Commands::CLOSE_PRINT_FILE:       return analyzers(&IAnalyzer::ISMBv1::closePrintFileSMBv1,       command<ClosePrintFileCommand>(header));
        case Commands::GET_PRINT_QUEUE:        return analyzers(&IAnalyzer::ISMBv1::getPrintQueueSMBv1,        command<GetPrintQueueCommand>(header));
        case Commands::READ_BULK:              return analyzers(&IAnalyzer::ISMBv1::readBulkSMBv1,             command<ReadBulkCommand>(header));
        case Commands::WRITE_BULK:             return analyzers(&IAnalyzer::ISMBv1::writeBulkSMBv1,            command<WriteBulkCommand>(header));
        case Commands::WRITE_BULK_DATA:        return analyzers(&IAnalyzer::ISMBv1::writeBulkDataSMBv1,        command<WriteBulkDataCommand>(header));
        case Commands::INVALID:                return analyzers(&IAnalyzer::ISMBv1::invalidSMBv1,              command<InvalidCommand>(header));
        case Commands::NO_ANDX_COMMAND:        return analyzers(&IAnalyzer::ISMBv1::noAndxCommandSMBv1,        command<NoAndxCommand>(header));
        default:
            break;
        }
    }
    else if (const CIFSv2::MessageHeader* header = CIFSv2::get_header(data->data))
    {
        using namespace NST::API::SMBv2;
        using namespace NST::protocols::CIFSv2;

        switch (header->cmd_code)
        {
        case Commands::CLOSE:                  return analyzers(&IAnalyzer::ISMBv2::closeFileSMBv2,            command<CloseFileCommand>(header));
        case Commands::NEGOTIATE:              return analyzers(&IAnalyzer::ISMBv2::negotiateSMBv2,            command<NegotiateCommand>(header));
        case Commands::SESSION_SETUP:          return analyzers(&IAnalyzer::ISMBv2::sessionSetupSMBv2,         command<SessionSetupCommand>(header));
        case Commands::LOGOFF:                 return analyzers(&IAnalyzer::ISMBv2::logOffSMBv2,               command<LogOffCommand>(header));
        case Commands::TREE_CONNECT:           return analyzers(&IAnalyzer::ISMBv2::treeConnectSMBv2,          command<TreeConnectCommand>(header));
        case Commands::TREE_DISCONNECT:        return analyzers(&IAnalyzer::ISMBv2::treeDisconnectSMBv2,       command<TreeDisconnectCommand>(header));
        case Commands::CREATE:                 return analyzers(&IAnalyzer::ISMBv2::createSMBv2,               command<CreateCommand>(header));
        case Commands::FLUSH:                  return analyzers(&IAnalyzer::ISMBv2::flushSMBv2,                command<FlushCommand>(header));
        case Commands::READ:                   return analyzers(&IAnalyzer::ISMBv2::readSMBv2,                 command<ReadCommand>(header));
        case Commands::WRITE:                  return analyzers(&IAnalyzer::ISMBv2::writeSMBv2,                command<WriteCommand>(header));
        case Commands::LOCK:                   return analyzers(&IAnalyzer::ISMBv2::lockSMBv2,                 command<LockCommand>(header));
        case Commands::IOCTL:                  return analyzers(&IAnalyzer::ISMBv2::ioctlSMBv2,                command<IoctlCommand>(header));
        case Commands::CANCEL:                 return analyzers(&IAnalyzer::ISMBv2::cancelSMBv2,               command<CancelCommand>(header));
        case Commands::ECHO:                   return analyzers(&IAnalyzer::ISMBv2::echoSMBv2,                 command<EchoCommand>(header));
        case Commands::QUERY_DIRECTORY:        return analyzers(&IAnalyzer::ISMBv2::queryDirSMBv2,             command<QueryDirCommand>(header));
        case Commands::CHANGE_NOTIFY:          return analyzers(&IAnalyzer::ISMBv2::changeNotifySMBv2,         command<ChangeNotifyCommand>(header));
        case Commands::QUERY_INFO:             return analyzers(&IAnalyzer::ISMBv2::queryInfoSMBv2,            command<QueryInfoCommand>(header));
        case Commands::SET_INFO:               return analyzers(&IAnalyzer::ISMBv2::setInfoSMBv2,              command<SetInfoCommand>(header));
        case Commands::OPLOCK_BREAK:           return analyzers(&IAnalyzer::ISMBv2::breakOplockSMBv2,          command<BreakOpLockCommand>(header));
        default:
            break;
        }
    }
    else
    {
        std::cout << "Got BAD message!" << std::endl;
    }
}
