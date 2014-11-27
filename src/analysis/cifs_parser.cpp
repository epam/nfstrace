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
    if (const CIFS::MessageHeader* header = CIFS::get_header(data->data))
    {
        using namespace NST::API;

        switch (header->cmd_code)
        {
        case CIFS::Commands::SMB_COM_CREATE_DIRECTORY       :          return analyzers(&IAnalyzer::ISMBv1::createDirectorySMBv1      ,CIFS::command<SMBv1::CreateDirectoryCommand>(header));
        case CIFS::Commands::SMB_COM_DELETE_DIRECTORY       :          return analyzers(&IAnalyzer::ISMBv1::deleteDirectorySMBv1      ,CIFS::command<SMBv1::DeleteDirectoryCommand>(header));
        case CIFS::Commands::SMB_COM_OPEN                   :          return analyzers(&IAnalyzer::ISMBv1::openSMBv1                 ,CIFS::command<SMBv1::OpenCommand>(header));
        case CIFS::Commands::SMB_COM_CREATE                 :          return analyzers(&IAnalyzer::ISMBv1::createSMBv1               ,CIFS::command<SMBv1::CreateCommand>(header));
        case CIFS::Commands::SMB_COM_CLOSE                  :          return analyzers(&IAnalyzer::ISMBv1::closeSMBv1                ,CIFS::command<SMBv1::CloseCommand>(header));
        case CIFS::Commands::SMB_COM_FLUSH                  :          return analyzers(&IAnalyzer::ISMBv1::flushSMBv1                ,CIFS::command<SMBv1::FlushCommand>(header));
        case CIFS::Commands::SMB_COM_DELETE                 :          return analyzers(&IAnalyzer::ISMBv1::deleteSMBv1               ,CIFS::command<SMBv1::DeleteCommand>(header));
        case CIFS::Commands::SMB_COM_RENAME                 :          return analyzers(&IAnalyzer::ISMBv1::renameSMBv1               ,CIFS::command<SMBv1::RenameCommand>(header));
        case CIFS::Commands::SMB_COM_QUERY_INFORMATION      :          return analyzers(&IAnalyzer::ISMBv1::queryInfoSMBv1            ,CIFS::command<SMBv1::QueryInformationCommand>(header));
        case CIFS::Commands::SMB_COM_SET_INFORMATION        :          return analyzers(&IAnalyzer::ISMBv1::setInfoSMBv1              ,CIFS::command<SMBv1::SetInformationCommand>(header));
        case CIFS::Commands::SMB_COM_READ                   :          return analyzers(&IAnalyzer::ISMBv1::readSMBv1                 ,CIFS::command<SMBv1::ReadCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE                  :          return analyzers(&IAnalyzer::ISMBv1::writeSMBv1                ,CIFS::command<SMBv1::WriteCommand>(header));
        case CIFS::Commands::SMB_COM_LOCK_BYTE_RANGE        :          return analyzers(&IAnalyzer::ISMBv1::lockByteRangeSMBv1        ,CIFS::command<SMBv1::LockByteRangeCommand>(header));
        case CIFS::Commands::SMB_COM_UNLOCK_BYTE_RANGE      :          return analyzers(&IAnalyzer::ISMBv1::unlockByteRangeSMBv1      ,CIFS::command<SMBv1::UnlockByteRangeCommand>(header));
        case CIFS::Commands::SMB_COM_CREATE_TEMPORARY       :          return analyzers(&IAnalyzer::ISMBv1::createTmpSMBv1            ,CIFS::command<SMBv1::CreateTemporaryCommand>(header));
        case CIFS::Commands::SMB_COM_CREATE_NEW             :          return analyzers(&IAnalyzer::ISMBv1::createNewSMBv1            ,CIFS::command<SMBv1::CreateNewCommand>(header));
        case CIFS::Commands::SMB_COM_CHECK_DIRECTORY        :          return analyzers(&IAnalyzer::ISMBv1::checkDirectorySMBv1       ,CIFS::command<SMBv1::CheckDirectoryCommand>(header));
        case CIFS::Commands::SMB_COM_PROCESS_EXIT           :          return analyzers(&IAnalyzer::ISMBv1::processExitSMBv1          ,CIFS::command<SMBv1::ProcessExitCommand>(header));
        case CIFS::Commands::SMB_COM_SEEK                   :          return analyzers(&IAnalyzer::ISMBv1::seekSMBv1                 ,CIFS::command<SMBv1::SeekCommand>(header));
        case CIFS::Commands::SMB_COM_LOCK_AND_READ          :          return analyzers(&IAnalyzer::ISMBv1::lockAndReadSMBv1          ,CIFS::command<SMBv1::LockAndReadCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_AND_UNLOCK       :          return analyzers(&IAnalyzer::ISMBv1::writeAndUnlockSMBv1       ,CIFS::command<SMBv1::WriteAndUnlockCommand>(header));
        case CIFS::Commands::SMB_COM_READ_RAW               :          return analyzers(&IAnalyzer::ISMBv1::readRawSMBv1              ,CIFS::command<SMBv1::ReadRawCommand>(header));
        case CIFS::Commands::SMB_COM_READ_MPX               :          return analyzers(&IAnalyzer::ISMBv1::readMpxSMBv1              ,CIFS::command<SMBv1::ReadMpxCommand>(header));
        case CIFS::Commands::SMB_COM_READ_MPX_SECONDARY     :          return analyzers(&IAnalyzer::ISMBv1::readMpxSecondarySMBv1     ,CIFS::command<SMBv1::ReadMpxSecondaryCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_RAW              :          return analyzers(&IAnalyzer::ISMBv1::writeRawSMBv1             ,CIFS::command<SMBv1::WriteRawCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_MPX              :          return analyzers(&IAnalyzer::ISMBv1::writeMpxSMBv1             ,CIFS::command<SMBv1::WriteMpxCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_MPX_SECONDARY    :          return analyzers(&IAnalyzer::ISMBv1::writeMpxSecondarySMBv1    ,CIFS::command<SMBv1::WriteMpxSecondaryCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_COMPLETE         :          return analyzers(&IAnalyzer::ISMBv1::writeCompleteSMBv1        ,CIFS::command<SMBv1::WriteCompleteCommand>(header));
        case CIFS::Commands::SMB_COM_QUERY_SERVER           :          return analyzers(&IAnalyzer::ISMBv1::queryServerSMBv1          ,CIFS::command<SMBv1::QueryServerCommand>(header));
        case CIFS::Commands::SMB_COM_SET_INFORMATION2       :          return analyzers(&IAnalyzer::ISMBv1::setInfo2SMBv1             ,CIFS::command<SMBv1::SetInformation2Command>(header));
        case CIFS::Commands::SMB_COM_QUERY_INFORMATION2     :          return analyzers(&IAnalyzer::ISMBv1::queryInfo2SMBv1           ,CIFS::command<SMBv1::QueryInformation2Command>(header));
        case CIFS::Commands::SMB_COM_LOCKING_ANDX           :          return analyzers(&IAnalyzer::ISMBv1::lockingAndxSMBv1          ,CIFS::command<SMBv1::LockingAndxCommand>(header));
        case CIFS::Commands::SMB_COM_TRANSACTION            :          return analyzers(&IAnalyzer::ISMBv1::transactionSMBv1          ,CIFS::command<SMBv1::TransactionCommand>(header));
        case CIFS::Commands::SMB_COM_TRANSACTION_SECONDARY  :          return analyzers(&IAnalyzer::ISMBv1::transactionSecondarySMBv1 ,CIFS::command<SMBv1::TransactionSecondaryCommand>(header));
        case CIFS::Commands::SMB_COM_IOCTL                  :          return analyzers(&IAnalyzer::ISMBv1::ioctlSMBv1                ,CIFS::command<SMBv1::IoctlCommand>(header));
        case CIFS::Commands::SMB_COM_IOCTL_SECONDARY        :          return analyzers(&IAnalyzer::ISMBv1::ioctlSecondarySMBv1       ,CIFS::command<SMBv1::IoctlSecondaryCommand>(header));
        case CIFS::Commands::SMB_COM_COPY                   :          return analyzers(&IAnalyzer::ISMBv1::copySMBv1                 ,CIFS::command<SMBv1::CopyCommand>(header));
        case CIFS::Commands::SMB_COM_MOVE                   :          return analyzers(&IAnalyzer::ISMBv1::moveSMBv1                 ,CIFS::command<SMBv1::MoveCommand>(header));
        case CIFS::Commands::SMB_COM_ECHO                   :          return analyzers(&IAnalyzer::ISMBv1::echoSMBv1                 ,CIFS::command<SMBv1::EchoCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_AND_CLOSE        :          return analyzers(&IAnalyzer::ISMBv1::writeAndCloseSMBv1        ,CIFS::command<SMBv1::WriteAndCloseCommand>(header));
        case CIFS::Commands::SMB_COM_OPEN_ANDX              :          return analyzers(&IAnalyzer::ISMBv1::openAndxSMBv1             ,CIFS::command<SMBv1::OpenAndxCommand>(header));
        case CIFS::Commands::SMB_COM_READ_ANDX              :          return analyzers(&IAnalyzer::ISMBv1::readAndxSMBv1             ,CIFS::command<SMBv1::ReadAndxCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_ANDX             :          return analyzers(&IAnalyzer::ISMBv1::writeAndxSMBv1            ,CIFS::command<SMBv1::WriteAndxCommand>(header));
        case CIFS::Commands::SMB_COM_NEW_FILE_SIZE          :          return analyzers(&IAnalyzer::ISMBv1::newFileSizeSMBv1          ,CIFS::command<SMBv1::NewFileSizeCommand>(header));
        case CIFS::Commands::SMB_COM_CLOSE_AND_TREE_DISC    :          return analyzers(&IAnalyzer::ISMBv1::closeAndTreeDiscSMBv1     ,CIFS::command<SMBv1::CloseAndTreeDiscCommand>(header));
        case CIFS::Commands::SMB_COM_TRANSACTION2           :          return analyzers(&IAnalyzer::ISMBv1::transaction2SMBv1         ,CIFS::command<SMBv1::Transaction2Command>(header));
        case CIFS::Commands::SMB_COM_TRANSACTION2_SECONDARY :          return analyzers(&IAnalyzer::ISMBv1::transaction2SecondarySMBv1,CIFS::command<SMBv1::Transaction2SecondaryCommand>(header));
        case CIFS::Commands::SMB_COM_FIND_CLOSE2            :          return analyzers(&IAnalyzer::ISMBv1::findClose2SMBv1           ,CIFS::command<SMBv1::FindClose2Command>(header));
        case CIFS::Commands::SMB_COM_FIND_NOTIFY_CLOSE      :          return analyzers(&IAnalyzer::ISMBv1::findNotifyCloseSMBv1      ,CIFS::command<SMBv1::FindNotifyCloseCommand>(header));
        case CIFS::Commands::SMB_COM_TREE_CONNECT           :          return analyzers(&IAnalyzer::ISMBv1::treeConnectSMBv1          ,CIFS::command<SMBv1::TreeConnectCommand>(header));
        case CIFS::Commands::SMB_COM_TREE_DISCONNECT        :          return analyzers(&IAnalyzer::ISMBv1::treeDisconnectSMBv1       ,CIFS::command<SMBv1::TreeDisconnectCommand>(header));
        case CIFS::Commands::SMB_COM_NEGOTIATE              :          return analyzers(&IAnalyzer::ISMBv1::negotiateSMBv1            ,CIFS::command<SMBv1::NegotiateCommand>(header));
        case CIFS::Commands::SMB_COM_SESSION_SETUP_ANDX     :          return analyzers(&IAnalyzer::ISMBv1::sessionSetupAndxSMBv1     ,CIFS::command<SMBv1::SessionSetupAndxCommand>(header));
        case CIFS::Commands::SMB_COM_LOGOFF_ANDX            :          return analyzers(&IAnalyzer::ISMBv1::logoffAndxSMBv1           ,CIFS::command<SMBv1::LogoffAndxCommand>(header));
        case CIFS::Commands::SMB_COM_TREE_CONNECT_ANDX      :          return analyzers(&IAnalyzer::ISMBv1::treeConnectAndxSMBv1      ,CIFS::command<SMBv1::TreeConnectAndxCommand>(header));
        case CIFS::Commands::SMB_COM_SECURITY_PACKAGE_ANDX  :          return analyzers(&IAnalyzer::ISMBv1::securityPackageAndxSMBv1  ,CIFS::command<SMBv1::SecurityPackageAndxCommand>(header));
        case CIFS::Commands::SMB_COM_QUERY_INFORMATION_DISK :          return analyzers(&IAnalyzer::ISMBv1::queryInformationDiskSMBv1 ,CIFS::command<SMBv1::QueryInformationDiskCommand>(header));
        case CIFS::Commands::SMB_COM_SEARCH                 :          return analyzers(&IAnalyzer::ISMBv1::searchSMBv1               ,CIFS::command<SMBv1::SearchCommand>(header));
        case CIFS::Commands::SMB_COM_FIND                   :          return analyzers(&IAnalyzer::ISMBv1::findSMBv1                 ,CIFS::command<SMBv1::FindCommand>(header));
        case CIFS::Commands::SMB_COM_FIND_UNIQUE            :          return analyzers(&IAnalyzer::ISMBv1::findUniqueSMBv1           ,CIFS::command<SMBv1::FindUniqueCommand>(header));
        case CIFS::Commands::SMB_COM_FIND_CLOSE             :          return analyzers(&IAnalyzer::ISMBv1::findCloseSMBv1            ,CIFS::command<SMBv1::FindCloseCommand>(header));
        case CIFS::Commands::SMB_COM_NT_TRANSACT            :          return analyzers(&IAnalyzer::ISMBv1::ntTransactSMBv1           ,CIFS::command<SMBv1::NtTransactCommand>(header));
        case CIFS::Commands::SMB_COM_NT_TRANSACT_SECONDARY  :          return analyzers(&IAnalyzer::ISMBv1::ntTransactSecondarySMBv1  ,CIFS::command<SMBv1::NtTransactSecondaryCommand>(header));
        case CIFS::Commands::SMB_COM_NT_CREATE_ANDX         :          return analyzers(&IAnalyzer::ISMBv1::ntCreateAndxSMBv1         ,CIFS::command<SMBv1::NtCreateAndxCommand>(header));
        case CIFS::Commands::SMB_COM_NT_CANCEL              :          return analyzers(&IAnalyzer::ISMBv1::ntCancelSMBv1             ,CIFS::command<SMBv1::NtCancelCommand>(header));
        case CIFS::Commands::SMB_COM_NT_RENAME              :          return analyzers(&IAnalyzer::ISMBv1::ntRenameSMBv1             ,CIFS::command<SMBv1::NtRenameCommand>(header));
        case CIFS::Commands::SMB_COM_OPEN_PRINT_FILE        :          return analyzers(&IAnalyzer::ISMBv1::openPrintFileSMBv1        ,CIFS::command<SMBv1::OpenPrintFileCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_PRINT_FILE       :          return analyzers(&IAnalyzer::ISMBv1::writePrintFileSMBv1       ,CIFS::command<SMBv1::WritePrintFileCommand>(header));
        case CIFS::Commands::SMB_COM_CLOSE_PRINT_FILE       :          return analyzers(&IAnalyzer::ISMBv1::closePrintFileSMBv1       ,CIFS::command<SMBv1::ClosePrintFileCommand>(header));
        case CIFS::Commands::SMB_COM_GET_PRINT_QUEUE        :          return analyzers(&IAnalyzer::ISMBv1::getPrintQueueSMBv1        ,CIFS::command<SMBv1::GetPrintQueueCommand>(header));
        case CIFS::Commands::SMB_COM_READ_BULK              :          return analyzers(&IAnalyzer::ISMBv1::readBulkSMBv1             ,CIFS::command<SMBv1::ReadBulkCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_BULK             :          return analyzers(&IAnalyzer::ISMBv1::writeBulkSMBv1            ,CIFS::command<SMBv1::WriteBulkCommand>(header));
        case CIFS::Commands::SMB_COM_WRITE_BULK_DATA        :          return analyzers(&IAnalyzer::ISMBv1::writeBulkDataSMBv1        ,CIFS::command<SMBv1::WriteBulkDataCommand>(header));
        case CIFS::Commands::SMB_COM_INVALID                :          return analyzers(&IAnalyzer::ISMBv1::invalidSMBv1              ,CIFS::command<SMBv1::InvalidCommand>(header));
        case CIFS::Commands::SMB_COM_NO_ANDX_COMMAND        :          return analyzers(&IAnalyzer::ISMBv1::noAndxCommandSMBv1        ,CIFS::command<SMBv1::NoAndxCommand>(header));
        default:
            break;
        }
    }
    else if (const CIFSv2::MessageHeader* header = CIFSv2::get_header(data->data))
    {
        using namespace NST::API;

        switch (header->cmd_code)
        {
        case CIFSv2::Commands::CLOSE:               return analyzers(&IAnalyzer::ISMBv2::closeFileSMBv2,        CIFSv2::command<SMBv2::CloseFileCommand>(header));
        case CIFSv2::Commands::NEGOTIATE:           return analyzers(&IAnalyzer::ISMBv2::negotiateSMBv2,        CIFSv2::command<SMBv2::NegotiateCommand>(header));
        case CIFSv2::Commands::SESSION_SETUP:       return analyzers(&IAnalyzer::ISMBv2::sessionSetupSMBv2,     CIFSv2::command<SMBv2::SessionSetupCommand>(header));
        case CIFSv2::Commands::LOGOFF:              return analyzers(&IAnalyzer::ISMBv2::logOffSMBv2,           CIFSv2::command<SMBv2::LogOffCommand>(header));
        case CIFSv2::Commands::TREE_CONNECT:        return analyzers(&IAnalyzer::ISMBv2::treeConnectSMBv2,      CIFSv2::command<SMBv2::TreeConnectCommand>(header));
        case CIFSv2::Commands::TREE_DISCONNECT:     return analyzers(&IAnalyzer::ISMBv2::treeDisconnectSMBv2,   CIFSv2::command<SMBv2::TreeDisconnectCommand>(header));
        case CIFSv2::Commands::CREATE:              return analyzers(&IAnalyzer::ISMBv2::createSMBv2,           CIFSv2::command<SMBv2::CreateCommand>(header));
        case CIFSv2::Commands::FLUSH:               return analyzers(&IAnalyzer::ISMBv2::flushSMBv2,            CIFSv2::command<SMBv2::FlushCommand>(header));
        case CIFSv2::Commands::READ:                return analyzers(&IAnalyzer::ISMBv2::readSMBv2,             CIFSv2::command<SMBv2::ReadCommand>(header));
        case CIFSv2::Commands::WRITE:               return analyzers(&IAnalyzer::ISMBv2::writeSMBv2,            CIFSv2::command<SMBv2::WriteCommand>(header));
        case CIFSv2::Commands::LOCK:                return analyzers(&IAnalyzer::ISMBv2::lockSMBv2,             CIFSv2::command<SMBv2::LockCommand>(header));
        case CIFSv2::Commands::IOCTL:               return analyzers(&IAnalyzer::ISMBv2::ioctlSMBv2,            CIFSv2::command<SMBv2::IoctlCommand>(header));
        case CIFSv2::Commands::CANCEL:              return analyzers(&IAnalyzer::ISMBv2::cancelSMBv2,           CIFSv2::command<SMBv2::CancelCommand>(header));
        case CIFSv2::Commands::ECHO:                return analyzers(&IAnalyzer::ISMBv2::echoSMBv2,             CIFSv2::command<SMBv2::EchoCommand>(header));
        case CIFSv2::Commands::QUERY_DIRECTORY:     return analyzers(&IAnalyzer::ISMBv2::queryDirSMBv2,         CIFSv2::command<SMBv2::QueryDirCommand>(header));
        case CIFSv2::Commands::CHANGE_NOTIFY:       return analyzers(&IAnalyzer::ISMBv2::changeNotifySMBv2,     CIFSv2::command<SMBv2::ChangeNotifyCommand>(header));
        case CIFSv2::Commands::QUERY_INFO:          return analyzers(&IAnalyzer::ISMBv2::queryInfoSMBv2,        CIFSv2::command<SMBv2::QueryInfoCommand>(header));
        case CIFSv2::Commands::SET_INFO:            return analyzers(&IAnalyzer::ISMBv2::setInfoSMBv2,          CIFSv2::command<SMBv2::SetInfoCommand>(header));
        case CIFSv2::Commands::OPLOCK_BREAK:        return analyzers(&IAnalyzer::ISMBv2::breakOplockSMBv2,      CIFSv2::command<SMBv2::BreakOpLockCommand>(header));
        default:
            break;
        }
    }
    else
    {
        std::cout << "Got BAD message!" << std::endl;
    }
}
