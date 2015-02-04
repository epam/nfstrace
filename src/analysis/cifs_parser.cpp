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
#include "utils/log.h"
//------------------------------------------------------------------------------
using namespace NST::protocols;
using namespace NST::analysis;

CIFSParser::CIFSParser(Analyzers& a) :
    analyzers(a)
{
}

bool CIFSParser::parse_data(FilteredDataQueue::Ptr& data)
{
    if (const CIFSv1::MessageHeader* header = CIFSv1::get_header(data->data))
    {
        parse_packet(header, std::move(data));
        return true;
    }
    else if (const CIFSv2::MessageHeader* header = CIFSv2::get_header(data->data))
    {
        parse_packet(header, std::move(data));
        return true;
    }
    else
    {
        LOG("Got non-CIFS message!");
    }
    return false;
}

void CIFSParser::parse_packet(const CIFSv1::MessageHeader* header, NST::utils::FilteredDataQueue::Ptr&& ptr)
{
    using namespace NST::API::SMBv1;
    using namespace NST::protocols::CIFSv1;

    if (header->isFlag(Flags::REPLY))
    {
        // It is response
        if (Session* session = sessions.get_session(ptr->session, ptr->direction, MsgType::REPLY))
        {
            FilteredDataQueue::Ptr&& requestData = session->get_call_data(header->sec.CID);
            if (requestData)
            {
                if (const MessageHeader* request = get_header(requestData->data))
                {
                    return analyse_operation(session, request, header, std::move(requestData), std::move(ptr));
                }
                LOG("Can't find request for response");
            }
            LOG("Can't find request's raw data for response");
        }
    }
    else
    {
        // It is request
        if (Session* session = sessions.get_session(ptr->session, ptr->direction, MsgType::CALL))
        {
            return session->save_call_data(header->sec.CID, std::move(ptr));
        }
        LOG("Can't get right CIFS session");
    }
}

void CIFSParser::parse_packet(const CIFSv2::MessageHeader* header, utils::FilteredDataQueue::Ptr&& ptr)
{
    using namespace NST::API::SMBv2;
    using namespace NST::protocols::CIFSv2;

    if (header->isFlag(Flags::SERVER_TO_REDIR))
    {
        // It is response
        if (Session* session = sessions.get_session(ptr->session, ptr->direction, MsgType::REPLY))
        {
            FilteredDataQueue::Ptr&& requestData = session->get_call_data(header->SessionId);
            if (requestData)
            {
                if (const MessageHeader* request = get_header(requestData->data))
                {
                    return analyse_operation(session, request, header, std::move(requestData), std::move(ptr));
                }
                LOG("Can't find request for response");
            }
            LOG("Can't find request's raw data for response");
        }
    }
    else
    {
        // It is request
        if (Session* session = sessions.get_session(ptr->session, ptr->direction, MsgType::CALL))
        {
            // It is async request
            if (header->isFlag(Flags::ASYNC_COMMAND))
            {
                return analyse_operation(session, header, nullptr, std::move(ptr), std::move(nullptr));
            }
            return session->save_call_data(header->SessionId, std::move(ptr));
        }
        LOG("Can't get right CIFS session");
    }
}

void CIFSParser::analyse_operation(Session* session,
                                   const CIFSv1::MessageHeader* request,
                                   const CIFSv1::MessageHeader* /*response*/,
                                   NST::utils::FilteredDataQueue::Ptr&& requestData,
                                   NST::utils::FilteredDataQueue::Ptr&& responseData)
{
    using namespace NST::API::SMBv1;
    using namespace NST::protocols::CIFSv1;

    //FIXME: code smells. Too much code
    switch (request->cmd_code)
    {
    case Commands::CREATE_DIRECTORY:
        return analyzers(&IAnalyzer::ISMBv1::createDirectorySMBv1,      command<CreateDirectoryCommand>(requestData, responseData, session));
    case Commands::DELETE_DIRECTORY:
        return analyzers(&IAnalyzer::ISMBv1::deleteDirectorySMBv1,      command<DeleteDirectoryCommand>(requestData, responseData, session));
    case Commands::OPEN:
        return analyzers(&IAnalyzer::ISMBv1::openSMBv1,                 command<OpenCommand>(requestData, responseData, session));
    case Commands::CREATE:
        return analyzers(&IAnalyzer::ISMBv1::createSMBv1,               command<CreateCommand>(requestData, responseData, session));
    case Commands::CLOSE:
        return analyzers(&IAnalyzer::ISMBv1::closeSMBv1,                command<CloseCommand>(requestData, responseData, session));
    case Commands::FLUSH:
        return analyzers(&IAnalyzer::ISMBv1::flushSMBv1,                command<FlushCommand>(requestData, responseData, session));
    case Commands::DELETE:
        return analyzers(&IAnalyzer::ISMBv1::deleteSMBv1,               command<DeleteCommand>(requestData, responseData, session));
    case Commands::RENAME:
        return analyzers(&IAnalyzer::ISMBv1::renameSMBv1,               command<RenameCommand>(requestData, responseData, session));
    case Commands::QUERY_INFORMATION:
        return analyzers(&IAnalyzer::ISMBv1::queryInfoSMBv1,            command<QueryInformationCommand>(requestData, responseData, session));
    case Commands::SET_INFORMATION:
        return analyzers(&IAnalyzer::ISMBv1::setInfoSMBv1,              command<SetInformationCommand>(requestData, responseData, session));
    case Commands::READ:
        return analyzers(&IAnalyzer::ISMBv1::readSMBv1,                 command<ReadCommand>(requestData, responseData, session));
    case Commands::WRITE:
        return analyzers(&IAnalyzer::ISMBv1::writeSMBv1,                command<WriteCommand>(requestData, responseData, session));
    case Commands::LOCK_BYTE_RANGE:
        return analyzers(&IAnalyzer::ISMBv1::lockByteRangeSMBv1,        command<LockByteRangeCommand>(requestData, responseData, session));
    case Commands::UNLOCK_BYTE_RANGE:
        return analyzers(&IAnalyzer::ISMBv1::unlockByteRangeSMBv1,      command<UnlockByteRangeCommand>(requestData, responseData, session));
    case Commands::CREATE_TEMPORARY:
        return analyzers(&IAnalyzer::ISMBv1::createTmpSMBv1,            command<CreateTemporaryCommand>(requestData, responseData, session));
    case Commands::CREATE_NEW:
        return analyzers(&IAnalyzer::ISMBv1::createNewSMBv1,            command<CreateNewCommand>(requestData, responseData, session));
    case Commands::CHECK_DIRECTORY:
        return analyzers(&IAnalyzer::ISMBv1::checkDirectorySMBv1,       command<CheckDirectoryCommand>(requestData, responseData, session));
    case Commands::PROCESS_EXIT:
        return analyzers(&IAnalyzer::ISMBv1::processExitSMBv1,          command<ProcessExitCommand>(requestData, responseData, session));
    case Commands::SEEK:
        return analyzers(&IAnalyzer::ISMBv1::seekSMBv1,                 command<SeekCommand>(requestData, responseData, session));
    case Commands::LOCK_AND_READ:
        return analyzers(&IAnalyzer::ISMBv1::lockAndReadSMBv1,          command<LockAndReadCommand>(requestData, responseData, session));
    case Commands::WRITE_AND_UNLOCK:
        return analyzers(&IAnalyzer::ISMBv1::writeAndUnlockSMBv1,       command<WriteAndUnlockCommand>(requestData, responseData, session));
    case Commands::READ_RAW:
        return analyzers(&IAnalyzer::ISMBv1::readRawSMBv1,              command<ReadRawCommand>(requestData, responseData, session));
    case Commands::READ_MPX:
        return analyzers(&IAnalyzer::ISMBv1::readMpxSMBv1,              command<ReadMpxCommand>(requestData, responseData, session));
    case Commands::READ_MPX_SECONDARY:
        return analyzers(&IAnalyzer::ISMBv1::readMpxSecondarySMBv1,     command<ReadMpxSecondaryCommand>(requestData, responseData, session));
    case Commands::WRITE_RAW:
        return analyzers(&IAnalyzer::ISMBv1::writeRawSMBv1,             command<WriteRawCommand>(requestData, responseData, session));
    case Commands::WRITE_MPX:
        return analyzers(&IAnalyzer::ISMBv1::writeMpxSMBv1,             command<WriteMpxCommand>(requestData, responseData, session));
    case Commands::WRITE_MPX_SECONDARY:
        return analyzers(&IAnalyzer::ISMBv1::writeMpxSecondarySMBv1,    command<WriteMpxSecondaryCommand>(requestData, responseData, session));
    case Commands::WRITE_COMPLETE:
        return analyzers(&IAnalyzer::ISMBv1::writeCompleteSMBv1,        command<WriteCompleteCommand>(requestData, responseData, session));
    case Commands::QUERY_SERVER:
        return analyzers(&IAnalyzer::ISMBv1::queryServerSMBv1,          command<QueryServerCommand>(requestData, responseData, session));
    case Commands::SET_INFORMATION2:
        return analyzers(&IAnalyzer::ISMBv1::setInfo2SMBv1,             command<SetInformation2Command>(requestData, responseData, session));
    case Commands::QUERY_INFORMATION2:
        return analyzers(&IAnalyzer::ISMBv1::queryInfo2SMBv1,           command<QueryInformation2Command>(requestData, responseData, session));
    case Commands::LOCKING_ANDX:
        return analyzers(&IAnalyzer::ISMBv1::lockingAndxSMBv1,          command<LockingAndxCommand>(requestData, responseData, session));
    case Commands::TRANSACTION:
        return analyzers(&IAnalyzer::ISMBv1::transactionSMBv1,          command<TransactionCommand>(requestData, responseData, session));
    case Commands::TRANSACTION_SECONDARY:
        return analyzers(&IAnalyzer::ISMBv1::transactionSecondarySMBv1, command<TransactionSecondaryCommand>(requestData, responseData, session));
    case Commands::IOCTL:
        return analyzers(&IAnalyzer::ISMBv1::ioctlSMBv1,                command<IoctlCommand>(requestData, responseData, session));
    case Commands::IOCTL_SECONDARY:
        return analyzers(&IAnalyzer::ISMBv1::ioctlSecondarySMBv1,       command<IoctlSecondaryCommand>(requestData, responseData, session));
    case Commands::COPY:
        return analyzers(&IAnalyzer::ISMBv1::copySMBv1,                 command<CopyCommand>(requestData, responseData, session));
    case Commands::MOVE:
        return analyzers(&IAnalyzer::ISMBv1::moveSMBv1,                 command<MoveCommand>(requestData, responseData, session));
    case Commands::ECHO:
        return analyzers(&IAnalyzer::ISMBv1::echoSMBv1,                 command<EchoCommand>(requestData, responseData, session));
    case Commands::WRITE_AND_CLOSE:
        return analyzers(&IAnalyzer::ISMBv1::writeAndCloseSMBv1,        command<WriteAndCloseCommand>(requestData, responseData, session));
    case Commands::OPEN_ANDX:
        return analyzers(&IAnalyzer::ISMBv1::openAndxSMBv1,             command<OpenAndxCommand>(requestData, responseData, session));
    case Commands::READ_ANDX:
        return analyzers(&IAnalyzer::ISMBv1::readAndxSMBv1,             command<ReadAndxCommand>(requestData, responseData, session));
    case Commands::WRITE_ANDX:
        return analyzers(&IAnalyzer::ISMBv1::writeAndxSMBv1,            command<WriteAndxCommand>(requestData, responseData, session));
    case Commands::NEW_FILE_SIZE:
        return analyzers(&IAnalyzer::ISMBv1::newFileSizeSMBv1,          command<NewFileSizeCommand>(requestData, responseData, session));
    case Commands::CLOSE_AND_TREE_DISC:
        return analyzers(&IAnalyzer::ISMBv1::closeAndTreeDiscSMBv1,     command<CloseAndTreeDiscCommand>(requestData, responseData, session));
    case Commands::TRANSACTION2:
        return analyzers(&IAnalyzer::ISMBv1::transaction2SMBv1,         command<Transaction2Command>(requestData, responseData, session));
    case Commands::TRANSACTION2_SECONDARY:
        return analyzers(&IAnalyzer::ISMBv1::transaction2SecondarySMBv1, command<Transaction2SecondaryCommand>(requestData, responseData, session));
    case Commands::FIND_CLOSE2:
        return analyzers(&IAnalyzer::ISMBv1::findClose2SMBv1,           command<FindClose2Command>(requestData, responseData, session));
    case Commands::FIND_NOTIFY_CLOSE:
        return analyzers(&IAnalyzer::ISMBv1::findNotifyCloseSMBv1,      command<FindNotifyCloseCommand>(requestData, responseData, session));
    case Commands::TREE_CONNECT:
        return analyzers(&IAnalyzer::ISMBv1::treeConnectSMBv1,          command<TreeConnectCommand>(requestData, responseData, session));
    case Commands::TREE_DISCONNECT:
        return analyzers(&IAnalyzer::ISMBv1::treeDisconnectSMBv1,       command<TreeDisconnectCommand>(requestData, responseData, session));
    case Commands::NEGOTIATE:
        return analyzers(&IAnalyzer::ISMBv1::negotiateSMBv1,            command<NegotiateCommand>(requestData, responseData, session));
    case Commands::SESSION_SETUP_ANDX:
        return analyzers(&IAnalyzer::ISMBv1::sessionSetupAndxSMBv1,     command<SessionSetupAndxCommand>(requestData, responseData, session));
    case Commands::LOGOFF_ANDX:
        return analyzers(&IAnalyzer::ISMBv1::logoffAndxSMBv1,           command<LogoffAndxCommand>(requestData, responseData, session));
    case Commands::TREE_CONNECT_ANDX:
        return analyzers(&IAnalyzer::ISMBv1::treeConnectAndxSMBv1,      command<TreeConnectAndxCommand>(requestData, responseData, session));
    case Commands::SECURITY_PACKAGE_ANDX:
        return analyzers(&IAnalyzer::ISMBv1::securityPackageAndxSMBv1,  command<SecurityPackageAndxCommand>(requestData, responseData, session));
    case Commands::QUERY_INFORMATION_DISK:
        return analyzers(&IAnalyzer::ISMBv1::queryInformationDiskSMBv1, command<QueryInformationDiskCommand>(requestData, responseData, session));
    case Commands::SEARCH:
        return analyzers(&IAnalyzer::ISMBv1::searchSMBv1,               command<SearchCommand>(requestData, responseData, session));
    case Commands::FIND:
        return analyzers(&IAnalyzer::ISMBv1::findSMBv1,                 command<FindCommand>(requestData, responseData, session));
    case Commands::FIND_UNIQUE:
        return analyzers(&IAnalyzer::ISMBv1::findUniqueSMBv1,           command<FindUniqueCommand>(requestData, responseData, session));
    case Commands::FIND_CLOSE:
        return analyzers(&IAnalyzer::ISMBv1::findCloseSMBv1,            command<FindCloseCommand>(requestData, responseData, session));
    case Commands::NT_TRANSACT:
        return analyzers(&IAnalyzer::ISMBv1::ntTransactSMBv1,           command<NtTransactCommand>(requestData, responseData, session));
    case Commands::NT_TRANSACT_SECONDARY:
        return analyzers(&IAnalyzer::ISMBv1::ntTransactSecondarySMBv1,  command<NtTransactSecondaryCommand>(requestData, responseData, session));
    case Commands::NT_CREATE_ANDX:
        return analyzers(&IAnalyzer::ISMBv1::ntCreateAndxSMBv1,         command<NtCreateAndxCommand>(requestData, responseData, session));
    case Commands::NT_CANCEL:
        return analyzers(&IAnalyzer::ISMBv1::ntCancelSMBv1,             command<NtCancelCommand>(requestData, responseData, session));
    case Commands::NT_RENAME:
        return analyzers(&IAnalyzer::ISMBv1::ntRenameSMBv1,             command<NtRenameCommand>(requestData, responseData, session));
    case Commands::OPEN_PRINT_FILE:
        return analyzers(&IAnalyzer::ISMBv1::openPrintFileSMBv1,        command<OpenPrintFileCommand>(requestData, responseData, session));
    case Commands::WRITE_PRINT_FILE:
        return analyzers(&IAnalyzer::ISMBv1::writePrintFileSMBv1,       command<WritePrintFileCommand>(requestData, responseData, session));
    case Commands::CLOSE_PRINT_FILE:
        return analyzers(&IAnalyzer::ISMBv1::closePrintFileSMBv1,       command<ClosePrintFileCommand>(requestData, responseData, session));
    case Commands::GET_PRINT_QUEUE:
        return analyzers(&IAnalyzer::ISMBv1::getPrintQueueSMBv1,        command<GetPrintQueueCommand>(requestData, responseData, session));
    case Commands::READ_BULK:
        return analyzers(&IAnalyzer::ISMBv1::readBulkSMBv1,             command<ReadBulkCommand>(requestData, responseData, session));
    case Commands::WRITE_BULK:
        return analyzers(&IAnalyzer::ISMBv1::writeBulkSMBv1,            command<WriteBulkCommand>(requestData, responseData, session));
    case Commands::WRITE_BULK_DATA:
        return analyzers(&IAnalyzer::ISMBv1::writeBulkDataSMBv1,        command<WriteBulkDataCommand>(requestData, responseData, session));
    case Commands::INVALID:
        return analyzers(&IAnalyzer::ISMBv1::invalidSMBv1,              command<InvalidCommand>(requestData, responseData, session));
    case Commands::NO_ANDX_COMMAND:
        return analyzers(&IAnalyzer::ISMBv1::noAndxCommandSMBv1,        command<NoAndxCommand>(requestData, responseData, session));
    default:
        LOG("Usupported command");
    }
}


void CIFSParser::analyse_operation(Session* session,
                                   const CIFSv2::MessageHeader* request,
                                   const CIFSv2::MessageHeader* /*response*/,
                                   NST::utils::FilteredDataQueue::Ptr&& requestData,
                                   NST::utils::FilteredDataQueue::Ptr&& responseData)
{
    using namespace NST::API::SMBv2;
    using namespace NST::protocols::CIFSv2;

    switch (request->cmd_code)
    {
    case Commands::CLOSE:
        return analyzers(&IAnalyzer::ISMBv2::closeFileSMBv2,            command<CloseFileCommand>(requestData, responseData, session));
    case Commands::NEGOTIATE:
        return analyzers(&IAnalyzer::ISMBv2::negotiateSMBv2,            command<NegotiateCommand>(requestData, responseData, session));
    case Commands::SESSION_SETUP:
        return analyzers(&IAnalyzer::ISMBv2::sessionSetupSMBv2,         command<SessionSetupCommand>(requestData, responseData, session));
    case Commands::LOGOFF:
        return analyzers(&IAnalyzer::ISMBv2::logOffSMBv2,               command<LogOffCommand>(requestData, responseData, session));
    case Commands::TREE_CONNECT:
        return analyzers(&IAnalyzer::ISMBv2::treeConnectSMBv2,          command<TreeConnectCommand>(requestData, responseData, session));
    case Commands::TREE_DISCONNECT:
        return analyzers(&IAnalyzer::ISMBv2::treeDisconnectSMBv2,       command<TreeDisconnectCommand>(requestData, responseData, session));
    case Commands::CREATE:
        return analyzers(&IAnalyzer::ISMBv2::createSMBv2,               command<CreateCommand>(requestData, responseData, session));
    case Commands::FLUSH:
        return analyzers(&IAnalyzer::ISMBv2::flushSMBv2,                command<FlushCommand>(requestData, responseData, session));
    case Commands::READ:
        return analyzers(&IAnalyzer::ISMBv2::readSMBv2,                 command<ReadCommand>(requestData, responseData, session));
    case Commands::WRITE:
        return analyzers(&IAnalyzer::ISMBv2::writeSMBv2,                command<WriteCommand>(requestData, responseData, session));
    case Commands::LOCK:
        return analyzers(&IAnalyzer::ISMBv2::lockSMBv2,                 command<LockCommand>(requestData, responseData, session));
    case Commands::IOCTL:
        return analyzers(&IAnalyzer::ISMBv2::ioctlSMBv2,                command<IoctlCommand>(requestData, responseData, session));
    case Commands::CANCEL:
        return analyzers(&IAnalyzer::ISMBv2::cancelSMBv2,               command<CancelCommand>(requestData, responseData, session));
    case Commands::ECHO:
        return analyzers(&IAnalyzer::ISMBv2::echoSMBv2,                 command<EchoCommand>(requestData, responseData, session));
    case Commands::QUERY_DIRECTORY:
        return analyzers(&IAnalyzer::ISMBv2::queryDirSMBv2,             command<QueryDirCommand>(requestData, responseData, session));
    case Commands::CHANGE_NOTIFY:
        return analyzers(&IAnalyzer::ISMBv2::changeNotifySMBv2,         command<ChangeNotifyCommand>(requestData, responseData, session));
    case Commands::QUERY_INFO:
        return analyzers(&IAnalyzer::ISMBv2::queryInfoSMBv2,            command<QueryInfoCommand>(requestData, responseData, session));
    case Commands::SET_INFO:
        return analyzers(&IAnalyzer::ISMBv2::setInfoSMBv2,              command<SetInfoCommand>(requestData, responseData, session));
    case Commands::OPLOCK_BREAK:
        return analyzers(&IAnalyzer::ISMBv2::breakOplockSMBv2,          command<BreakOpLockCommand>(requestData, responseData, session));
    default:
        LOG("Usupported command");
    }
}
