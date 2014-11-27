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
        case CIFS::Commands::SMB_COM_ECHO:          return analyzers(&IAnalyzer::ISMBv1::echoRequest,           CIFS::command<SMBv1::EchoRequestCommand>(header));
        case CIFS::Commands::SMB_COM_CLOSE:         return analyzers(&IAnalyzer::ISMBv1::closeFile,             CIFS::command<SMBv1::CloseFileCommand>(header));
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
