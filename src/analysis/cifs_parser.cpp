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
//------------------------------------------------------------------------------
using namespace NST::protocols;
using namespace NST::analysis;

CIFSParser::CIFSParser(Analyzers &a) :
    analyzers(a)
{
}

void CIFSParser::parse_data(NST::utils::FilteredDataQueue::Ptr &&data)
{
    if (const CIFS::MessageHeader* header = CIFS::get_header(data->data))
    {
        using namespace NST::API;

        switch (header->cmd_code) {
        case CIFS::Commands::SMB_COM_ECHO: return analyzers(&IAnalyzer::ISMBv1::echoRequest, SMBv1::EchoRequestCommand(header));
        case CIFS::Commands::SMB_COM_CLOSE: return analyzers(&IAnalyzer::ISMBv1::closeFile, SMBv1::EchoRequestCommand(header));
        default:
            break;
        }
    }
    else
    {
        std::cout << "Got BAD message!" << std::endl;
    }
}
