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
#include "protocols/cifs/cifs_header.h"
//------------------------------------------------------------------------------
using namespace NST::protocols;
using namespace NST::analysis;

void CIFSParser::parse_data(NST::utils::FilteredDataQueue::Ptr &&data)
{
    for (int i = 0; i < 5 ; i++) {
        std::cout << data->data[i];
    }
    std::cout << std::endl;

    auto header = CIFS::get_header(data->data);
    if (header) {
        std::cout << "msg: ";
        std::cout << header->commandDescription() << std::dec;
        std::cout << std::endl;
    } else {
        std::cout << "Got BAD message!" << std::endl;
    }
}
