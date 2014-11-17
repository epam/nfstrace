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
#include "analysis/cifs_parser.h"
#include <iostream>

#include "protocols/cifs/cifs_header.h"

using namespace std;
using namespace NST::protocols;
using namespace NST::analysis;

void CIFSParser::parse_data(NST::utils::FilteredDataQueue::Ptr &&data)
{
    auto header = CIFS::get_header(data->data);
    if (header) {
        cout << "msg: ";
        cout << header->commandDescription() << dec;
        cout << endl;
    } else {
        cout << "Got BAD message!" << endl;
    }
}
