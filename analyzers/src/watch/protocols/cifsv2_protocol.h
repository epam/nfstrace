//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for CIFSv2 protocol.
// Copyright (c) 2015 EPAM Systems. All Rights Reserved.
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
#ifndef CIFSV2_PROTOCOL_H
#define CIFSV2_PROTOCOL_H
//------------------------------------------------------------------------------
#include "abstract_protocol.h"
//------------------------------------------------------------------------------
class CIFSv2Protocol : public AbstractProtocol
{
public:
    CIFSv2Protocol();
    ~CIFSv2Protocol();
    virtual const char* printProcedure(std::size_t);
};
//------------------------------------------------------------------------------
#endif //CIFSV2_PROTOCOL_H
//------------------------------------------------------------------------------
