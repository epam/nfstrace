//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for NFSv3 protocol.
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
#ifndef NFSV3_PROTOCOL_H
#define NFSV3_PROTOCOL_H
//------------------------------------------------------------------------------
#include "abstract_protocol.h"
//------------------------------------------------------------------------------
class NFSv3Protocol : public AbstractProtocol
{
public:
    NFSv3Protocol();
    ~NFSv3Protocol();
    virtual const char* printProcedure(std::size_t);
};
//------------------------------------------------------------------------------
#endif // NFSV3_PROTOCOL_H
//------------------------------------------------------------------------------
