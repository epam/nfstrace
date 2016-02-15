//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for NFSv41 protocol.
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
#ifndef NFSV41_PROTOCOL_H
#define NFSV41_PROTOCOL_H
//------------------------------------------------------------------------------
#include "abstract_protocol.h"
//------------------------------------------------------------------------------
class NFSv41Protocol : public AbstractProtocol
{
public:
    NFSv41Protocol();
    ~NFSv41Protocol();
    virtual const char* printProcedure(std::size_t);
    virtual std::size_t getGroups();
    virtual std::size_t getGroupBegin(std::size_t);
};
//------------------------------------------------------------------------------
#endif //NFSV41_PROTOCOL_H
//------------------------------------------------------------------------------
