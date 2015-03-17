//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for abstract protocol.
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
#include "abstract_protocol.h"
#include <api/plugin_api.h> // include plugin development definitions
//------------------------------------------------------------------------------
namespace
{
    const int EMPTY_GROUP = 1;
}

AbstractProtocol::AbstractProtocol(const char* n, std::size_t i)
: name {n}
, amount {i}
{
}

AbstractProtocol::~AbstractProtocol()
{
}

const char* AbstractProtocol::printProcedure(std::size_t)
{
    return nullptr;
}

std::string AbstractProtocol::getProtocolName() const
{
    return name;
}

unsigned int AbstractProtocol::getAmount() const
{
    return amount;
}

std::size_t AbstractProtocol::getGroups()
{
    return EMPTY_GROUP;
}

std::size_t AbstractProtocol::getGroupBegin(std::size_t i)
{
    if( i == EMPTY_GROUP)
        return 0;
    else
        return amount;
}

//------------------------------------------------------------------------------
