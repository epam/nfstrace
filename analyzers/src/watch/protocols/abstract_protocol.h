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
#ifndef ABSTRACT_PROTOCOL_H
#define ABSTRACT_PROTOCOL_H
//------------------------------------------------------------------------------
#include <cstdlib>
#include <string>
//------------------------------------------------------------------------------
class AbstractProtocol
{
public:
    AbstractProtocol() = delete;
    AbstractProtocol(const char*, std::size_t);
    virtual ~AbstractProtocol();

    /*!
     * Use to conver number of operation to it's name.
     */
    virtual const char* printProcedure(std::size_t);

    /*!
     * Return number of groups
     */
    virtual std::size_t getGroups();

    /*!
     * Return first counter of group
     */
    virtual std::size_t getGroupBegin(std::size_t);

    /*!
     * Return amount of operations.
     */
    unsigned int getAmount() const;

    /*!
     * Return protocol's name.
     */
    std::string getProtocolName() const;

private:
    std::string name;
    std::size_t amount;
};
//------------------------------------------------------------------------------
#endif//ABSTRACT_PROTOCOL_H
//------------------------------------------------------------------------------
