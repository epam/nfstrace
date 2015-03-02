//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source for all nfs protocols.
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
#ifndef PROTOCOLS_H
#define PROTOCOLS_H
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
    virtual const char* printProcedure(std::size_t);
    unsigned int getAmount();
    std::string getProtocolName();
private:
    std::string name;
    std::size_t amount;
};

class NFSv3Protocol : public AbstractProtocol
{
public:
    NFSv3Protocol();
    ~NFSv3Protocol();
    virtual const char* printProcedure(std::size_t);
};

class NFSv4Protocol : public AbstractProtocol
{
public:
    NFSv4Protocol();
    ~NFSv4Protocol();
    virtual const char* printProcedure(std::size_t);
};

class NFSv41Protocol : public AbstractProtocol
{
public:
    NFSv41Protocol();
    ~NFSv41Protocol();
    virtual const char* printProcedure(std::size_t);
};

class CIFSv1Protocol : public AbstractProtocol
{
public:
    CIFSv1Protocol();
    ~CIFSv1Protocol();
    virtual const char* printProcedure(std::size_t);
};

class CIFSv2Protocol : public AbstractProtocol
{
public:
    CIFSv2Protocol();
    ~CIFSv2Protocol();
    virtual const char* printProcedure(std::size_t);
};
//------------------------------------------------------------------------------
#endif // PROTOCOLS_H
//------------------------------------------------------------------------------
