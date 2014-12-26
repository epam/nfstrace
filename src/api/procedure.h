//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Abstraction of operation (CIFS or NFS)
// Copyright (c) 2013 EPAM Systems
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
#ifndef PROCEDURE_H
#define PROCEDURE_H
//------------------------------------------------------------------------------
#include <sys/time.h>

#include "session.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

template<typename ProcedureType>
struct Procedure
{
    ProcedureType rpc_call;
    ProcedureType rpc_reply;

    const struct Session* session;
    const struct timeval* ctimestamp;
    const struct timeval* rtimestamp;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif // PROCEDURE_H
//------------------------------------------------------------------------------
