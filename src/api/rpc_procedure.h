//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Presentation info about ISO/OSI layers up to RPC protocol.
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
#ifndef RPC_PROCEDURE_H
#define RPC_PROCEDURE_H
//------------------------------------------------------------------------------
#include <rpc/rpc_msg.h>

#include "procedure.h"
#include "rpc_types.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

using RPCProcedure = Procedure<struct rpc_msg>;

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_PROCEDURE_H
//------------------------------------------------------------------------------
