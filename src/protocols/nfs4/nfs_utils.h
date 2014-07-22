//------------------------------------------------------------------------------
// Author: Alexey Costroma
// Description: Helpers for parsing NFS structures.
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
#ifndef NFS4_UTILS_H
#define NFS4_UTILS_H
//------------------------------------------------------------------------------
#include <cassert>
#include <ostream>

#include "api/nfs4_types.h"

#include "protocols/xdr/xdr_decoder.h"
#include "protocols/xdr/xdr_reader.h"
#include "protocols/rpc/rpc_header.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS4
{

using namespace NST::API;

using namespace NST::protocols::xdr;

using Validator = rpc::RPCProgramValidator
                <
                    100003,             // SunRPC/NFS program
                    4,                  // v4
                    Proc4Enum::NFS_NULL,   // NFSPROC4RPCGEN_NULL     (0)
                    Proc4Enum::COMPOUND    // NFSPROC4RPCGEN_COMPOUND (1)
                >;

static const char* const NFS4ProcedureTitles[ProcEnum::count] =
{
  "NULL",       "COMPOUND"
};

} // namespace NFS4
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS4_UTILS_H
//------------------------------------------------------------------------------
