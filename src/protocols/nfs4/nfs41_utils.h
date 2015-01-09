//------------------------------------------------------------------------------
// Author: Alexey Costroma
// Description: Helpers for parsing NFS structures.
// Copyright (c) 2015 EPAM Systems
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
#include <ostream>

#include "api/nfs_types.h"
#include "api/nfs41_types_rpcgen.h"
#include "protocols/nfs/nfs_utils.h"
#include "protocols/rpc/rpc_header.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS41
{

namespace NFS41 = NST::API::NFS41;

using ProcEnumNFS41 = API::ProcEnumNFS41;

using Validator = rpc::RPCProgramValidator
                <
                    100003,                  // SunRPC/NFS program
                    4,                       // v4
                    ProcEnumNFS41::NFS_NULL, // NFSPROC41RPCGEN_NULL     (0)
                    ProcEnumNFS41::COMPOUND  // NFSPROC41RPCGEN_COMPOUND (1)
                >;

// Procedure 0: NULL - Do nothing
inline auto proc_t_of(NFS41::NULL4args&)->decltype(&NFS41::xdr_NULL4args)
{
    return &NFS41::xdr_NULL4args;
}

inline auto proc_t_of(NFS41::NULL4res&)->decltype(&NFS41::xdr_NULL4res)
{
    return &NFS41::xdr_NULL4res;
}

// Procedure 1: COMPOUND
inline auto proc_t_of(NFS41::COMPOUND4args&)->decltype(&NFS41::xdr_COMPOUND4args)
{
    return &NFS41::xdr_COMPOUND4args;
}

inline auto proc_t_of(NFS41::COMPOUND4res&)->decltype(&NFS41::xdr_COMPOUND4res)
{
    return &NFS41::xdr_COMPOUND4res;
}

} // namespace NFS41
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS41_UTILS_H
//------------------------------------------------------------------------------
