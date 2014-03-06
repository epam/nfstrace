//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition and fill up NFSv3 procedures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PROCEDURE_H
#define NFS_PROCEDURE_H
//------------------------------------------------------------------------------
#include "protocols/rpc/rpc_procedure_struct.h"
#include "protocols/rpc/rpc_reader.h"
#include "protocols/nfs3/nfs_structs.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NFS3
{

template
<
    typename ArgType,   // structure of RPC procedure parameters
    typename ResType    // structure of RPC procedure results
>
class NFSProcedure: public rpc::RPCProcedure
{
public:

    inline NFSProcedure(rpc::RPCReader& c, rpc::RPCReader& r, const Session* s)
    {
        c >> call  >> arg;    // fill procedure call and arguments
        r >> reply >> res;    // fill procedure reply and results

        session = s;

        ctimestamp = &c.data().timestamp;
        rtimestamp = &r.data().timestamp;
    }

    ArgType arg;
    ResType res;
};

using NFSPROC3_NULL        = NFSProcedure <NULLargs,         NULLres>;
using NFSPROC3_GETATTR     = NFSProcedure <GETATTR3args,     GETATTR3res>;
using NFSPROC3_SETATTR     = NFSProcedure <SETATTR3args,     SETATTR3res>;
using NFSPROC3_LOOKUP      = NFSProcedure <LOOKUP3args,      LOOKUP3res>;
using NFSPROC3_ACCESS      = NFSProcedure <ACCESS3args,      ACCESS3res>;
using NFSPROC3_READLINK    = NFSProcedure <READLINK3args,    READLINK3res>;
using NFSPROC3_READ        = NFSProcedure <READ3args,        READ3res>;
using NFSPROC3_WRITE       = NFSProcedure <WRITE3args,       WRITE3res>;
using NFSPROC3_CREATE      = NFSProcedure <CREATE3args,      CREATE3res>;
using NFSPROC3_MKDIR       = NFSProcedure <MKDIR3args,       MKDIR3res>;
using NFSPROC3_SYMLINK     = NFSProcedure <SYMLINK3args,     SYMLINK3res>;
using NFSPROC3_MKNOD       = NFSProcedure <MKNOD3args,       MKNOD3res>;
using NFSPROC3_REMOVE      = NFSProcedure <REMOVE3args,      REMOVE3res>;
using NFSPROC3_RMDIR       = NFSProcedure <RMDIR3args,       RMDIR3res>;
using NFSPROC3_RENAME      = NFSProcedure <RENAME3args,      RENAME3res>;
using NFSPROC3_LINK        = NFSProcedure <LINK3args,        LINK3res>;
using NFSPROC3_READDIR     = NFSProcedure <READDIR3args,     READDIR3res>;
using NFSPROC3_READDIRPLUS = NFSProcedure <READDIRPLUS3args, READDIRPLUS3res>;
using NFSPROC3_FSSTAT      = NFSProcedure <FSSTAT3args,      FSSTAT3res>;
using NFSPROC3_FSINFO      = NFSProcedure <FSINFO3args,      FSINFO3res>;
using NFSPROC3_PATHCONF    = NFSProcedure <PATHCONF3args,    PATHCONF3res>;
using NFSPROC3_COMMIT      = NFSProcedure <COMMIT3args,      COMMIT3res>;

} // namespace NFS3
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PROCEDURE_H
//------------------------------------------------------------------------------
