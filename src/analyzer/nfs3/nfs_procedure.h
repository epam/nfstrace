//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Base structure for nfs-info.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PROCEDURE_H
#define NFS_PROCEDURE_H
//------------------------------------------------------------------------------
#include "../../auxiliary/filtered_data.h"
#include "../rpc/rpc_procedure_struct.h"
#include "../rpc/rpc_reader.h"
#include "nfs_structs.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace NFS3
{

template
<
    typename ArgType,   // structure of RPC procedure parameters
    typename ResType    // structure of RPC procedure results
>
class NFSProcedure: public RPC::RPCProcedure
{
public:
    typedef ArgType Arg;
    typedef ResType Res;

    inline NFSProcedure(RPC::RPCReader& c, RPC::RPCReader& r, const Session* s)
    {
        c >> call  >> arg;    // fill procedure call and arguments
        r >> reply >> res;    // fill procedure reply and results

        session = s;

        ctimestamp = &c.data().timestamp;
        rtimestamp = &r.data().timestamp;
    }

    Arg arg;
    Res res;
};

typedef NFSProcedure <NULLargs,         NULLres>            NFSPROC3_NULL;
typedef NFSProcedure <GETATTR3args,     GETATTR3res>        NFSPROC3_GETATTR;
typedef NFSProcedure <SETATTR3args,     SETATTR3res>        NFSPROC3_SETATTR;
typedef NFSProcedure <LOOKUP3args,      LOOKUP3res>         NFSPROC3_LOOKUP;
typedef NFSProcedure <ACCESS3args,      ACCESS3res>         NFSPROC3_ACCESS;
typedef NFSProcedure <READLINK3args,    READLINK3res>       NFSPROC3_READLINK;
typedef NFSProcedure <READ3args,        READ3res>           NFSPROC3_READ;
typedef NFSProcedure <WRITE3args,       WRITE3res>          NFSPROC3_WRITE;
typedef NFSProcedure <CREATE3args,      CREATE3res>         NFSPROC3_CREATE;
typedef NFSProcedure <MKDIR3args,       MKDIR3res>          NFSPROC3_MKDIR;
typedef NFSProcedure <SYMLINK3args,     SYMLINK3res>        NFSPROC3_SYMLINK;
typedef NFSProcedure <MKNOD3args,       MKNOD3res>          NFSPROC3_MKNOD;
typedef NFSProcedure <REMOVE3args,      REMOVE3res>         NFSPROC3_REMOVE;
typedef NFSProcedure <RMDIR3args,       RMDIR3res>          NFSPROC3_RMDIR;
typedef NFSProcedure <RENAME3args,      RENAME3res>         NFSPROC3_RENAME;
typedef NFSProcedure <LINK3args,        LINK3res>           NFSPROC3_LINK;
typedef NFSProcedure <READDIR3args,     READDIR3res>        NFSPROC3_READDIR;
typedef NFSProcedure <READDIRPLUS3args, READDIRPLUS3res>    NFSPROC3_READDIRPLUS;
typedef NFSProcedure <FSSTAT3args,      FSSTAT3res>         NFSPROC3_FSSTAT;
typedef NFSProcedure <FSINFO3args,      FSINFO3res>         NFSPROC3_FSINFO;
typedef NFSProcedure <PATHCONF3args,    PATHCONF3res>       NFSPROC3_PATHCONF;
typedef NFSProcedure <COMMIT3args,      COMMIT3res>         NFSPROC3_COMMIT;

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PROCEDURE_H
//------------------------------------------------------------------------------
