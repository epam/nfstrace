//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Base structure for nfs-info.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PROCEDURE_H
#define NFS_PROCEDURE_H
//------------------------------------------------------------------------------
#include "../../auxiliary/filtered_data.h"
#include "../rpc/rpc_operation.h"
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

// Artificial structure for enumeration of the NFS procedures
struct Proc
{
    enum Enum
    {
        NFS_NULL    = 0,
        GETATTR     = 1,
        SETATTR     = 2,
        LOOKUP      = 3,
        ACCESS      = 4,
        READLINK    = 5,
        READ        = 6,
        WRITE       = 7,
        CREATE      = 8,
        MKDIR       = 9,
        SYMLINK     = 10,
        MKNOD       = 11,
        REMOVE      = 12,
        RMDIR       = 13,
        RENAME      = 14,
        LINK        = 15,
        READDIR     = 16,
        READDIRPLUS = 17,
        FSSTAT      = 18,
        FSINFO      = 19,
        PATHCONF    = 20,
        COMMIT      = 21,
        num         = 22
    };

    static const char* Titles[Proc::num];

private:
    Proc(const Proc&);            // undefiend
    Proc& operator=(const Proc&); // undefiend
};

inline std::ostream& operator<<(std::ostream& out, const Proc::Enum proc);

template
<
    typename ArgType,   // structure of RPC procedure parameters
    typename ResType    // structure of RPC procedure results
>
class NFSOperation: public RPC::RPCOperation
{
public:
    typedef ArgType Arg;
    typedef ResType Res;

    NFSOperation(FilteredDataQueue::Ptr& c,
                 FilteredDataQueue::Ptr& r,
                 RPCSession* s)
                 : RPC::RPCOperation(c, r, s)
    {
        RPC::RPCOperation::cdata >> arg;    // fill procedure parameters
        RPC::RPCOperation::rdata >> res;    // fill procedure results
    }

    inline const Arg& get_arg() const { return arg; }
    inline const Res& get_res() const { return res; }

private:
    Arg arg;
    Res res;
};

typedef NFSOperation <NULLargs,         NULLres>            NFSPROC3_NULL;
typedef NFSOperation <GETATTR3args,     GETATTR3res>        NFSPROC3_GETATTR;
typedef NFSOperation <SETATTR3args,     SETATTR3res>        NFSPROC3_SETATTR;
typedef NFSOperation <LOOKUP3args,      LOOKUP3res>         NFSPROC3_LOOKUP;
typedef NFSOperation <ACCESS3args,      ACCESS3res>         NFSPROC3_ACCESS;
typedef NFSOperation <READLINK3args,    READLINK3res>       NFSPROC3_READLINK;
typedef NFSOperation <READ3args,        READ3res>           NFSPROC3_READ;
typedef NFSOperation <WRITE3args,       WRITE3res>          NFSPROC3_WRITE;
typedef NFSOperation <CREATE3args,      CREATE3res>         NFSPROC3_CREATE;
typedef NFSOperation <MKDIR3args,       MKDIR3res>          NFSPROC3_MKDIR;
typedef NFSOperation <SYMLINK3args,     SYMLINK3res>        NFSPROC3_SYMLINK;
typedef NFSOperation <MKNOD3args,       MKNOD3res>          NFSPROC3_MKNOD;
typedef NFSOperation <REMOVE3args,      REMOVE3res>         NFSPROC3_REMOVE;
typedef NFSOperation <RMDIR3args,       RMDIR3res>          NFSPROC3_RMDIR;
typedef NFSOperation <RENAME3args,      RENAME3res>         NFSPROC3_RENAME;
typedef NFSOperation <LINK3args,        LINK3res>           NFSPROC3_LINK;
typedef NFSOperation <READDIR3args,     READDIR3res>        NFSPROC3_READDIR;
typedef NFSOperation <READDIRPLUS3args, READDIRPLUS3res>    NFSPROC3_READDIRPLUS;
typedef NFSOperation <FSSTAT3args,      FSSTAT3res>         NFSPROC3_FSSTAT;
typedef NFSOperation <FSINFO3args,      FSINFO3res>         NFSPROC3_FSINFO;
typedef NFSOperation <PATHCONF3args,    PATHCONF3res>       NFSPROC3_PATHCONF;
typedef NFSOperation <COMMIT3args,      COMMIT3res>         NFSPROC3_COMMIT;

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PROCEDURE_H
//------------------------------------------------------------------------------
