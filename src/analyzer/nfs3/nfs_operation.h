//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Base structure for nfs-info.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_OPERATION_H
#define NFS_OPERATION_H
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

typedef NFSOperation <NULLargs,         NULLres>    NFSPROC3_NULL;
typedef NFSOperation <GETATTR3args,     NULLres>    NFSPROC3_GETATTR;
typedef NFSOperation <SETATTR3args,     NULLres>    NFSPROC3_SETATTR;
typedef NFSOperation <LOOKUP3args,      LOOKUP3res>    NFSPROC3_LOOKUP;
typedef NFSOperation <ACCESS3args,      NULLres>    NFSPROC3_ACCESS;
typedef NFSOperation <READLINK3args,    NULLres>    NFSPROC3_READLINK;
typedef NFSOperation <READ3args,        NULLres>    NFSPROC3_READ;
typedef NFSOperation <WRITE3args,       NULLres>    NFSPROC3_WRITE;
typedef NFSOperation <CREATE3args,      NULLres>    NFSPROC3_CREATE;
typedef NFSOperation <MKDIR3args,       NULLres>    NFSPROC3_MKDIR;
typedef NFSOperation <SYMLINK3args,     NULLres>    NFSPROC3_SYMLINK;
typedef NFSOperation <MKNOD3args,       NULLres>    NFSPROC3_MKNOD;
typedef NFSOperation <REMOVE3args,      NULLres>    NFSPROC3_REMOVE;
typedef NFSOperation <RMDIR3args,       NULLres>    NFSPROC3_RMDIR;
typedef NFSOperation <RENAME3args,      NULLres>    NFSPROC3_RENAME;
typedef NFSOperation <LINK3args,        NULLres>    NFSPROC3_LINK;
typedef NFSOperation <READDIR3args,     NULLres>    NFSPROC3_READDIR;
typedef NFSOperation <READDIRPLUS3args, NULLres>    NFSPROC3_READDIRPLUS;
typedef NFSOperation <FSSTAT3args,      NULLres>    NFSPROC3_FSSTAT;
typedef NFSOperation <FSINFO3args,      NULLres>    NFSPROC3_FSINFO;
typedef NFSOperation <PATHCONF3args,    NULLres>    NFSPROC3_PATHCONF;
typedef NFSOperation <COMMIT3args,      NULLres>    NFSPROC3_COMMIT;

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_OPERATION_H
//------------------------------------------------------------------------------
