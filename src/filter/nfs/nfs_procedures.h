//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Enumeration of the NFS procedures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PROCEDURE_H
#define NFS_PROCEDURE_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace NFS3
{

struct Proc // counters definition for NFS v3 procedures. See: RFC 1813
{
    enum Ops
    {
        NFS_NULL        = 0,
        NFS_GETATTR     = 1,
        NFS_SETATTR     = 2,
        NFS_LOOKUP      = 3,
        NFS_ACCESS      = 4,
        NFS_READLINK    = 5,
        NFS_READ        = 6,
        NFS_WRITE       = 7,
        NFS_CREATE      = 8,
        NFS_MKDIR       = 9,
        NFS_SYMLINK     = 10,
        NFS_MKNOD       = 11,
        NFS_REMOVE      = 12,
        NFS_RMDIR       = 13,
        NFS_RENAME      = 14,
        NFS_LINK        = 15,
        NFS_READDIR     = 16,
        NFS_READDIRPLUS = 17,
        NFS_FSSTAT      = 18,
        NFS_FSINFO      = 19,
        NFS_PATHCONF    = 20,
        NFS_COMMIT      = 21,
        num             = 22
    };

    static const char* titles[num];
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PROCEDURE_H
//------------------------------------------------------------------------------
