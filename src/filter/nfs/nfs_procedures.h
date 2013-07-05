//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Enumeration of the NFS procedures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PROCEDURES_H
#define NFS_PROCEDURES_H
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

    static const char* titles[num];
};

} // namespace NFS3
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PROCEDURES_H
//------------------------------------------------------------------------------
