//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: BaseAnalyzer describe interface expected by nst.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BASE_ANALYZER2_H
#define BASE_ANALYZER2_H
//------------------------------------------------------------------------------
#include "rpc_types.h"
#include "nfs3_types.h"
#include "session_type.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

class BaseAnalyzer2
{
public:
    BaseAnalyzer2() {};
    virtual ~BaseAnalyzer2() {};
    
    virtual void null(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct NULLArgs*,
            const struct NULLRes*) {}
    virtual void getattr3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct GETATTR3Args*,
            const struct GETATTR3Res*) {}
    virtual void setattr3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct SETATTR3Args*,
            const struct SETATTR3Res*) {}
    virtual void lookup3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct LOOKUP3Args*,
            const struct LOOKUP3Res*) {}
    virtual void access3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct ACCESS3Args*,
            const struct ACCESS3Res*) {}
    virtual void readlink3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct READLINK3Args*,
            const struct READLINK3Res*) {}
    virtual void read3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct READ3Args*,
            const struct READ3Res*) {}
    virtual void write3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct WRITE3Args*,
            const struct WRITE3Res*) {}
    virtual void create3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct CREATE3Args*,
            const struct CREATE3Res*) {}
    virtual void mkdir3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct MKDIR3Args*,
            const struct MKDIR3Res*) {}
    virtual void symlink3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct SYMLINK3Args*,
            const struct SYMLINK3Res*) {}
    virtual void mknod3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct MKNOD3Args*,
            const struct MKNOD3Res*) {}
    virtual void remove3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct REMOVE3Args*,
            const struct REMOVE3Res*) {}
    virtual void rmdir3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct RMDIR3Args*,
            const struct RMDIR3Res*) {}
    virtual void rename3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct RENAME3Args*,
            const struct RENAME3Res*) {}
    virtual void link3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct LINK3Args*,
            const struct LINK3Res*) {}
    virtual void readdir3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct READDIR3Args*,
            const struct READDIR3Res*) {}
    virtual void readdirplus3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct READDIRPLUS3Args*,
            const struct READDIRPLUS3Res*) {}
    virtual void fsstat3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct FSSTAT3Args*,
            const struct FSSTAT3Res*) {}
    virtual void fsinfo3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct FSINFO3Args*,
            const struct FSINFO3Res*) {}
    virtual void pathconf3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct PATHCONF3Args*,
            const struct PATHCONF3Res*) {}
    virtual void commit3(const struct Session&,
            const struct RPCCall&,
            const struct RPCReply&,
            const struct COMMIT3Args*,
            const struct COMMIT3Res*) {}

    virtual const char* usage() = 0;
};

} // extern "C"
//------------------------------------------------------------------------------
#endif //BASE_ANALYZER2_H
//------------------------------------------------------------------------------
