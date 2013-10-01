//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: IAnalyzer describe interface of analyzers expected by application.
// The interface define set of NFSv3 Procedure handlers with empty dummy implementation
// and pure virtual function for flushing analyzer statistics.
// Copyright (c) 2013 EPAM Systems. All Rights reserved.
//------------------------------------------------------------------------------
#ifndef IANALYZER_TYPE_H
#define IANALYZER_TYPE_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

class IAnalyzer
{
public:
    virtual ~IAnalyzer() {};

    virtual void null(const struct RPCProcedure*,
            const struct NULLargs*,
            const struct NULLres*) {}
    virtual void getattr3(const struct RPCProcedure*,
            const struct GETATTR3args*,
            const struct GETATTR3res*) {}
    virtual void setattr3(const struct RPCProcedure*,
            const struct SETATTR3args*,
            const struct SETATTR3res*) {}
    virtual void lookup3(const struct RPCProcedure*,
            const struct LOOKUP3args*,
            const struct LOOKUP3res*) {}
    virtual void access3(const struct RPCProcedure*,
            const struct ACCESS3args*,
            const struct ACCESS3res*) {}
    virtual void readlink3(const struct RPCProcedure*,
            const struct READLINK3args*,
            const struct READLINK3res*) {}
    virtual void read3(const struct RPCProcedure*,
            const struct READ3args*,
            const struct READ3res*) {}
    virtual void write3(const struct RPCProcedure*,
            const struct WRITE3args*,
            const struct WRITE3res*) {}
    virtual void create3(const struct RPCProcedure*,
            const struct CREATE3args*,
            const struct CREATE3res*) {}
    virtual void mkdir3(const struct RPCProcedure*,
            const struct MKDIR3args*,
            const struct MKDIR3res*) {}
    virtual void symlink3(const struct RPCProcedure*,
            const struct SYMLINK3args*,
            const struct SYMLINK3res*) {}
    virtual void mknod3(const struct RPCProcedure*,
            const struct MKNOD3args*,
            const struct MKNOD3res*) {}
    virtual void remove3(const struct RPCProcedure*,
            const struct REMOVE3args*,
            const struct REMOVE3res*) {}
    virtual void rmdir3(const struct RPCProcedure*,
            const struct RMDIR3args*,
            const struct RMDIR3res*) {}
    virtual void rename3(const struct RPCProcedure*,
            const struct RENAME3args*,
            const struct RENAME3res*) {}
    virtual void link3(const struct RPCProcedure*,
            const struct LINK3args*,
            const struct LINK3res*) {}
    virtual void readdir3(const struct RPCProcedure*,
            const struct READDIR3args*,
            const struct READDIR3res*) {}
    virtual void readdirplus3(const struct RPCProcedure*,
            const struct READDIRPLUS3args*,
            const struct READDIRPLUS3res*) {}
    virtual void fsstat3(const struct RPCProcedure*,
            const struct FSSTAT3args*,
            const struct FSSTAT3res*) {}
    virtual void fsinfo3(const struct RPCProcedure*,
            const struct FSINFO3args*,
            const struct FSINFO3res*) {}
    virtual void pathconf3(const struct RPCProcedure*,
            const struct PATHCONF3args*,
            const struct PATHCONF3res*) {}
    virtual void commit3(const struct RPCProcedure*,
            const struct COMMIT3args*,
            const struct COMMIT3res*) {}

    virtual void flush_statistics() = 0;
};

}
//------------------------------------------------------------------------------
#endif //IANALYZER_TYPE_H
//------------------------------------------------------------------------------
