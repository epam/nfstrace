//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: IAnalyzer describe interface of analysiss expected by application.
// The interface define set of NFS Procedure handlers with empty dummy implementation
// and pure virtual function for flushing analysis statistics.
// Copyright (c) 2013 EPAM Systems
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
#ifndef IANALYZER_TYPE_H
#define IANALYZER_TYPE_H
//------------------------------------------------------------------------------
#include "nfs_types.h"
#include "nfs3_types_rpcgen.h"
#include "nfs4_types_rpcgen.h"
#include "rpc_procedure.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

class INFSv3rpcgen
{
public:
    virtual void null(const struct RPCProcedure*,
            const struct NFS3::NULL3args*,
            const struct NFS3::NULL3res*) {}
    virtual void getattr3(const struct RPCProcedure*,
            const struct NFS3::GETATTR3args*,
            const struct NFS3::GETATTR3res*) {}
    virtual void setattr3(const struct RPCProcedure*,
            const struct NFS3::SETATTR3args*,
            const struct NFS3::SETATTR3res*) {}
    virtual void lookup3(const struct RPCProcedure*,
            const struct NFS3::LOOKUP3args*,
            const struct NFS3::LOOKUP3res*) {}
    virtual void access3(const struct RPCProcedure*,
            const struct NFS3::ACCESS3args*,
            const struct NFS3::ACCESS3res*) {}
    virtual void readlink3(const struct RPCProcedure*,
            const struct NFS3::READLINK3args*,
            const struct NFS3::READLINK3res*) {}
    virtual void read3(const struct RPCProcedure*,
            const struct NFS3::READ3args*,
            const struct NFS3::READ3res*) {}
    virtual void write3(const struct RPCProcedure*,
            const struct NFS3::WRITE3args*,
            const struct NFS3::WRITE3res*) {}
    virtual void create3(const struct RPCProcedure*,
            const struct NFS3::CREATE3args*,
            const struct NFS3::CREATE3res*) {}
    virtual void mkdir3(const struct RPCProcedure*,
            const struct NFS3::MKDIR3args*,
            const struct NFS3::MKDIR3res*) {}
    virtual void symlink3(const struct RPCProcedure*,
            const struct NFS3::SYMLINK3args*,
            const struct NFS3::SYMLINK3res*) {}
    virtual void mknod3(const struct RPCProcedure*,
            const struct NFS3::MKNOD3args*,
            const struct NFS3::MKNOD3res*) {}
    virtual void remove3(const struct RPCProcedure*,
            const struct NFS3::REMOVE3args*,
            const struct NFS3::REMOVE3res*) {}
    virtual void rmdir3(const struct RPCProcedure*,
            const struct NFS3::RMDIR3args*,
            const struct NFS3::RMDIR3res*) {}
    virtual void rename3(const struct RPCProcedure*,
            const struct NFS3::RENAME3args*,
            const struct NFS3::RENAME3res*) {}
    virtual void link3(const struct RPCProcedure*,
            const struct NFS3::LINK3args*,
            const struct NFS3::LINK3res*) {}
    virtual void readdir3(const struct RPCProcedure*,
            const struct NFS3::READDIR3args*,
            const struct NFS3::READDIR3res*) {}
    virtual void readdirplus3(const struct RPCProcedure*,
            const struct NFS3::READDIRPLUS3args*,
            const struct NFS3::READDIRPLUS3res*) {}
    virtual void fsstat3(const struct RPCProcedure*,
            const struct NFS3::FSSTAT3args*,
            const struct NFS3::FSSTAT3res*) {}
    virtual void fsinfo3(const struct RPCProcedure*,
            const struct NFS3::FSINFO3args*,
            const struct NFS3::FSINFO3res*) {}
    virtual void pathconf3(const struct RPCProcedure*,
            const struct NFS3::PATHCONF3args*,
            const struct NFS3::PATHCONF3res*) {}
    virtual void commit3(const struct RPCProcedure*,
            const struct NFS3::COMMIT3args*,
            const struct NFS3::COMMIT3res*) {}
};

class INFSv4rpcgen
{
public:
    virtual void null(const struct RPCProcedure*,
            const struct NFS4::NULL4args*,
            const struct NFS4::NULL4res*) {}
    virtual void compound4(const struct RPCProcedure*,
            const struct NFS4::COMPOUND4args*,
            const struct NFS4::COMPOUND4res*) {}
};

class IAnalyzer : public INFSv3rpcgen, public INFSv4rpcgen
{
public:
    virtual ~IAnalyzer() {};
    virtual void flush_statistics() = 0;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//IANALYZER_TYPE_H
//------------------------------------------------------------------------------
