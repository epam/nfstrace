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
#include "cifs_types.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

class INFSv3rpcgen
{
public:
    virtual void null(const struct RPCProcedure*,
            const struct rpcgen::NULL3args*,
            const struct rpcgen::NULL3res*) {}
    virtual void getattr3(const struct RPCProcedure*,
            const struct rpcgen::GETATTR3args*,
            const struct rpcgen::GETATTR3res*) {}
    virtual void setattr3(const struct RPCProcedure*,
            const struct rpcgen::SETATTR3args*,
            const struct rpcgen::SETATTR3res*) {}
    virtual void lookup3(const struct RPCProcedure*,
            const struct rpcgen::LOOKUP3args*,
            const struct rpcgen::LOOKUP3res*) {}
    virtual void access3(const struct RPCProcedure*,
            const struct rpcgen::ACCESS3args*,
            const struct rpcgen::ACCESS3res*) {}
    virtual void readlink3(const struct RPCProcedure*,
            const struct rpcgen::READLINK3args*,
            const struct rpcgen::READLINK3res*) {}
    virtual void read3(const struct RPCProcedure*,
            const struct rpcgen::READ3args*,
            const struct rpcgen::READ3res*) {}
    virtual void write3(const struct RPCProcedure*,
            const struct rpcgen::WRITE3args*,
            const struct rpcgen::WRITE3res*) {}
    virtual void create3(const struct RPCProcedure*,
            const struct rpcgen::CREATE3args*,
            const struct rpcgen::CREATE3res*) {}
    virtual void mkdir3(const struct RPCProcedure*,
            const struct rpcgen::MKDIR3args*,
            const struct rpcgen::MKDIR3res*) {}
    virtual void symlink3(const struct RPCProcedure*,
            const struct rpcgen::SYMLINK3args*,
            const struct rpcgen::SYMLINK3res*) {}
    virtual void mknod3(const struct RPCProcedure*,
            const struct rpcgen::MKNOD3args*,
            const struct rpcgen::MKNOD3res*) {}
    virtual void remove3(const struct RPCProcedure*,
            const struct rpcgen::REMOVE3args*,
            const struct rpcgen::REMOVE3res*) {}
    virtual void rmdir3(const struct RPCProcedure*,
            const struct rpcgen::RMDIR3args*,
            const struct rpcgen::RMDIR3res*) {}
    virtual void rename3(const struct RPCProcedure*,
            const struct rpcgen::RENAME3args*,
            const struct rpcgen::RENAME3res*) {}
    virtual void link3(const struct RPCProcedure*,
            const struct rpcgen::LINK3args*,
            const struct rpcgen::LINK3res*) {}
    virtual void readdir3(const struct RPCProcedure*,
            const struct rpcgen::READDIR3args*,
            const struct rpcgen::READDIR3res*) {}
    virtual void readdirplus3(const struct RPCProcedure*,
            const struct rpcgen::READDIRPLUS3args*,
            const struct rpcgen::READDIRPLUS3res*) {}
    virtual void fsstat3(const struct RPCProcedure*,
            const struct rpcgen::FSSTAT3args*,
            const struct rpcgen::FSSTAT3res*) {}
    virtual void fsinfo3(const struct RPCProcedure*,
            const struct rpcgen::FSINFO3args*,
            const struct rpcgen::FSINFO3res*) {}
    virtual void pathconf3(const struct RPCProcedure*,
            const struct rpcgen::PATHCONF3args*,
            const struct rpcgen::PATHCONF3res*) {}
    virtual void commit3(const struct RPCProcedure*,
            const struct rpcgen::COMMIT3args*,
            const struct rpcgen::COMMIT3res*) {}
};

class INFSv4rpcgen
{
public:
    virtual void null(const struct RPCProcedure*,
            const struct rpcgen::NULL4args*,
            const struct rpcgen::NULL4res*) {}
    virtual void compound4(const struct RPCProcedure*,
            const struct rpcgen::COMPOUND4args*,
            const struct rpcgen::COMPOUND4res*) {}
};

/*! Abstract interface of plugin which collects SMBv1 statistic
 */
class ISMBv1
{
public:
    /*! SMBv1 echo request "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void echoRequest(const SMBv1::EchoRequestCommand *, const SMBv1::EchoRequestArgumentType &, const SMBv1::EchoRequestResultType &) {}

    /*! SMBv1 "Close file" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void closeFile(const SMBv1::CloseFileCommand *, const SMBv1::CloseFileArgumentType &, const SMBv1::CloseFileResultType &) {}
};

/*! Abstract interface of plugin which collects SMBv2 statistic
 */
class ISMBv2
{
public:
    /*! SMBv2 command "on receive" event handler
     * \param cmd - command
     */
    virtual void command(const SMBv2::Command* /*cmd*/, const void* const, const void* const) {}
};

class IAnalyzer : public INFSv3rpcgen, public INFSv4rpcgen, public ISMBv1
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
