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
    /*! "Close file" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void closeFileSMBv2(const SMBv2::CloseFileCommand *, const SMBv2::CloseFileArgumentType &, const SMBv2::CloseFileResultType &) {}

    /*! "Negotiate" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void negotiateSMBv2(const SMBv2::NegotiateCommand *, const SMBv2::NegotiateArgumentType &, const SMBv2::NegotiateResultType &) {}

    /*! "session setup" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void sessionSetupSMBv2(const SMBv2::SessionSetupCommand *, const SMBv2::SessionSetupArgumentType &, const SMBv2::SessionSetupResultType &) {}

    /*! "log off" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void logOffSMBv2(const SMBv2::CloseFileCommand *, const SMBv2::CloseFileArgumentType &, const SMBv2::CloseFileResultType &) {}

    /*! "Tree Connect" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeConnectSMBv2(const SMBv2::TreeConnectCommand *, const SMBv2::TreeConnectArgumentType &, const SMBv2::TreeConnectResultType &) {}

    /*! "Tree disconnect" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeDisconnectSMBv2(const SMBv2::TreeDisconnectCommand *, const SMBv2::TreeDisconnectArgumentType &, const SMBv2::TreeDisconnectResultType &) {}

    /*! "Create" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createSMBv2(const SMBv2::CreateCommand *, const SMBv2::CreateArgumentType &, const SMBv2::CreateResultType &) {}

    /*! "Flush" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void flushSMBv2(const SMBv2::FlushCommand *, const SMBv2::FlushArgumentType &, const SMBv2::FlushResultType &) {}

    /*! "Read" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readSMBv2(const SMBv2::ReadCommand *, const SMBv2::ReadArgumentType &, const SMBv2::ReadResultType &) {}

    /*! "Write" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeSMBv2(const SMBv2::WriteCommand *, const SMBv2::WriteArgumentType &, const SMBv2::WriteResultType &) {}

    /*! "Lock" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void lockSMBv2(const SMBv2::LockCommand *, const SMBv2::LockArgumentType &, const SMBv2::LockResultType &) {}

    /*! "IO ctl" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ioctlSMBv2(const SMBv2::IoctlCommand *, const SMBv2::IoctlArgumentType &, const SMBv2::IoctlResultType &) {}

    /*! "Cancel" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void cancelSMBv2(const SMBv2::CancelCommand *, const SMBv2::CancelArgumentType &, const SMBv2::CancelResultType &) {}

    /*! "Echo" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void echoSMBv2(const SMBv2::EchoCommand *, const SMBv2::EchoArgumentType &, const SMBv2::EchoResultType &) {}

    /*! "Query directory" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryDirSMBv2(const SMBv2::QueryDirCommand *, const SMBv2::QueryDirArgumentType &, const SMBv2::QueryDirResultType &) {}

    /*! "Change notify" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void changeNotifySMBv2(const SMBv2::ChangeNotifyCommand *, const SMBv2::ChangeNotifyArgumentType &, const SMBv2::ChangeNotifyResultType &) {}

    /*! "Query Info" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryInfoSMBv2(const SMBv2::QueryInfoCommand *, const SMBv2::QueryInfoArgumentType &, const SMBv2::QueryInfoResultType &) {}

    /*! "Set Info" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void setInfoSMBv2(const SMBv2::SetInfoCommand *, const SMBv2::SetInfoArgumentType &, const SMBv2::SetInfoResultType &) {}

    /*! "Break opportunistic lock" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void breakOplockSMBv2(const SMBv2::BreakOpLockCommand *, const SMBv2::BreakOpLockArgumentType &, const SMBv2::BreakOpLockResultType &) {}
};

class IAnalyzer : public INFSv3rpcgen, public INFSv4rpcgen, public ISMBv1, public ISMBv2
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
