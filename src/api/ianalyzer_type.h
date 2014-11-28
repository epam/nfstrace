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

    /*! SMBv1 "CreateDirectory" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createDirectorySMBv1(const SMBv1::CreateDirectoryCommand*, const SMBv1::CreateDirectoryArgumentType, const SMBv1::CreateDirectoryResultType) {}

    /*! SMBv1 "DeleteDirectory" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void deleteDirectorySMBv1(const SMBv1::DeleteDirectoryCommand*, const SMBv1::DeleteDirectoryArgumentType, const SMBv1::DeleteDirectoryResultType) {}

    /*! SMBv1 "Open" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void openSMBv1(const SMBv1::OpenCommand*, const SMBv1::OpenArgumentType, const SMBv1::OpenResultType) {}

    /*! SMBv1 "Create" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createSMBv1(const SMBv1::CreateCommand*, const SMBv1::CreateArgumentType, const SMBv1::CreateResultType) {}

    /*! SMBv1 "Close" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void closeSMBv1(const SMBv1::CloseCommand*, const SMBv1::CloseArgumentType, const SMBv1::CloseResultType) {}

    /*! SMBv1 "Flush" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void flushSMBv1(const SMBv1::FlushCommand*, const SMBv1::FlushArgumentType, const SMBv1::FlushResultType) {}

    /*! SMBv1 "Delete" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void deleteSMBv1(const SMBv1::DeleteCommand*, const SMBv1::DeleteArgumentType, const SMBv1::DeleteResultType) {}

    /*! SMBv1 "Rename" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void renameSMBv1(const SMBv1::RenameCommand*, const SMBv1::RenameArgumentType, const SMBv1::RenameResultType) {}

    /*! SMBv1 "QueryInformation" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryInfoSMBv1(const SMBv1::QueryInformationCommand*, const SMBv1::QueryInformationArgumentType, const SMBv1::QueryInformationResultType) {}

    /*! SMBv1 "SetInformation" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void setInfoSMBv1(const SMBv1::SetInformationCommand*, const SMBv1::SetInformationArgumentType, const SMBv1::SetInformationResultType) {}

    /*! SMBv1 "Read" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readSMBv1(const SMBv1::ReadCommand*, const SMBv1::ReadArgumentType, const SMBv1::ReadResultType) {}

    /*! SMBv1 "Write" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeSMBv1(const SMBv1::WriteCommand*, const SMBv1::WriteArgumentType, const SMBv1::WriteResultType) {}

    /*! SMBv1 "LockByteRange" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void lockByteRangeSMBv1(const SMBv1::LockByteRangeCommand*, const SMBv1::LockByteRangeArgumentType, const SMBv1::LockByteRangeResultType) {}

    /*! SMBv1 "UnlockByteRange" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void unlockByteRangeSMBv1(const SMBv1::UnlockByteRangeCommand*, const SMBv1::UnlockByteRangeArgumentType, const SMBv1::UnlockByteRangeResultType) {}

    /*! SMBv1 "CreateTemporary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createTmpSMBv1(const SMBv1::CreateTemporaryCommand*, const SMBv1::CreateTemporaryArgumentType, const SMBv1::CreateTemporaryResultType) {}

    /*! SMBv1 "CreateNew" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createNewSMBv1(const SMBv1::CreateNewCommand*, const SMBv1::CreateNewArgumentType, const SMBv1::CreateNewResultType) {}

    /*! SMBv1 "CheckDirectory" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void checkDirectorySMBv1(const SMBv1::CheckDirectoryCommand*, const SMBv1::CheckDirectoryArgumentType, const SMBv1::CheckDirectoryResultType) {}

    /*! SMBv1 "ProcessExit" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void processExitSMBv1(const SMBv1::ProcessExitCommand*, const SMBv1::ProcessExitArgumentType, const SMBv1::ProcessExitResultType) {}

    /*! SMBv1 "Seek" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void seekSMBv1(const SMBv1::SeekCommand*, const SMBv1::SeekArgumentType, const SMBv1::SeekResultType) {}

    /*! SMBv1 "LockAndRead" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void lockAndReadSMBv1(const SMBv1::LockAndReadCommand*, const SMBv1::LockAndReadArgumentType, const SMBv1::LockAndReadResultType) {}

    /*! SMBv1 "WriteAndUnlock" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeAndUnlockSMBv1(const SMBv1::WriteAndUnlockCommand*, const SMBv1::WriteAndUnlockArgumentType, const SMBv1::WriteAndUnlockResultType) {}

    /*! SMBv1 "ReadRaw" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readRawSMBv1(const SMBv1::ReadRawCommand*, const SMBv1::ReadRawArgumentType, const SMBv1::ReadRawResultType) {}

    /*! SMBv1 "ReadMpx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readMpxSMBv1(const SMBv1::ReadMpxCommand*, const SMBv1::ReadMpxArgumentType, const SMBv1::ReadMpxResultType) {}

    /*! SMBv1 "ReadMpxSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readMpxSecondarySMBv1(const SMBv1::ReadMpxSecondaryCommand*, const SMBv1::ReadMpxSecondaryArgumentType, const SMBv1::ReadMpxSecondaryResultType) {}

    /*! SMBv1 "WriteRaw" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeRawSMBv1(const SMBv1::WriteRawCommand*, const SMBv1::WriteRawArgumentType, const SMBv1::WriteRawResultType) {}

    /*! SMBv1 "WriteMpx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeMpxSMBv1(const SMBv1::WriteMpxCommand*, const SMBv1::WriteMpxArgumentType, const SMBv1::WriteMpxResultType) {}

    /*! SMBv1 "WriteMpxSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeMpxSecondarySMBv1(const SMBv1::WriteMpxSecondaryCommand*, const SMBv1::WriteMpxSecondaryArgumentType, const SMBv1::WriteMpxSecondaryResultType) {}

    /*! SMBv1 "WriteComplete" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeCompleteSMBv1(const SMBv1::WriteCompleteCommand*, const SMBv1::WriteCompleteArgumentType, const SMBv1::WriteCompleteResultType) {}

    /*! SMBv1 "QueryServer" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryServerSMBv1(const SMBv1::QueryServerCommand*, const SMBv1::QueryServerArgumentType, const SMBv1::QueryServerResultType) {}

    /*! SMBv1 "SetInformation2" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void setInfo2SMBv1(const SMBv1::SetInformation2Command*, const SMBv1::SetInformation2ArgumentType, const SMBv1::SetInformation2ResultType) {}

    /*! SMBv1 "QueryInformation2" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryInfo2SMBv1(const SMBv1::QueryInformation2Command*, const SMBv1::QueryInformation2ArgumentType, const SMBv1::QueryInformation2ResultType) {}

    /*! SMBv1 "LockingAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void lockingAndxSMBv1(const SMBv1::LockingAndxCommand*, const SMBv1::LockingAndxArgumentType, const SMBv1::LockingAndxResultType) {}

    /*! SMBv1 "Transaction" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void transactionSMBv1(const SMBv1::TransactionCommand*, const SMBv1::TransactionArgumentType, const SMBv1::TransactionResultType) {}

    /*! SMBv1 "TransactionSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void transactionSecondarySMBv1(const SMBv1::TransactionSecondaryCommand*, const SMBv1::TransactionSecondaryArgumentType, const SMBv1::TransactionSecondaryResultType) {}

    /*! SMBv1 "Ioctl" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ioctlSMBv1(const SMBv1::IoctlCommand*, const SMBv1::IoctlArgumentType, const SMBv1::IoctlResultType) {}

    /*! SMBv1 "IoctlSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ioctlSecondarySMBv1(const SMBv1::IoctlSecondaryCommand*, const SMBv1::IoctlSecondaryArgumentType, const SMBv1::IoctlSecondaryResultType) {}

    /*! SMBv1 "Copy" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void copySMBv1(const SMBv1::CopyCommand*, const SMBv1::CopyArgumentType, const SMBv1::CopyResultType) {}

    /*! SMBv1 "Move" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void moveSMBv1(const SMBv1::MoveCommand*, const SMBv1::MoveArgumentType, const SMBv1::MoveResultType) {}

    /*! SMBv1 "Echo" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void echoSMBv1(const SMBv1::EchoCommand*, const SMBv1::EchoArgumentType, const SMBv1::EchoResultType) {}

    /*! SMBv1 "WriteAndClose" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeAndCloseSMBv1(const SMBv1::WriteAndCloseCommand*, const SMBv1::WriteAndCloseArgumentType, const SMBv1::WriteAndCloseResultType) {}

    /*! SMBv1 "OpenAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void openAndxSMBv1(const SMBv1::OpenAndxCommand*, const SMBv1::OpenAndxArgumentType, const SMBv1::OpenAndxResultType) {}

    /*! SMBv1 "ReadAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readAndxSMBv1(const SMBv1::ReadAndxCommand*, const SMBv1::ReadAndxArgumentType, const SMBv1::ReadAndxResultType) {}

    /*! SMBv1 "WriteAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeAndxSMBv1(const SMBv1::WriteAndxCommand*, const SMBv1::WriteAndxArgumentType, const SMBv1::WriteAndxResultType) {}

    /*! SMBv1 "NewFileSize" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void newFileSizeSMBv1(const SMBv1::NewFileSizeCommand*, const SMBv1::NewFileSizeArgumentType, const SMBv1::NewFileSizeResultType) {}

    /*! SMBv1 "CloseAndTreeDisc" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void closeAndTreeDiscSMBv1(const SMBv1::CloseAndTreeDiscCommand*, const SMBv1::CloseAndTreeDiscArgumentType, const SMBv1::CloseAndTreeDiscResultType) {}

    /*! SMBv1 "Transaction2" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void transaction2SMBv1(const SMBv1::Transaction2Command*, const SMBv1::Transaction2ArgumentType, const SMBv1::Transaction2ResultType) {}

    /*! SMBv1 "Transaction2Secondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void transaction2SecondarySMBv1(const SMBv1::Transaction2SecondaryCommand*, const SMBv1::Transaction2SecondaryArgumentType, const SMBv1::Transaction2SecondaryResultType) {}

    /*! SMBv1 "FindClose2" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findClose2SMBv1(const SMBv1::FindClose2Command*, const SMBv1::FindClose2ArgumentType, const SMBv1::FindClose2ResultType) {}

    /*! SMBv1 "FindNotifyClose" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findNotifyCloseSMBv1(const SMBv1::FindNotifyCloseCommand*, const SMBv1::FindNotifyCloseArgumentType, const SMBv1::FindNotifyCloseResultType) {}

    /*! SMBv1 "TreeConnect" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeConnectSMBv1(const SMBv1::TreeConnectCommand*, const SMBv1::TreeConnectArgumentType, const SMBv1::TreeConnectResultType) {}

    /*! SMBv1 "TreeDisconnect" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeDisconnectSMBv1(const SMBv1::TreeDisconnectCommand*, const SMBv1::TreeDisconnectArgumentType, const SMBv1::TreeDisconnectResultType) {}

    /*! SMBv1 "Negotiate" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void negotiateSMBv1(const SMBv1::NegotiateCommand*, const SMBv1::NegotiateArgumentType, const SMBv1::NegotiateResultType) {}

    /*! SMBv1 "SessionSetupAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void sessionSetupAndxSMBv1(const SMBv1::SessionSetupAndxCommand*, const SMBv1::SessionSetupAndxArgumentType, const SMBv1::SessionSetupAndxResultType) {}

    /*! SMBv1 "LogoffAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void logoffAndxSMBv1(const SMBv1::LogoffAndxCommand*, const SMBv1::LogoffAndxArgumentType, const SMBv1::LogoffAndxResultType) {}

    /*! SMBv1 "TreeConnectAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeConnectAndxSMBv1(const SMBv1::TreeConnectAndxCommand*, const SMBv1::TreeConnectAndxArgumentType, const SMBv1::TreeConnectAndxResultType) {}

    /*! SMBv1 "SecurityPackageAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void securityPackageAndxSMBv1(const SMBv1::SecurityPackageAndxCommand*, const SMBv1::SecurityPackageAndxArgumentType, const SMBv1::SecurityPackageAndxResultType) {}

    /*! SMBv1 "QueryInformationDisk" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryInformationDiskSMBv1(const SMBv1::QueryInformationDiskCommand*, const SMBv1::QueryInformationDiskArgumentType, const SMBv1::QueryInformationDiskResultType) {}

    /*! SMBv1 "Search" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void searchSMBv1(const SMBv1::SearchCommand*, const SMBv1::SearchArgumentType, const SMBv1::SearchResultType) {}

    /*! SMBv1 "Find" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findSMBv1(const SMBv1::FindCommand*, const SMBv1::FindArgumentType, const SMBv1::FindResultType) {}

    /*! SMBv1 "FindUnique" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findUniqueSMBv1(const SMBv1::FindUniqueCommand*, const SMBv1::FindUniqueArgumentType, const SMBv1::FindUniqueResultType) {}

    /*! SMBv1 "FindClose" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findCloseSMBv1(const SMBv1::FindCloseCommand*, const SMBv1::FindCloseArgumentType, const SMBv1::FindCloseResultType) {}

    /*! SMBv1 "NtTransact" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntTransactSMBv1(const SMBv1::NtTransactCommand*, const SMBv1::NtTransactArgumentType, const SMBv1::NtTransactResultType) {}

    /*! SMBv1 "NtTransactSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntTransactSecondarySMBv1(const SMBv1::NtTransactSecondaryCommand*, const SMBv1::NtTransactSecondaryArgumentType, const SMBv1::NtTransactSecondaryResultType) {}

    /*! SMBv1 "NtCreateAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntCreateAndxSMBv1(const SMBv1::NtCreateAndxCommand*, const SMBv1::NtCreateAndxArgumentType, const SMBv1::NtCreateAndxResultType) {}

    /*! SMBv1 "NtCancel" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntCancelSMBv1(const SMBv1::NtCancelCommand*, const SMBv1::NtCancelArgumentType, const SMBv1::NtCancelResultType) {}

    /*! SMBv1 "NtRename" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntRenameSMBv1(const SMBv1::NtRenameCommand*, const SMBv1::NtRenameArgumentType, const SMBv1::NtRenameResultType) {}

    /*! SMBv1 "OpenPrintFile" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void openPrintFileSMBv1(const SMBv1::OpenPrintFileCommand*, const SMBv1::OpenPrintFileArgumentType, const SMBv1::OpenPrintFileResultType) {}

    /*! SMBv1 "WritePrintFile" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writePrintFileSMBv1(const SMBv1::WritePrintFileCommand*, const SMBv1::WritePrintFileArgumentType, const SMBv1::WritePrintFileResultType) {}

    /*! SMBv1 "ClosePrintFile" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void closePrintFileSMBv1(const SMBv1::ClosePrintFileCommand*, const SMBv1::ClosePrintFileArgumentType, const SMBv1::ClosePrintFileResultType) {}

    /*! SMBv1 "GetPrintQueue" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void getPrintQueueSMBv1(const SMBv1::GetPrintQueueCommand*, const SMBv1::GetPrintQueueArgumentType, const SMBv1::GetPrintQueueResultType) {}

    /*! SMBv1 "ReadBulk" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readBulkSMBv1(const SMBv1::ReadBulkCommand*, const SMBv1::ReadBulkArgumentType, const SMBv1::ReadBulkResultType) {}

    /*! SMBv1 "WriteBulk" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeBulkSMBv1(const SMBv1::WriteBulkCommand*, const SMBv1::WriteBulkArgumentType, const SMBv1::WriteBulkResultType) {}

    /*! SMBv1 "WriteBulkData" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeBulkDataSMBv1(const SMBv1::WriteBulkDataCommand*, const SMBv1::WriteBulkDataArgumentType, const SMBv1::WriteBulkDataResultType) {}

    /*! SMBv1 "Invalid" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void invalidSMBv1(const SMBv1::InvalidCommand*, const SMBv1::InvalidArgumentType, const SMBv1::InvalidResultType) {}

    /*! SMBv1 "NoAndxCommand" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void noAndxCommandSMBv1(const SMBv1::NoAndxCommand*, const SMBv1::NoAndxCmdArgumentType, const SMBv1::NoAndxCmdResultType) {}
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
    virtual void logOffSMBv2(const SMBv2::LogOffCommand *, const SMBv2::LogOffArgumentType &, const SMBv2::LogOffResultType &) {}

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
