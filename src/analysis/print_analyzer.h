//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Created for demonstration purpose only.
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
#ifndef PRINT_ANALYZER_H
#define PRINT_ANALYZER_H
//------------------------------------------------------------------------------
#include <ostream>

#include "api/plugin_api.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

namespace NFS3  = NST::API::NFS3;
namespace NFS4  = NST::API::NFS4;
namespace NFS41 = NST::API::NFS41;

class PrintAnalyzer : public IAnalyzer
{
public:
    PrintAnalyzer(std::ostream& o) : out(o)
    {
    }
    ~PrintAnalyzer()
    {
    }

    void readSMBv2(const SMBv2::ReadCommand*,
                   const SMBv2::ReadRequest*,
                   const SMBv2::ReadResponse*) override final;
    void createDirectorySMBv1(const SMBv1::CreateDirectoryCommand*,
                              const SMBv1::CreateDirectoryArgumentType*,
                              const SMBv1::CreateDirectoryResultType*) override final;
    void deleteDirectorySMBv1(const SMBv1::DeleteDirectoryCommand*,
                              const SMBv1::DeleteDirectoryArgumentType*,
                              const SMBv1::DeleteDirectoryResultType*) override final;
    void openSMBv1(const SMBv1::OpenCommand*,
                   const SMBv1::OpenArgumentType*,
                   const SMBv1::OpenResultType*) override final;
    void createSMBv1(const SMBv1::CreateCommand*,
                     const SMBv1::CreateArgumentType*,
                     const SMBv1::CreateResultType*) override final;
    void closeSMBv1(const SMBv1::CloseCommand*,
                    const SMBv1::CloseArgumentType*,
                    const SMBv1::CloseResultType*) override final;
    void flushSMBv1(const SMBv1::FlushCommand*,
                    const SMBv1::FlushArgumentType*,
                    const SMBv1::FlushResultType*) override final;
    void deleteSMBv1(const SMBv1::DeleteCommand*,
                     const SMBv1::DeleteArgumentType*,
                     const SMBv1::DeleteResultType*) override final;
    void renameSMBv1(const SMBv1::RenameCommand*,
                     const SMBv1::RenameArgumentType*,
                     const SMBv1::RenameResultType*) override final;
    void queryInfoSMBv1(const SMBv1::QueryInformationCommand*,
                        const SMBv1::QueryInformationArgumentType*,
                        const SMBv1::QueryInformationResultType*) override final;
    void setInfoSMBv1(const SMBv1::SetInformationCommand*,
                      const SMBv1::SetInformationArgumentType*,
                      const SMBv1::SetInformationResultType*) override final;
    void readSMBv1(const SMBv1::ReadCommand*,
                   const SMBv1::ReadArgumentType*,
                   const SMBv1::ReadResultType*) override final;
    void writeSMBv1(const SMBv1::WriteCommand*,
                    const SMBv1::WriteArgumentType*,
                    const SMBv1::WriteResultType*) override final;
    void lockByteRangeSMBv1(const SMBv1::LockByteRangeCommand*,
                            const SMBv1::LockByteRangeArgumentType*,
                            const SMBv1::LockByteRangeResultType*) override final;
    void unlockByteRangeSMBv1(const SMBv1::UnlockByteRangeCommand*,
                              const SMBv1::UnlockByteRangeArgumentType*,
                              const SMBv1::UnlockByteRangeResultType*) override final;
    void createTmpSMBv1(const SMBv1::CreateTemporaryCommand*,
                        const SMBv1::CreateTemporaryArgumentType*,
                        const SMBv1::CreateTemporaryResultType*) override final;
    void createNewSMBv1(const SMBv1::CreateNewCommand*,
                        const SMBv1::CreateNewArgumentType*,
                        const SMBv1::CreateNewResultType*) override final;
    void checkDirectorySMBv1(const SMBv1::CheckDirectoryCommand*,
                             const SMBv1::CheckDirectoryArgumentType*,
                             const SMBv1::CheckDirectoryResultType*) override final;
    void processExitSMBv1(const SMBv1::ProcessExitCommand*,
                          const SMBv1::ProcessExitArgumentType*,
                          const SMBv1::ProcessExitResultType*) override final;
    void seekSMBv1(const SMBv1::SeekCommand*,
                   const SMBv1::SeekArgumentType*,
                   const SMBv1::SeekResultType*) override final;
    void lockAndReadSMBv1(const SMBv1::LockAndReadCommand*,
                          const SMBv1::LockAndReadArgumentType*,
                          const SMBv1::LockAndReadResultType*) override final;
    void writeAndUnlockSMBv1(const SMBv1::WriteAndUnlockCommand*,
                             const SMBv1::WriteAndUnlockArgumentType*,
                             const SMBv1::WriteAndUnlockResultType*) override final;
    void readRawSMBv1(const SMBv1::ReadRawCommand*,
                      const SMBv1::ReadRawArgumentType*,
                      const SMBv1::ReadRawResultType*) override final;
    void readMpxSMBv1(const SMBv1::ReadMpxCommand*,
                      const SMBv1::ReadMpxArgumentType*,
                      const SMBv1::ReadMpxResultType*) override final;
    void readMpxSecondarySMBv1(const SMBv1::ReadMpxSecondaryCommand*,
                               const SMBv1::ReadMpxSecondaryArgumentType*,
                               const SMBv1::ReadMpxSecondaryResultType*) override final;
    void writeRawSMBv1(const SMBv1::WriteRawCommand*,
                       const SMBv1::WriteRawArgumentType*,
                       const SMBv1::WriteRawResultType*) override final;
    void writeMpxSMBv1(const SMBv1::WriteMpxCommand*,
                       const SMBv1::WriteMpxArgumentType*,
                       const SMBv1::WriteMpxResultType*) override final;
    void writeMpxSecondarySMBv1(const SMBv1::WriteMpxSecondaryCommand*,
                                const SMBv1::WriteMpxSecondaryArgumentType*,
                                const SMBv1::WriteMpxSecondaryResultType*) override final;
    void writeCompleteSMBv1(const SMBv1::WriteCompleteCommand*,
                            const SMBv1::WriteCompleteArgumentType*,
                            const SMBv1::WriteCompleteResultType*) override final;
    void queryServerSMBv1(const SMBv1::QueryServerCommand*,
                          const SMBv1::QueryServerArgumentType*,
                          const SMBv1::QueryServerResultType*) override final;
    void setInfo2SMBv1(const SMBv1::SetInformation2Command*,
                       const SMBv1::SetInformation2ArgumentType*,
                       const SMBv1::SetInformation2ResultType*) override final;
    void queryInfo2SMBv1(const SMBv1::QueryInformation2Command*,
                         const SMBv1::QueryInformation2ArgumentType*,
                         const SMBv1::QueryInformation2ResultType*) override final;
    void lockingAndxSMBv1(const SMBv1::LockingAndxCommand*,
                          const SMBv1::LockingAndxArgumentType*,
                          const SMBv1::LockingAndxResultType*) override final;
    void transactionSMBv1(const SMBv1::TransactionCommand*,
                          const SMBv1::TransactionArgumentType*,
                          const SMBv1::TransactionResultType*) override final;
    void transactionSecondarySMBv1(const SMBv1::TransactionSecondaryCommand*,
                                   const SMBv1::TransactionSecondaryArgumentType*,
                                   const SMBv1::TransactionSecondaryResultType*) override final;
    void ioctlSMBv1(const SMBv1::IoctlCommand*,
                    const SMBv1::IoctlArgumentType*,
                    const SMBv1::IoctlResultType*) override final;
    void ioctlSecondarySMBv1(const SMBv1::IoctlSecondaryCommand*,
                             const SMBv1::IoctlSecondaryArgumentType*,
                             const SMBv1::IoctlSecondaryResultType*) override final;
    void copySMBv1(const SMBv1::CopyCommand*,
                   const SMBv1::CopyArgumentType*,
                   const SMBv1::CopyResultType*) override final;
    void moveSMBv1(const SMBv1::MoveCommand*,
                   const SMBv1::MoveArgumentType*,
                   const SMBv1::MoveResultType*) override final;
    void echoSMBv1(const SMBv1::EchoCommand*,
                   const SMBv1::EchoArgumentType*,
                   const SMBv1::EchoResultType*) override final;
    void writeAndCloseSMBv1(const SMBv1::WriteAndCloseCommand*,
                            const SMBv1::WriteAndCloseArgumentType*,
                            const SMBv1::WriteAndCloseResultType*) override final;
    void openAndxSMBv1(const SMBv1::OpenAndxCommand*,
                       const SMBv1::OpenAndxArgumentType*,
                       const SMBv1::OpenAndxResultType*) override final;
    void readAndxSMBv1(const SMBv1::ReadAndxCommand*,
                       const SMBv1::ReadAndxArgumentType*,
                       const SMBv1::ReadAndxResultType*) override final;
    void writeAndxSMBv1(const SMBv1::WriteAndxCommand*,
                        const SMBv1::WriteAndxArgumentType*,
                        const SMBv1::WriteAndxResultType*) override final;
    void newFileSizeSMBv1(const SMBv1::NewFileSizeCommand*,
                          const SMBv1::NewFileSizeArgumentType*,
                          const SMBv1::NewFileSizeResultType*) override final;
    void closeAndTreeDiscSMBv1(const SMBv1::CloseAndTreeDiscCommand*,
                               const SMBv1::CloseAndTreeDiscArgumentType*,
                               const SMBv1::CloseAndTreeDiscResultType*) override final;
    void transaction2SMBv1(const SMBv1::Transaction2Command*,
                           const SMBv1::Transaction2ArgumentType*,
                           const SMBv1::Transaction2ResultType*) override final;
    void transaction2SecondarySMBv1(const SMBv1::Transaction2SecondaryCommand*,
                                    const SMBv1::Transaction2SecondaryArgumentType*,
                                    const SMBv1::Transaction2SecondaryResultType*) override final;
    void findClose2SMBv1(const SMBv1::FindClose2Command*,
                         const SMBv1::FindClose2ArgumentType*,
                         const SMBv1::FindClose2ResultType*) override final;
    void findNotifyCloseSMBv1(const SMBv1::FindNotifyCloseCommand*,
                              const SMBv1::FindNotifyCloseArgumentType*,
                              const SMBv1::FindNotifyCloseResultType*) override final;
    void treeConnectSMBv1(const SMBv1::TreeConnectCommand*,
                          const SMBv1::TreeConnectArgumentType*,
                          const SMBv1::TreeConnectResultType*) override final;
    void treeDisconnectSMBv1(const SMBv1::TreeDisconnectCommand*,
                             const SMBv1::TreeDisconnectArgumentType*,
                             const SMBv1::TreeDisconnectResultType*) override final;
    void negotiateSMBv1(const SMBv1::NegotiateCommand*,
                        const SMBv1::NegotiateArgumentType*,
                        const SMBv1::NegotiateResultType*) override final;
    void sessionSetupAndxSMBv1(const SMBv1::SessionSetupAndxCommand*,
                               const SMBv1::SessionSetupAndxArgumentType*,
                               const SMBv1::SessionSetupAndxResultType*) override final;
    void logoffAndxSMBv1(const SMBv1::LogoffAndxCommand*,
                         const SMBv1::LogoffAndxArgumentType*,
                         const SMBv1::LogoffAndxResultType*) override final;
    void treeConnectAndxSMBv1(const SMBv1::TreeConnectAndxCommand*,
                              const SMBv1::TreeConnectAndxArgumentType*,
                              const SMBv1::TreeConnectAndxResultType*) override final;
    void securityPackageAndxSMBv1(const SMBv1::SecurityPackageAndxCommand*,
                                  const SMBv1::SecurityPackageAndxArgumentType*,
                                  const SMBv1::SecurityPackageAndxResultType*) override final;
    void queryInformationDiskSMBv1(const SMBv1::QueryInformationDiskCommand*,
                                   const SMBv1::QueryInformationDiskArgumentType*,
                                   const SMBv1::QueryInformationDiskResultType*) override final;
    void searchSMBv1(const SMBv1::SearchCommand*,
                     const SMBv1::SearchArgumentType*,
                     const SMBv1::SearchResultType*) override final;
    void findSMBv1(const SMBv1::FindCommand*,
                   const SMBv1::FindArgumentType*,
                   const SMBv1::FindResultType*) override final;
    void findUniqueSMBv1(const SMBv1::FindUniqueCommand*,
                         const SMBv1::FindUniqueArgumentType*,
                         const SMBv1::FindUniqueResultType*) override final;
    void findCloseSMBv1(const SMBv1::FindCloseCommand*,
                        const SMBv1::FindCloseArgumentType*,
                        const SMBv1::FindCloseResultType*) override final;
    void ntTransactSMBv1(const SMBv1::NtTransactCommand*,
                         const SMBv1::NtTransactArgumentType*,
                         const SMBv1::NtTransactResultType*) override final;
    void ntTransactSecondarySMBv1(const SMBv1::NtTransactSecondaryCommand*,
                                  const SMBv1::NtTransactSecondaryArgumentType*,
                                  const SMBv1::NtTransactSecondaryResultType*) override final;
    void ntCreateAndxSMBv1(const SMBv1::NtCreateAndxCommand*,
                           const SMBv1::NtCreateAndxArgumentType*,
                           const SMBv1::NtCreateAndxResultType*) override final;
    void ntCancelSMBv1(const SMBv1::NtCancelCommand*,
                       const SMBv1::NtCancelArgumentType*,
                       const SMBv1::NtCancelResultType*) override final;
    void ntRenameSMBv1(const SMBv1::NtRenameCommand*,
                       const SMBv1::NtRenameArgumentType*,
                       const SMBv1::NtRenameResultType*) override final;
    void openPrintFileSMBv1(const SMBv1::OpenPrintFileCommand*,
                            const SMBv1::OpenPrintFileArgumentType*,
                            const SMBv1::OpenPrintFileResultType*) override final;
    void writePrintFileSMBv1(const SMBv1::WritePrintFileCommand*,
                             const SMBv1::WritePrintFileArgumentType*,
                             const SMBv1::WritePrintFileResultType*) override final;
    void closePrintFileSMBv1(const SMBv1::ClosePrintFileCommand*,
                             const SMBv1::ClosePrintFileArgumentType*,
                             const SMBv1::ClosePrintFileResultType*) override final;
    void getPrintQueueSMBv1(const SMBv1::GetPrintQueueCommand*,
                            const SMBv1::GetPrintQueueArgumentType*,
                            const SMBv1::GetPrintQueueResultType*) override final;
    void readBulkSMBv1(const SMBv1::ReadBulkCommand*,
                       const SMBv1::ReadBulkArgumentType*,
                       const SMBv1::ReadBulkResultType*) override final;
    void writeBulkSMBv1(const SMBv1::WriteBulkCommand*,
                        const SMBv1::WriteBulkArgumentType*,
                        const SMBv1::WriteBulkResultType*) override final;
    void writeBulkDataSMBv1(const SMBv1::WriteBulkDataCommand*,
                            const SMBv1::WriteBulkDataArgumentType*,
                            const SMBv1::WriteBulkDataResultType*) override final;
    void invalidSMBv1(const SMBv1::InvalidCommand*,
                      const SMBv1::InvalidArgumentType*,
                      const SMBv1::InvalidResultType*) override final;
    void noAndxCommandSMBv1(const SMBv1::NoAndxCommand*,
                            const SMBv1::NoAndxCmdArgumentType*,
                            const SMBv1::NoAndxCmdResultType*) override final;
    void null(const RPCProcedure* proc,
              const struct NFS3::NULL3args*,
              const struct NFS3::NULL3res*) override final;
    void getattr3(const RPCProcedure*              proc,
                  const struct NFS3::GETATTR3args* args,
                  const struct NFS3::GETATTR3res*  res) override final;
    void setattr3(const RPCProcedure*              proc,
                  const struct NFS3::SETATTR3args* args,
                  const struct NFS3::SETATTR3res*  res) override final;
    void lookup3(const RPCProcedure*             proc,
                 const struct NFS3::LOOKUP3args* args,
                 const struct NFS3::LOOKUP3res*  res) override final;
    void access3(const RPCProcedure*             proc,
                 const struct NFS3::ACCESS3args* args,
                 const struct NFS3::ACCESS3res*  res) override final;
    void readlink3(const RPCProcedure*               proc,
                   const struct NFS3::READLINK3args* args,
                   const struct NFS3::READLINK3res*  res) override final;
    void read3(const RPCProcedure*           proc,
               const struct NFS3::READ3args* args,
               const struct NFS3::READ3res*  res) override final;
    void write3(const RPCProcedure*            proc,
                const struct NFS3::WRITE3args* args,
                const struct NFS3::WRITE3res*  res) override final;
    void create3(const RPCProcedure*             proc,
                 const struct NFS3::CREATE3args* args,
                 const struct NFS3::CREATE3res*  res) override final;
    void mkdir3(const RPCProcedure*            proc,
                const struct NFS3::MKDIR3args* args,
                const struct NFS3::MKDIR3res*  res) override final;
    void symlink3(const RPCProcedure*              proc,
                  const struct NFS3::SYMLINK3args* args,
                  const struct NFS3::SYMLINK3res*  res) override final;
    void mknod3(const RPCProcedure*            proc,
                const struct NFS3::MKNOD3args* args,
                const struct NFS3::MKNOD3res*  res) override final;
    void remove3(const RPCProcedure*             proc,
                 const struct NFS3::REMOVE3args* args,
                 const struct NFS3::REMOVE3res*  res) override final;
    void rmdir3(const RPCProcedure*            proc,
                const struct NFS3::RMDIR3args* args,
                const struct NFS3::RMDIR3res*  res) override final;
    void rename3(const RPCProcedure*             proc,
                 const struct NFS3::RENAME3args* args,
                 const struct NFS3::RENAME3res*  res) override final;
    void link3(const RPCProcedure*           proc,
               const struct NFS3::LINK3args* args,
               const struct NFS3::LINK3res*  res) override final;
    void readdir3(const RPCProcedure*              proc,
                  const struct NFS3::READDIR3args* args,
                  const struct NFS3::READDIR3res*  res) override final;
    void readdirplus3(const RPCProcedure*                  proc,
                      const struct NFS3::READDIRPLUS3args* args,
                      const struct NFS3::READDIRPLUS3res*  res) override final;
    void fsstat3(const RPCProcedure*             proc,
                 const struct NFS3::FSSTAT3args* args,
                 const struct NFS3::FSSTAT3res*  res) override final;
    void fsinfo3(const RPCProcedure*             proc,
                 const struct NFS3::FSINFO3args* args,
                 const struct NFS3::FSINFO3res*  res) override final;
    void pathconf3(const RPCProcedure*               proc,
                   const struct NFS3::PATHCONF3args* args,
                   const struct NFS3::PATHCONF3res*  res) override final;
    void commit3(const RPCProcedure*             proc,
                 const struct NFS3::COMMIT3args* args,
                 const struct NFS3::COMMIT3res*  res) override final;

    void null(const RPCProcedure*           proc,
              const struct NFS4::NULL4args* args,
              const struct NFS4::NULL4res*  res) override final;
    void compound4(const RPCProcedure*               proc,
                   const struct NFS4::COMPOUND4args* args,
                   const struct NFS4::COMPOUND4res*  res) override final;

    void nfs4_operation(const struct NFS4::nfs_argop4*                 op);
    void nfs4_operation(const struct NFS4::nfs_resop4*                 op);

    void nfs4_operation(const struct NFS4::ACCESS4args*              args);
    void nfs4_operation(const struct NFS4::ACCESS4res*               res );

    void nfs4_operation(const struct NFS4::CLOSE4args*               args);
    void nfs4_operation(const struct NFS4::CLOSE4res*                res );

    void nfs4_operation(const struct NFS4::COMMIT4args*              args);
    void nfs4_operation(const struct NFS4::COMMIT4res*               res );

    void nfs4_operation(const struct NFS4::CREATE4args*              args);
    void nfs4_operation(const struct NFS4::CREATE4res*               res );

    void nfs4_operation(const struct NFS4::DELEGPURGE4args*          args);
    void nfs4_operation(const struct NFS4::DELEGPURGE4res*           res );

    void nfs4_operation(const struct NFS4::DELEGRETURN4args*         args);
    void nfs4_operation(const struct NFS4::DELEGRETURN4res*          res );

    void nfs4_operation(const struct NFS4::GETATTR4args*             args);
    void nfs4_operation(const struct NFS4::GETATTR4res*              res );

    void nfs4_operation(const struct NFS4::LINK4args*                args);
    void nfs4_operation(const struct NFS4::LINK4res*                 res );

    void nfs4_operation(const struct NFS4::LOCK4args*                args);
    void nfs4_operation(const struct NFS4::LOCK4res*                 res );

    void nfs4_operation(const struct NFS4::LOCKT4args*               args);
    void nfs4_operation(const struct NFS4::LOCKT4res*                res );

    void nfs4_operation(const struct NFS4::LOCKU4args*               args);
    void nfs4_operation(const struct NFS4::LOCKU4res*                res );

    void nfs4_operation(const struct NFS4::LOOKUP4args*              args);
    void nfs4_operation(const struct NFS4::LOOKUP4res*               res );

    void nfs4_operation(const struct NFS4::NVERIFY4args*             args);
    void nfs4_operation(const struct NFS4::NVERIFY4res*              res );

    void nfs4_operation(const struct NFS4::OPEN4args*                args);
    void nfs4_operation(const struct NFS4::OPEN4res*                 res );

    void nfs4_operation(const struct NFS4::OPENATTR4args*            args);
    void nfs4_operation(const struct NFS4::OPENATTR4res*             res );

    void nfs4_operation(const struct NFS4::OPEN_CONFIRM4args*        args);
    void nfs4_operation(const struct NFS4::OPEN_CONFIRM4res*         res );

    void nfs4_operation(const struct NFS4::OPEN_DOWNGRADE4args*      args);
    void nfs4_operation(const struct NFS4::OPEN_DOWNGRADE4res*       res );

    void nfs4_operation(const struct NFS4::PUTFH4args*               args);
    void nfs4_operation(const struct NFS4::PUTFH4res*                res );

    void nfs4_operation(const struct NFS4::READ4args*                args);
    void nfs4_operation(const struct NFS4::READ4res*                 res );

    void nfs4_operation(const struct NFS4::READDIR4args*             args);
    void nfs4_operation(const struct NFS4::READDIR4res*              res );

    void nfs4_operation(const struct NFS4::REMOVE4args*              args);
    void nfs4_operation(const struct NFS4::REMOVE4res*               res );

    void nfs4_operation(const struct NFS4::RENAME4args*              args);
    void nfs4_operation(const struct NFS4::RENAME4res*               res );

    void nfs4_operation(const struct NFS4::RENEW4args*               args);
    void nfs4_operation(const struct NFS4::RENEW4res*                res );

    void nfs4_operation(const struct NFS4::SECINFO4args*             args);
    void nfs4_operation(const struct NFS4::SECINFO4res*              res );

    void nfs4_operation(const struct NFS4::SETATTR4args*             args);
    void nfs4_operation(const struct NFS4::SETATTR4res*              res );

    void nfs4_operation(const struct NFS4::SETCLIENTID4args*         args);
    void nfs4_operation(const struct NFS4::SETCLIENTID4res*          res );

    void nfs4_operation(const struct NFS4::SETCLIENTID_CONFIRM4args* args);
    void nfs4_operation(const struct NFS4::SETCLIENTID_CONFIRM4res*  res );

    void nfs4_operation(const struct NFS4::VERIFY4args*              args);
    void nfs4_operation(const struct NFS4::VERIFY4res*               res );

    void nfs4_operation(const struct NFS4::WRITE4args*               args);
    void nfs4_operation(const struct NFS4::WRITE4res*                res );

    void nfs4_operation(const struct NFS4::RELEASE_LOCKOWNER4args*   args);
    void nfs4_operation(const struct NFS4::RELEASE_LOCKOWNER4res*    res );

    void nfs4_operation(const struct NFS4::GET_DIR_DELEGATION4args*  args);
    void nfs4_operation(const struct NFS4::GET_DIR_DELEGATION4res*   res );

    void nfs4_operation(const struct NFS4::GETFH4res*                 res);

    void nfs4_operation(const struct NFS4::LOOKUPP4res*               res);

    void nfs4_operation(const struct NFS4::PUTPUBFH4res*              res);

    void nfs4_operation(const struct NFS4::PUTROOTFH4res*             res);

    void nfs4_operation(const struct NFS4::READLINK4res*              res);

    void nfs4_operation(const struct NFS4::RESTOREFH4res*             res);

    void nfs4_operation(const struct NFS4::SAVEFH4res*                res);

    void nfs4_operation(const struct NFS4::ILLEGAL4res*               res);

    void compound41(const RPCProcedure*               proc,
                    const struct NFS41::COMPOUND4args* args,
                    const struct NFS41::COMPOUND4res*  res) override final;

    void nfs41_operation(const struct NFS41::nfs_argop4*                  op);
    void nfs41_operation(const struct NFS41::nfs_resop4*                  op);

    void nfs41_operation(const struct NFS41::ACCESS4args*               args);
    void nfs41_operation(const struct NFS41::ACCESS4res*                res );

    void nfs41_operation(const struct NFS41::CLOSE4args*                args);
    void nfs41_operation(const struct NFS41::CLOSE4res*                 res );

    void nfs41_operation(const struct NFS41::COMMIT4args*               args);
    void nfs41_operation(const struct NFS41::COMMIT4res*                res );

    void nfs41_operation(const struct NFS41::CREATE4args*               args);
    void nfs41_operation(const struct NFS41::CREATE4res*                res );

    void nfs41_operation(const struct NFS41::DELEGPURGE4args*           args);
    void nfs41_operation(const struct NFS41::DELEGPURGE4res*            res );

    void nfs41_operation(const struct NFS41::DELEGRETURN4args*          args);
    void nfs41_operation(const struct NFS41::DELEGRETURN4res*           res );

    void nfs41_operation(const struct NFS41::GETATTR4args*              args);
    void nfs41_operation(const struct NFS41::GETATTR4res*               res );

    void nfs41_operation(const struct NFS41::LINK4args*                 args);
    void nfs41_operation(const struct NFS41::LINK4res*                  res );

    void nfs41_operation(const struct NFS41::LOCK4args*                 args);
    void nfs41_operation(const struct NFS41::LOCK4res*                  res );

    void nfs41_operation(const struct NFS41::LOCKT4args*                args);
    void nfs41_operation(const struct NFS41::LOCKT4res*                 res );

    void nfs41_operation(const struct NFS41::LOCKU4args*                args);
    void nfs41_operation(const struct NFS41::LOCKU4res*                 res );

    void nfs41_operation(const struct NFS41::LOOKUP4args*               args);
    void nfs41_operation(const struct NFS41::LOOKUP4res*                res );

    void nfs41_operation(const struct NFS41::NVERIFY4args*              args);
    void nfs41_operation(const struct NFS41::NVERIFY4res*               res );

    void nfs41_operation(const struct NFS41::OPEN4args*                 args);
    void nfs41_operation(const struct NFS41::OPEN4res*                  res );

    void nfs41_operation(const struct NFS41::OPENATTR4args*             args);
    void nfs41_operation(const struct NFS41::OPENATTR4res*              res );

    void nfs41_operation(const struct NFS41::OPEN_CONFIRM4args*         args);
    void nfs41_operation(const struct NFS41::OPEN_CONFIRM4res*          res );

    void nfs41_operation(const struct NFS41::OPEN_DOWNGRADE4args*       args);
    void nfs41_operation(const struct NFS41::OPEN_DOWNGRADE4res*        res );

    void nfs41_operation(const struct NFS41::PUTFH4args*                args);
    void nfs41_operation(const struct NFS41::PUTFH4res*                 res );

    void nfs41_operation(const struct NFS41::READ4args*                 args);
    void nfs41_operation(const struct NFS41::READ4res*                  res );

    void nfs41_operation(const struct NFS41::READDIR4args*              args);
    void nfs41_operation(const struct NFS41::READDIR4res*               res );

    void nfs41_operation(const struct NFS41::REMOVE4args*               args);
    void nfs41_operation(const struct NFS41::REMOVE4res*                res );

    void nfs41_operation(const struct NFS41::RENAME4args*               args);
    void nfs41_operation(const struct NFS41::RENAME4res*                res );

    void nfs41_operation(const struct NFS41::RENEW4args*                args);
    void nfs41_operation(const struct NFS41::RENEW4res*                 res );

    void nfs41_operation(const struct NFS41::SECINFO4args*              args);
    void nfs41_operation(const struct NFS41::SECINFO4res*               res );

    void nfs41_operation(const struct NFS41::SETATTR4args*              args);
    void nfs41_operation(const struct NFS41::SETATTR4res*               res );

    void nfs41_operation(const struct NFS41::SETCLIENTID4args*          args);
    void nfs41_operation(const struct NFS41::SETCLIENTID4res*           res );

    void nfs41_operation(const struct NFS41::SETCLIENTID_CONFIRM4args*  args);
    void nfs41_operation(const struct NFS41::SETCLIENTID_CONFIRM4res*   res );

    void nfs41_operation(const struct NFS41::VERIFY4args*               args);
    void nfs41_operation(const struct NFS41::VERIFY4res*                res );

    void nfs41_operation(const struct NFS41::WRITE4args*                args);
    void nfs41_operation(const struct NFS41::WRITE4res*                 res );

    void nfs41_operation(const struct NFS41::RELEASE_LOCKOWNER4args*    args);
    void nfs41_operation(const struct NFS41::RELEASE_LOCKOWNER4res*     res );

    void nfs41_operation(const struct NFS41::BACKCHANNEL_CTL4args*      args);
    void nfs41_operation(const struct NFS41::BACKCHANNEL_CTL4res*       res );

    void nfs41_operation(const struct NFS41::BIND_CONN_TO_SESSION4args* args);
    void nfs41_operation(const struct NFS41::BIND_CONN_TO_SESSION4res*  res );

    void nfs41_operation(const struct NFS41::EXCHANGE_ID4args*          args);
    void nfs41_operation(const struct NFS41::EXCHANGE_ID4res*           res );

    void nfs41_operation(const struct NFS41::CREATE_SESSION4args*       args);
    void nfs41_operation(const struct NFS41::CREATE_SESSION4res*        res );

    void nfs41_operation(const struct NFS41::DESTROY_SESSION4args*      args);
    void nfs41_operation(const struct NFS41::DESTROY_SESSION4res*       res );

    void nfs41_operation(const struct NFS41::FREE_STATEID4args*         args);
    void nfs41_operation(const struct NFS41::FREE_STATEID4res*          res );

    void nfs41_operation(const struct NFS41::GET_DIR_DELEGATION4args*   args);
    void nfs41_operation(const struct NFS41::GET_DIR_DELEGATION4res*    res );

    void nfs41_operation(const struct NFS41::GETDEVICEINFO4args*        args);
    void nfs41_operation(const struct NFS41::GETDEVICEINFO4res*         res );

    void nfs41_operation(const struct NFS41::GETDEVICELIST4args*        args);
    void nfs41_operation(const struct NFS41::GETDEVICELIST4res*         res );

    void nfs41_operation(const struct NFS41::LAYOUTCOMMIT4args*         args);
    void nfs41_operation(const struct NFS41::LAYOUTCOMMIT4res*          res );

    void nfs41_operation(const struct NFS41::LAYOUTGET4args*            args);
    void nfs41_operation(const struct NFS41::LAYOUTGET4res*             res );

    void nfs41_operation(const struct NFS41::LAYOUTRETURN4args*         args);
    void nfs41_operation(const struct NFS41::LAYOUTRETURN4res*          res );

    void nfs41_operation(const enum NFS41::secinfo_style4*              args);

    void nfs41_operation(const struct NFS41::SEQUENCE4args*             args);
    void nfs41_operation(const struct NFS41::SEQUENCE4res*              res );

    void nfs41_operation(const struct NFS41::SET_SSV4args*              args);
    void nfs41_operation(const struct NFS41::SET_SSV4res*               res );

    void nfs41_operation(const struct NFS41::TEST_STATEID4args*         args);
    void nfs41_operation(const struct NFS41::TEST_STATEID4res*          res );

    void nfs41_operation(const struct NFS41::WANT_DELEGATION4args*      args);
    void nfs41_operation(const struct NFS41::WANT_DELEGATION4res*       res );

    void nfs41_operation(const struct NFS41::DESTROY_CLIENTID4args*     args);
    void nfs41_operation(const struct NFS41::DESTROY_CLIENTID4res*      res );

    void nfs41_operation(const struct NFS41::RECLAIM_COMPLETE4args*     args);
    void nfs41_operation(const struct NFS41::RECLAIM_COMPLETE4res*      res );

    void nfs41_operation(const struct NFS41::GETFH4res*                 res);

    void nfs41_operation(const struct NFS41::LOOKUPP4res*               res);

    void nfs41_operation(const struct NFS41::PUTPUBFH4res*              res);

    void nfs41_operation(const struct NFS41::PUTROOTFH4res*             res);

    void nfs41_operation(const struct NFS41::READLINK4res*              res);

    void nfs41_operation(const struct NFS41::RESTOREFH4res*             res);

    void nfs41_operation(const struct NFS41::SAVEFH4res*                res);

    void nfs41_operation(const struct NFS41::ILLEGAL4res*               res);

    void flush_statistics() override final;

private:
    PrintAnalyzer(const PrintAnalyzer&)            = delete;
    PrintAnalyzer& operator=(const PrintAnalyzer&) = delete;

    std::ostream& out;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//PRINT_ANALYZER_H
//------------------------------------------------------------------------------
