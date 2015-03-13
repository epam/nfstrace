//------------------------------------------------------------------------------
// Author: Dzianis Huznou (Alexey Costroma)
// Description: Created for demonstration purpose only.
// Copyright (c) 2013-2015 EPAM Systems
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
#include <iomanip>
#include <time.h>

#include "analysis/print_analyzer.h"
#include "protocols/cifs/cifs.h"
#include "protocols/cifs2/cifs2.h"
#include "protocols/nfs/nfs_utils.h"
#include "protocols/nfs3/nfs3_utils.h"
#include "protocols/nfs4/nfs4_utils.h"
#include "protocols/nfs4/nfs41_utils.h"
#include "protocols/cifs2/cifs2_utils.h"
//------------------------------------------------------------------------------

namespace NST
{
namespace analysis
{

using SMBv1Commands = NST::API::SMBv1::SMBv1Commands;
using namespace NST::protocols::CIFSv2;
using namespace NST::protocols::NFS;   // NFS helpers
using namespace NST::protocols::NFS3;  // NFSv3 helpers
using namespace NST::protocols::NFS4;  // NFSv4.0 helpers
using namespace NST::protocols::NFS41; // NFSv4.1 helpers
namespace NFS3  = NST::API::NFS3;
namespace NFS4  = NST::API::NFS4;
namespace NFS41 = NST::API::NFS41;

namespace
{
bool print_procedure(std::ostream& out, const RPCProcedure* proc)
{
    bool result {false};
    NST::utils::operator<<(out, *(proc->session));

    auto& call = proc->call;
    const unsigned long nfs_version {call.ru.RM_cmb.cb_vers};
    if (out_all())
    {
        out << " XID: "         << call.rm_xid
            << " RPC version: " << call.ru.RM_cmb.cb_rpcvers
            << " RPC program: " << call.ru.RM_cmb.cb_prog
            << " version: "     << nfs_version << ' ';
    }
    switch (nfs_version)
    {
    case NFS_V3:
        out << print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(call.ru.RM_cmb.cb_proc));
        break;
    case NFS_V4:
        out << print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(call.ru.RM_cmb.cb_proc));
        break;
    }

    // check procedure reply
    auto& reply = proc->reply;
    if (reply.ru.RM_rmb.rp_stat == reply_stat::MSG_ACCEPTED)
    {
        switch (reply.ru.RM_rmb.ru.RP_ar.ar_stat)
        {
        case accept_stat::SUCCESS:
            result = true;    // Ok, reply is correct
            break;
        case accept_stat::PROG_MISMATCH:
            out << " Program mismatch: "
                << " low: "  << reply.ru.RM_rmb.ru.RP_ar.ru.AR_versions.low
                << " high: " << reply.ru.RM_rmb.ru.RP_ar.ru.AR_versions.high;
            break;
        case accept_stat::PROG_UNAVAIL:
            out << " Program unavailable";
            break;
        case accept_stat::PROC_UNAVAIL:
            out << " Procedure unavailable";
            break;
        case accept_stat::GARBAGE_ARGS:
            out << " Garbage arguments";
            break;
        case accept_stat::SYSTEM_ERR:
            out << " System error";
            break;
        }
    }
    else if (reply.ru.RM_rmb.rp_stat == reply_stat::MSG_DENIED)
    {
        out << " RPC Call rejected: ";
        switch (reply.ru.RM_rmb.ru.RP_dr.rj_stat)
        {
        case reject_stat::RPC_MISMATCH:
            out << "RPC version number mismatch, "
                << " low: "
                << reply.ru.RM_rmb.ru.RP_dr.ru.RJ_versions.low
                << " high: "
                << reply.ru.RM_rmb.ru.RP_dr.ru.RJ_versions.high;
            break;
        case reject_stat::AUTH_ERROR:
        {
            out << " Authentication check: ";
            switch (reply.ru.RM_rmb.ru.RP_dr.ru.RJ_why)
            {
            case auth_stat::AUTH_OK:
                out << "OK";
                break;
            case auth_stat::AUTH_BADCRED:
                out << " bogus credentials (seal broken)"
                    << " (failed at remote end)";
                break;
            case auth_stat::AUTH_REJECTEDCRED:
                out << " rejected credentials (client should begin new session)"
                    << " (failed at remote end)";
                break;
            case auth_stat::AUTH_BADVERF:
                out << " bogus verifier (seal broken)"
                    << " (failed at remote end)";
                break;
            case auth_stat::AUTH_REJECTEDVERF:
                out << " verifier expired or was replayed"
                    << " (failed at remote end)";
                break;
            case auth_stat::AUTH_TOOWEAK:
                out << " too weak (rejected due to security reasons)"
                    << " (failed at remote end)";
                break;
            case auth_stat::AUTH_INVALIDRESP:
                out << " bogus response verifier"
                    << " (failed locally)";
                break;
            default:
                out << " some unknown reason"
                    << " (failed locally)";
                break;
            }
            break;
        }
        }
    }
    out << '\n'; // end line of RPC procedure information
    return result;
}

template<typename CommandType>
void print_smbv2_common_info(std::ostream& out, Commands cmdEnum, CommandType* cmd, const std::string& cmdComment)
{
    out << print_cifs2_procedures(cmdEnum) << " " << cmdComment << " (";
    print_hex16(out, to_integral(cmdEnum));
    out << ")\n"
        << "  Structure size = ";
    print_hex16(out, cmd->StructureSize);
    out << "\n  Credit Charge = " << cmd->CreditCharge << "\n";
    out << "  Session Id = ";
    print_hex64(out, cmd->SessionId);
}

template<typename CommandType>
void print_smbv2_common_info_req(std::ostream& out, Commands cmdEnum, CommandType* cmd)
{
    out << "\n";
    NST::utils::operator<<(out, *(cmd->session));
    out << "\n";
    print_smbv2_common_info(out, cmdEnum, cmd->req_header, "request");
}

template<typename CommandType>
void print_smbv2_common_info_resp(std::ostream& out, Commands cmdEnum, CommandType* cmd)
{
    print_smbv2_common_info(out, cmdEnum, cmd->res_header, "response");
    out << "\n  NT Status = " << static_cast<NST::API::SMBv2::NTStatus>(cmd->res_header->status);
}

void print_time(std::ostream& out, uint64_t time)
{
    // TODO: Replace with C++ 11 functions

    const auto EPOCH_DIFF = 0x019DB1DED53E8000LL; /* 116444736000000000 nsecs */
    const auto RATE_DIFF = 10000000;              /* 100 nsecs */

    uint64_t unixTimestamp = (time - EPOCH_DIFF) / RATE_DIFF;
    time_t t = static_cast<time_t>(unixTimestamp);

    // NOTE: If you ever want to print the year/day/month separately like this:
    //
    // struct tm* lt = localtime(&t);
    //
    // do not forget adding 1900 to tm_year field, just to get current year
    // lt->tm_year + 1900

    out << ctime(&t);
}

void print_buffer(std::ostream& out, const uint8_t *buffer, uint16_t len)
{
    // TODO: Add unicode support
    const char* char_buffer = reinterpret_cast<const char*>(buffer);
    out << "  ";
    for(uint16_t i = 0; i < len; i++)
    {
        out << char_buffer[i];
    }
}

} // unnamed namespace


void PrintAnalyzer::createDirectorySMBv1(const SMBv1::CreateDirectoryCommand*,
                                         const SMBv1::CreateDirectoryArgumentType*,
                                         const SMBv1::CreateDirectoryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_CREATE_DIRECTORY);
}

void PrintAnalyzer::deleteDirectorySMBv1(const SMBv1::DeleteDirectoryCommand*,
                                         const SMBv1::DeleteDirectoryArgumentType*,
                                         const SMBv1::DeleteDirectoryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_DELETE_DIRECTORY);
}

void PrintAnalyzer::openSMBv1(const SMBv1::OpenCommand*,
                              const SMBv1::OpenArgumentType*,
                              const SMBv1::OpenResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_OPEN);
}

void PrintAnalyzer::createSMBv1(const SMBv1::CreateCommand*,
                                const SMBv1::CreateArgumentType*,
                                const SMBv1::CreateResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_CREATE);
}

void PrintAnalyzer::closeSMBv1(const SMBv1::CloseCommand*,
                               const SMBv1::CloseArgumentType*,
                               const SMBv1::CloseResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_CLOSE);
}

void PrintAnalyzer::flushSMBv1(const SMBv1::FlushCommand*,
                               const SMBv1::FlushArgumentType*,
                               const SMBv1::FlushResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_FLUSH);
}

void PrintAnalyzer::deleteSMBv1(const SMBv1::DeleteCommand*,
                                const SMBv1::DeleteArgumentType*,
                                const SMBv1::DeleteResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_DELETE);
}

void PrintAnalyzer::renameSMBv1(const SMBv1::RenameCommand*,
                                const SMBv1::RenameArgumentType*,
                                const SMBv1::RenameResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_RENAME);
}

void PrintAnalyzer::queryInfoSMBv1(const SMBv1::QueryInformationCommand*,
                                   const SMBv1::QueryInformationArgumentType*,
                                   const SMBv1::QueryInformationResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_QUERY_INFORMATION);
}

void PrintAnalyzer::setInfoSMBv1(const SMBv1::SetInformationCommand*,
                                 const SMBv1::SetInformationArgumentType*,
                                 const SMBv1::SetInformationResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_SET_INFORMATION);
}

void PrintAnalyzer::readSMBv1(const SMBv1::ReadCommand*,
                              const SMBv1::ReadArgumentType*,
                              const SMBv1::ReadResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_READ);
}

void PrintAnalyzer::writeSMBv1(const SMBv1::WriteCommand*,
                               const SMBv1::WriteArgumentType*,
                               const SMBv1::WriteResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE);
}

void PrintAnalyzer::lockByteRangeSMBv1(const SMBv1::LockByteRangeCommand*,
                                       const SMBv1::LockByteRangeArgumentType*,
                                       const SMBv1::LockByteRangeResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_LOCK_BYTE_RANGE);
}

void PrintAnalyzer::unlockByteRangeSMBv1(const SMBv1::UnlockByteRangeCommand*,
                                         const SMBv1::UnlockByteRangeArgumentType*,
                                         const SMBv1::UnlockByteRangeResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_UNLOCK_BYTE_RANGE);
}

void PrintAnalyzer::createTmpSMBv1(const SMBv1::CreateTemporaryCommand*,
                                   const SMBv1::CreateTemporaryArgumentType*,
                                   const SMBv1::CreateTemporaryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_CREATE_TEMPORARY);
}

void PrintAnalyzer::createNewSMBv1(const SMBv1::CreateNewCommand*,
                                   const SMBv1::CreateNewArgumentType*,
                                   const SMBv1::CreateNewResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_CREATE_NEW);
}

void PrintAnalyzer::checkDirectorySMBv1(const SMBv1::CheckDirectoryCommand*,
                                        const SMBv1::CheckDirectoryArgumentType*,
                                        const SMBv1::CheckDirectoryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_CHECK_DIRECTORY);
}

void PrintAnalyzer::processExitSMBv1(const SMBv1::ProcessExitCommand*,
                                     const SMBv1::ProcessExitArgumentType*,
                                     const SMBv1::ProcessExitResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_PROCESS_EXIT);
}

void PrintAnalyzer::seekSMBv1(const SMBv1::SeekCommand*,
                              const SMBv1::SeekArgumentType*,
                              const SMBv1::SeekResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_SEEK);
}

void PrintAnalyzer::lockAndReadSMBv1(const SMBv1::LockAndReadCommand*,
                                     const SMBv1::LockAndReadArgumentType*,
                                     const SMBv1::LockAndReadResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_LOCK_AND_READ);
}

void PrintAnalyzer::writeAndUnlockSMBv1(const SMBv1::WriteAndUnlockCommand*,
                                        const SMBv1::WriteAndUnlockArgumentType*,
                                        const SMBv1::WriteAndUnlockResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_AND_UNLOCK);
}

void PrintAnalyzer::readRawSMBv1(const SMBv1::ReadRawCommand*,
                                 const SMBv1::ReadRawArgumentType*,
                                 const SMBv1::ReadRawResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_READ_RAW);
}

void PrintAnalyzer::readMpxSMBv1(const SMBv1::ReadMpxCommand*,
                                 const SMBv1::ReadMpxArgumentType*,
                                 const SMBv1::ReadMpxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_READ_MPX);
}

void PrintAnalyzer::readMpxSecondarySMBv1(const SMBv1::ReadMpxSecondaryCommand*,
                                          const SMBv1::ReadMpxSecondaryArgumentType*,
                                          const SMBv1::ReadMpxSecondaryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_READ_MPX_SECONDARY);
}

void PrintAnalyzer::writeRawSMBv1(const SMBv1::WriteRawCommand*,
                                  const SMBv1::WriteRawArgumentType*,
                                  const SMBv1::WriteRawResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_RAW);
}

void PrintAnalyzer::writeMpxSMBv1(const SMBv1::WriteMpxCommand*,
                                  const SMBv1::WriteMpxArgumentType*,
                                  const SMBv1::WriteMpxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_MPX);
}

void PrintAnalyzer::writeMpxSecondarySMBv1(const SMBv1::WriteMpxSecondaryCommand*,
                                           const SMBv1::WriteMpxSecondaryArgumentType*,
                                           const SMBv1::WriteMpxSecondaryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_MPX_SECONDARY);
}

void PrintAnalyzer::writeCompleteSMBv1(const SMBv1::WriteCompleteCommand*,
                                       const SMBv1::WriteCompleteArgumentType*,
                                       const SMBv1::WriteCompleteResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_COMPLETE);
}

void PrintAnalyzer::queryServerSMBv1(const SMBv1::QueryServerCommand*,
                                     const SMBv1::QueryServerArgumentType*,
                                     const SMBv1::QueryServerResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_QUERY_SERVER);
}

void PrintAnalyzer::setInfo2SMBv1(const SMBv1::SetInformation2Command*,
                                  const SMBv1::SetInformation2ArgumentType*,
                                  const SMBv1::SetInformation2ResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_SET_INFORMATION2);
}

void PrintAnalyzer::queryInfo2SMBv1(const SMBv1::QueryInformation2Command*,
                                    const SMBv1::QueryInformation2ArgumentType*,
                                    const SMBv1::QueryInformation2ResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_QUERY_INFORMATION2);
}

void PrintAnalyzer::lockingAndxSMBv1(const SMBv1::LockingAndxCommand*,
                                     const SMBv1::LockingAndxArgumentType*,
                                     const SMBv1::LockingAndxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_LOCKING_ANDX);
}

void PrintAnalyzer::transactionSMBv1(const SMBv1::TransactionCommand*,
                                     const SMBv1::TransactionArgumentType*,
                                     const SMBv1::TransactionResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_TRANSACTION);
}

void PrintAnalyzer::transactionSecondarySMBv1(const SMBv1::TransactionSecondaryCommand*,
                                              const SMBv1::TransactionSecondaryArgumentType*,
                                              const SMBv1::TransactionSecondaryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_TRANSACTION_SECONDARY);
}

void PrintAnalyzer::ioctlSMBv1(const SMBv1::IoctlCommand*,
                               const SMBv1::IoctlArgumentType*,
                               const SMBv1::IoctlResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_IOCTL);
}

void PrintAnalyzer::ioctlSecondarySMBv1(const SMBv1::IoctlSecondaryCommand*,
                                        const SMBv1::IoctlSecondaryArgumentType*,
                                        const SMBv1::IoctlSecondaryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_IOCTL_SECONDARY);
}

void PrintAnalyzer::copySMBv1(const SMBv1::CopyCommand*,
                              const SMBv1::CopyArgumentType*,
                              const SMBv1::CopyResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_COPY);
}

void PrintAnalyzer::moveSMBv1(const SMBv1::MoveCommand*,
                              const SMBv1::MoveArgumentType*,
                              const SMBv1::MoveResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_MOVE);
}

void PrintAnalyzer::echoSMBv1(const SMBv1::EchoCommand*,
                              const SMBv1::EchoArgumentType*,
                              const SMBv1::EchoResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_ECHO);
}

void PrintAnalyzer::writeAndCloseSMBv1(const SMBv1::WriteAndCloseCommand*,
                                       const SMBv1::WriteAndCloseArgumentType*,
                                       const SMBv1::WriteAndCloseResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_AND_CLOSE);
}

void PrintAnalyzer::openAndxSMBv1(const SMBv1::OpenAndxCommand*,
                                  const SMBv1::OpenAndxArgumentType*,
                                  const SMBv1::OpenAndxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_OPEN_ANDX);
}

void PrintAnalyzer::readAndxSMBv1(const SMBv1::ReadAndxCommand*,
                                  const SMBv1::ReadAndxArgumentType*,
                                  const SMBv1::ReadAndxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_READ_ANDX);
}

void PrintAnalyzer::writeAndxSMBv1(const SMBv1::WriteAndxCommand*,
                                   const SMBv1::WriteAndxArgumentType*,
                                   const SMBv1::WriteAndxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_ANDX);
}

void PrintAnalyzer::newFileSizeSMBv1(const SMBv1::NewFileSizeCommand*,
                                     const SMBv1::NewFileSizeArgumentType*,
                                     const SMBv1::NewFileSizeResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_NEW_FILE_SIZE);
}

void PrintAnalyzer::closeAndTreeDiscSMBv1(const SMBv1::CloseAndTreeDiscCommand*,
                                          const SMBv1::CloseAndTreeDiscArgumentType*,
                                          const SMBv1::CloseAndTreeDiscResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_CLOSE_AND_TREE_DISC);
}

void PrintAnalyzer::transaction2SMBv1(const SMBv1::Transaction2Command*,
                                      const SMBv1::Transaction2ArgumentType*,
                                      const SMBv1::Transaction2ResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_TRANSACTION2);
}

void PrintAnalyzer::transaction2SecondarySMBv1(const SMBv1::Transaction2SecondaryCommand*,
                                               const SMBv1::Transaction2SecondaryArgumentType*,
                                               const SMBv1::Transaction2SecondaryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_TRANSACTION2_SECONDARY);
}

void PrintAnalyzer::findClose2SMBv1(const SMBv1::FindClose2Command*,
                                    const SMBv1::FindClose2ArgumentType*,
                                    const SMBv1::FindClose2ResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_FIND_CLOSE2);
}

void PrintAnalyzer::findNotifyCloseSMBv1(const SMBv1::FindNotifyCloseCommand*,
                                         const SMBv1::FindNotifyCloseArgumentType*,
                                         const SMBv1::FindNotifyCloseResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_FIND_NOTIFY_CLOSE);
}

void PrintAnalyzer::treeConnectSMBv1(const SMBv1::TreeConnectCommand*,
                                     const SMBv1::TreeConnectArgumentType*,
                                     const SMBv1::TreeConnectResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_TREE_CONNECT);
}

void PrintAnalyzer::treeDisconnectSMBv1(const SMBv1::TreeDisconnectCommand*,
                                        const SMBv1::TreeDisconnectArgumentType*,
                                        const SMBv1::TreeDisconnectResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_TREE_DISCONNECT);
}

void PrintAnalyzer::negotiateSMBv1(const SMBv1::NegotiateCommand*,
                                   const SMBv1::NegotiateArgumentType*,
                                   const SMBv1::NegotiateResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_NEGOTIATE);
}

void PrintAnalyzer::sessionSetupAndxSMBv1(const SMBv1::SessionSetupAndxCommand*,
                                          const SMBv1::SessionSetupAndxArgumentType*,
                                          const SMBv1::SessionSetupAndxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_SESSION_SETUP_ANDX);
}

void PrintAnalyzer::logoffAndxSMBv1(const SMBv1::LogoffAndxCommand*,
                                    const SMBv1::LogoffAndxArgumentType*,
                                    const SMBv1::LogoffAndxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_LOGOFF_ANDX);
}

void PrintAnalyzer::treeConnectAndxSMBv1(const SMBv1::TreeConnectAndxCommand*,
                                         const SMBv1::TreeConnectAndxArgumentType*,
                                         const SMBv1::TreeConnectAndxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_TREE_CONNECT_ANDX);
}

void PrintAnalyzer::securityPackageAndxSMBv1(const SMBv1::SecurityPackageAndxCommand*,
                                             const SMBv1::SecurityPackageAndxArgumentType*,
                                             const SMBv1::SecurityPackageAndxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_SECURITY_PACKAGE_ANDX);
}

void PrintAnalyzer::queryInformationDiskSMBv1(const SMBv1::QueryInformationDiskCommand*,
                                              const SMBv1::QueryInformationDiskArgumentType*,
                                              const SMBv1::QueryInformationDiskResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_QUERY_INFORMATION_DISK);
}

void PrintAnalyzer::searchSMBv1(const SMBv1::SearchCommand*,
                                const SMBv1::SearchArgumentType*,
                                const SMBv1::SearchResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_SEARCH);
}

void PrintAnalyzer::findSMBv1(const SMBv1::FindCommand*,
                              const SMBv1::FindArgumentType*,
                              const SMBv1::FindResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_FIND);
}

void PrintAnalyzer::findUniqueSMBv1(const SMBv1::FindUniqueCommand*,
                                    const SMBv1::FindUniqueArgumentType*,
                                    const SMBv1::FindUniqueResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_FIND_UNIQUE);
}

void PrintAnalyzer::findCloseSMBv1(const SMBv1::FindCloseCommand*,
                                   const SMBv1::FindCloseArgumentType*,
                                   const SMBv1::FindCloseResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_FIND_CLOSE);
}

void PrintAnalyzer::ntTransactSMBv1(const SMBv1::NtTransactCommand*,
                                    const SMBv1::NtTransactArgumentType*,
                                    const SMBv1::NtTransactResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_NT_TRANSACT);
}

void PrintAnalyzer::ntTransactSecondarySMBv1(const SMBv1::NtTransactSecondaryCommand*,
                                             const SMBv1::NtTransactSecondaryArgumentType*,
                                             const SMBv1::NtTransactSecondaryResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_NT_TRANSACT_SECONDARY);
}

void PrintAnalyzer::ntCreateAndxSMBv1(const SMBv1::NtCreateAndxCommand*,
                                      const SMBv1::NtCreateAndxArgumentType*,
                                      const SMBv1::NtCreateAndxResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_NT_CREATE_ANDX);
}

void PrintAnalyzer::ntCancelSMBv1(const SMBv1::NtCancelCommand*,
                                  const SMBv1::NtCancelArgumentType*,
                                  const SMBv1::NtCancelResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_NT_CANCEL);
}

void PrintAnalyzer::ntRenameSMBv1(const SMBv1::NtRenameCommand*,
                                  const SMBv1::NtRenameArgumentType*,
                                  const SMBv1::NtRenameResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_NT_RENAME);
}

void PrintAnalyzer::openPrintFileSMBv1(const SMBv1::OpenPrintFileCommand*,
                                       const SMBv1::OpenPrintFileArgumentType*,
                                       const SMBv1::OpenPrintFileResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_OPEN_PRINT_FILE);
}

void PrintAnalyzer::writePrintFileSMBv1(const SMBv1::WritePrintFileCommand*,
                                        const SMBv1::WritePrintFileArgumentType*,
                                        const SMBv1::WritePrintFileResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_PRINT_FILE);
}

void PrintAnalyzer::closePrintFileSMBv1(const SMBv1::ClosePrintFileCommand*,
                                        const SMBv1::ClosePrintFileArgumentType*,
                                        const SMBv1::ClosePrintFileResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_CLOSE_PRINT_FILE);
}

void PrintAnalyzer::getPrintQueueSMBv1(const SMBv1::GetPrintQueueCommand*,
                                       const SMBv1::GetPrintQueueArgumentType*,
                                       const SMBv1::GetPrintQueueResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_GET_PRINT_QUEUE);
}

void PrintAnalyzer::readBulkSMBv1(const SMBv1::ReadBulkCommand*,
                                  const SMBv1::ReadBulkArgumentType*,
                                  const SMBv1::ReadBulkResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_READ_BULK);
}

void PrintAnalyzer::writeBulkSMBv1(const SMBv1::WriteBulkCommand*,
                                   const SMBv1::WriteBulkArgumentType*,
                                   const SMBv1::WriteBulkResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_BULK);
}

void PrintAnalyzer::writeBulkDataSMBv1(const SMBv1::WriteBulkDataCommand*,
                                       const SMBv1::WriteBulkDataArgumentType*,
                                       const SMBv1::WriteBulkDataResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_WRITE_BULK_DATA);
}

void PrintAnalyzer::invalidSMBv1(const SMBv1::InvalidCommand*,
                                 const SMBv1::InvalidArgumentType*,
                                 const SMBv1::InvalidResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_INVALID);
}

void PrintAnalyzer::noAndxCommandSMBv1(const SMBv1::NoAndxCommand*,
                                       const SMBv1::NoAndxCmdArgumentType*,
                                       const SMBv1::NoAndxCmdResultType*)
{
    out << print_cifs1_procedures(SMBv1Commands::SMB_COM_NO_ANDX_COMMAND);
}

void PrintAnalyzer::closeFileSMBv2(const SMBv2::CloseFileCommand*,
                                   const SMBv2::CloseRequest*,
                                   const SMBv2::CloseResponse*)
{
}
void PrintAnalyzer::negotiateSMBv2(const SMBv2::NegotiateCommand*,
                                   const SMBv2::NegotiateRequest*,
                                   const SMBv2::NegotiateResponse*)
{
}
void PrintAnalyzer::sessionSetupSMBv2(const SMBv2::SessionSetupCommand* cmd,
                                      const SMBv2::SessionSetupRequest*,
                                      const SMBv2::SessionSetupResponse* res)
{
    Commands cmdEnum = Commands::SESSION_SETUP;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    out << "  Flags = " << cmd->parg->VcNumber << "\n"
        << "  Security mode = " << cmd->parg->securityMode << "\n"
        << "  Capabilities = " << cmd->parg->capabilities << "\n"
        << "  Channel = " << cmd->parg->Channel << "\n"
        << "  Previous session id = " << cmd->parg->PreviousSessionId << "\n";
    //TODO: print security blob ( cmd->parg->Buffer )
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
    out << "  Session flags = " << res->sessionFlags << "\n";
    //TODO: print security blob ( res->Buffer )
}
void PrintAnalyzer::logOffSMBv2(const SMBv2::LogOffCommand* cmd,
                                const SMBv2::LogOffRequest*,
                                const SMBv2::LogOffResponse*)
{
    Commands cmdEnum = Commands::LOGOFF;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
}

void PrintAnalyzer::treeConnectSMBv2(const SMBv2::TreeConnectCommand* cmd,
                                     const SMBv2::TreeConnectRequest*,
                                     const SMBv2::TreeConnectResponse* res)
{
    Commands cmdEnum = Commands::TREE_CONNECT;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    out << "  Tree = ";
    print_buffer(out,cmd->parg->Buffer, cmd->parg->PathLength);
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
    out << "  Share types = " << res->ShareType << "\n"
        << "  Capabilities = "  << res->capabilities << "\n"
        << "  Share flags = " << res->shareFlags << "\n"
        << "  Access mask = " << static_cast<NST::API::SMBv2::AccessMask>(res->MaximalAccess) << "\n";
}
void PrintAnalyzer::treeDisconnectSMBv2(const SMBv2::TreeDisconnectCommand* cmd,
                                        const SMBv2::TreeDisconnectRequest*,
                                        const SMBv2::TreeDisconnectResponse*)
{
    Commands cmdEnum = Commands::TREE_DISCONNECT;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
}
void PrintAnalyzer::createSMBv2(const SMBv2::CreateCommand* cmd,
                                const SMBv2::CreateRequest*,
                                const SMBv2::CreateResponse* res)
{
    Commands cmdEnum = Commands::CREATE;
    print_smbv2_common_info_req(out, cmdEnum, cmd);

    out << "  Oplock = "
        << cmd->parg->RequestedOplockLevel
        << "\n"
        << "  Impersonation = " << cmd->parg->ImpersonationLevel << "\n"
        << "  Create Flags = ";

    print_hex64(out, cmd->parg->SmbCreateFlags);
    out << "\n";

    out << "  Access Mask = "
        << cmd->parg->desiredAccess
        << "\n";

    out << "  File Attributes = "
        << cmd->parg->attributes
        << "\n";

    out << "  Share Access = "
        << cmd->parg->shareAccess
        << "\n"
        << "  Disposition = " << cmd->parg->createDisposition
        << "\n"
        << "  Create Options = "
        << cmd->parg->createOptions;

    out << "\n";
    out << "  File name = ";
    print_buffer(out, cmd->parg->Buffer, cmd->parg->NameLength);

    out << "\n"
        << "  File length = " << cmd->parg->NameLength;

    //
    // TODO: In some cases buffer can contains : CreateContextsOffset, and CreateContextsLength
    // handle and test this in future
    //


    out << "\n";
    print_smbv2_common_info_resp(out, cmdEnum, cmd);

    out << "  Oplock = "
        << res->oplockLevel
        << "\n"
        << "  Response Flags = ";
    print_hex8(out, res->flag);
    out << "\n"
        << "  Create Action = " << res->CreateAction << "\n";
    if (cmd->res_header->status == to_integral(NST::API::SMBv2::NTStatus::STATUS_SUCCESS))
    {
        out << "  Create = ";
        print_time(out, res->CreationTime);

        out << "  Last Access = ";
        print_time(out, res->LastAccessTime);

        out << "  Last Write = ";
        print_time(out, res->LastWriteTime);

        out << "  Last Change = ";
        print_time(out, res->ChangeTime);

        out << "  Allocation Size = ";
        print_time(out, res->AllocationSize);

        out << "  End Of File = ";
        print_time(out, res->EndofFile);

        out << "  File Attributes = " << res->attributes << "\n";
    }
}

void PrintAnalyzer::flushSMBv2(const SMBv2::FlushCommand* cmd,
                               const SMBv2::FlushRequest*,
                               const SMBv2::FlushResponse*)
{
    Commands cmdEnum = Commands::FLUSH;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
}
void PrintAnalyzer::readSMBv2(const SMBv2::ReadCommand* cmd,
                              const SMBv2::ReadRequest*,
                              const SMBv2::ReadResponse* res)
{
    Commands cmdEnum = Commands::READ;

    print_smbv2_common_info_req(out, cmdEnum, cmd);

    out << "  Read length = " << cmd->parg->length << "\n"
        << "  File offset = " << cmd->parg->offset << "\n"
        << "  Min count = " << cmd->parg->minimumCount << "\n"
        << "  Channel = " << to_integral(cmd->parg->channel) << "\n"
        << "  Remaining bytes = " << cmd->parg->RemainingBytes << "\n"
        << "  Channel Info Offset = " << cmd->parg->ReadChannelInfoOffset << "\n"
        << "  Channel Info Length = " << cmd->parg->ReadChannelInfoLength << "\n";

    print_smbv2_common_info_resp(out, cmdEnum, cmd);

    out << "  Data offset = ";
    print_hex16(out, res->DataOffset);
    out << "\n"
        << "  Read length = " << res->DataLength << "\n"
        << "  Read remaining = " << res->DataRemaining << "\n";
}

void PrintAnalyzer::writeSMBv2(const SMBv2::WriteCommand* cmd,
                               const SMBv2::WriteRequest*,
                               const SMBv2::WriteResponse* res)
{
    Commands cmdEnum = Commands::WRITE;
    print_smbv2_common_info_req(out, cmdEnum, cmd);

    out << "  Data offset = ";
    print_hex16(out, cmd->parg->dataOffset);

    out << "\n"
    << "  Write Length = " << cmd->parg->Length << "\n"
    << "  File Offset = " << cmd->parg->Offset << "\n"
    << "  Channel = " << to_integral(cmd->parg->Channel) << "\n"
    << "  Remaining Bytes = " << cmd->parg->RemainingBytes << "\n"
    << "  Channel Info Offset = " << cmd->parg->WriteChannelInfoOffset << "\n"
    << "  Channel Info Length = " << cmd->parg->WriteChannelInfoLength << "\n"
    << "  Write Flags = " << cmd->parg->Flags << "\n";
    // TODO: Wireshark also shows binary representation of file ...
    // For now it is skipped

    print_smbv2_common_info_resp(out, cmdEnum, cmd);

    out << "  Write Count = " << res->Count << "\n"
        << "  Write Remaining = " << res->Remaining << "\n"
        << "  Channel Info Offset = " << res->WriteChannelInfoOffset << "\n"
        << "  Channel Info Length = " << res->WriteChannelInfoLength << "\n";
}

void PrintAnalyzer::lockSMBv2(const SMBv2::LockCommand* cmd,
                              const SMBv2::LockRequest*,
                              const SMBv2::LockResponse*)
{
    Commands cmdEnum = Commands::LOCK;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    out << "  Lock Count = " << static_cast<uint32_t>(cmd->parg->LockCount) << "\n"
        << "  Lock Sequence = " << static_cast<uint32_t>(cmd->parg->LockSequence) << "\n";
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
}
void PrintAnalyzer::ioctlSMBv2(const SMBv2::IoctlCommand* cmd,
                               const SMBv2::IoCtlRequest*,
                               const SMBv2::IoCtlResponse* res)
{
    Commands cmdEnum = Commands::IOCTL;
    print_smbv2_common_info_req(out, cmdEnum, cmd); 
    out << "  Control Code = " << cmd->parg->CtlCode << "\n"
        << "  Input offset = " << cmd->parg->InputOffset << "\n"
        << "  Input count = " << cmd->parg->InputCount << "\n"
        << "  Max input response = " << cmd->parg->MaxInputResponse << "\n"
        << "  Output offset = " << cmd->parg->OutputOffset << "\n"
        << "  Output count = " << cmd->parg->OutputCount << "\n"
        << "  Max output response  = " << cmd->parg->MaxOutputResponse << "\n";
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
    out << "  Control Code = " << res->CtlCode << "\n"
        << "  Input offset = " << res->InputOffset << "\n"
        << "  Input count = " << res->InputCount << "\n"
        << "  Output offset = " << res->OutputOffset << "\n"
        << "  Output count = " << res->OutputCount << "\n";
}
void PrintAnalyzer::cancelSMBv2(const SMBv2::CancelCommand* cmd,
                                const SMBv2::CancelRequest*,
                                const SMBv2::CancelResponce*)
{
    Commands cmdEnum = Commands::CANCEL;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
}
void PrintAnalyzer::echoSMBv2(const SMBv2::EchoCommand* cmd,
                              const SMBv2::EchoRequest*,
                              const SMBv2::EchoResponse*)
{
    Commands cmdEnum = Commands::ECHO;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
}
void PrintAnalyzer::queryDirSMBv2(const SMBv2::QueryDirCommand* cmd,
                                  const SMBv2::QueryDirRequest*,
                                  const SMBv2::QueryDirResponse*)
{
    Commands cmdEnum = Commands::QUERY_DIRECTORY;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    out << "\n  Info level = " << cmd->parg->infoType << "\n"
        << "  File index = " << cmd->parg->FileIndex << "\n";
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
}
void PrintAnalyzer::changeNotifySMBv2(const SMBv2::ChangeNotifyCommand* cmd,
                                      const SMBv2::ChangeNotifyRequest*,
                                      const SMBv2::ChangeNotifyResponse* res)
{
    Commands cmdEnum = Commands::CHANGE_NOTIFY;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    out << "  Length = 0x" << std::hex << cmd->parg->OutputBufferLength << std::dec << "\n";
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
    out << "  Length = 0x" << std::hex << res->OutputBufferLength << std::dec << "\n"
        << "  Offset = 0x" << std::hex << res->OutputBufferOffset << std::dec << "\n";
}
void PrintAnalyzer::queryInfoSMBv2(const SMBv2::QueryInfoCommand* cmd,
                                   const SMBv2::QueryInfoRequest*,
                                   const SMBv2::QueryInfoResponse* res)
{
    using namespace NST::API::SMBv2;
    Commands cmdEnum = Commands::QUERY_INFO;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    out << "  Class = " << cmd->parg->infoType << "\n";
    print_info_levels(out, cmd->parg->infoType, cmd->parg->FileInfoClass);
    //TODO: Print GUID handle file
    //print_file_name(out, cmd->parg->Buffer, cmd->parg->OutputBufferLength);
    print_smbv2_common_info_resp(out, cmdEnum, cmd);
    out << "  Offset = 0x" << std::hex << static_cast<uint32_t>(res->OutputBufferOffset) << std::dec << "\n"
        << "  Length = 0x" << std::hex << static_cast<uint32_t>(res->OutputBufferLength) << std::dec << "\n";
}
void PrintAnalyzer::setInfoSMBv2(const SMBv2::SetInfoCommand* cmd,
                                 const SMBv2::SetInfoRequest*,
                                 const SMBv2::SetInfoResponse*)
{
    Commands cmdEnum = Commands::SET_INFO;
    print_smbv2_common_info_req(out, cmdEnum, cmd);
    out << "  Class = " << cmd->parg->infoType << "\n";
    print_info_levels(out, cmd->parg->infoType, cmd->parg->FileInfoClass);
    //TODO: Print GUID handle file
    //print_file_name(out, cmd->parg->Buffer, cmd->parg->OutputBufferLength);
    out << "  Setinfo Size = " << cmd->parg->BufferLength << "\n"
        << "  Setinfo Offset = 0x" << std::hex << cmd->parg->BufferOffset << std::dec << "\n";

    print_smbv2_common_info_resp(out, cmdEnum, cmd);
}


// Print NFSv3 procedures (rpcgen)
// 1st line - PRC information: src and dst hosts, status of RPC procedure
// 2nd line - <tabulation>related RPC procedure-specific arguments
// 3rd line - <tabulation>related RPC procedure-specific results

void PrintAnalyzer::null(const RPCProcedure* proc,
                         const struct NFS3::NULL3args*,
                         const struct NFS3::NULL3res*)
{
    if (!print_procedure(out, proc)) { return; }
    out << "\tCALL  []\n\tREPLY []\n";
}

void PrintAnalyzer::getattr3(const RPCProcedure*              proc,
                             const struct NFS3::GETATTR3args* args,
                             const struct NFS3::GETATTR3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  ["
            << " object: " << args->object
            << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all() && res->status == NFS3::nfsstat3::NFS3_OK)
            out << " obj attributes: "
                << res->GETATTR3res_u.resok.obj_attributes;
        out << " ]\n";
    }
}

void PrintAnalyzer::setattr3(const RPCProcedure*              proc,
                             const struct NFS3::SETATTR3args* args,
                             const struct NFS3::SETATTR3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ object: " << args->object
            << " new attributes: "  << args->new_attributes
            << " guard: "           << args->guard
            << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj_wcc: "
                    << res->SETATTR3res_u.resok.obj_wcc;
            else
                out << " obj_wcc: "
                    << res->SETATTR3res_u.resfail.obj_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::lookup3(const RPCProcedure*             proc,
                            const struct NFS3::LOOKUP3args* args,
                            const struct NFS3::LOOKUP3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args) { out << "\tCALL  [ what: " << args->what << " ]\n"; }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " object: "
                    << res->LOOKUP3res_u.resok.object
                    << " object attributes: "
                    << res->LOOKUP3res_u.resok.obj_attributes
                    << " dir attributes: "
                    << res->LOOKUP3res_u.resok.dir_attributes;
            else
                out << " dir attributes: "
                    << res->LOOKUP3res_u.resfail.dir_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::access3(const RPCProcedure*             proc,
                            const struct NFS3::ACCESS3args* args,
                            const struct NFS3::ACCESS3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ object: ";
        print_nfs_fh(out,
                     args->object.data.data_val,
                     args->object.data.data_len);
        out << " access: ";
        print_access3(out, args->access);
        out << " ]\n";
    }

    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " object attributes: "
                    << res->ACCESS3res_u.resok.obj_attributes
                    << " access: ";
                print_access3(out, res->ACCESS3res_u.resok.access);
            }
            else
            {
                out << " access: "
                    << res->ACCESS3res_u.resfail.obj_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readlink3(const RPCProcedure*               proc,
                              const struct NFS3::READLINK3args* args,
                              const struct NFS3::READLINK3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args) { out << "\tCALL  [ symlink: " << args->symlink << " ]\n"; }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " symlink attributes: "
                    << res->READLINK3res_u.resok.symlink_attributes
                    << " data: "
                    << res->READLINK3res_u.resok.data;
            else
                out << " symlink attributes: "
                    << res->READLINK3res_u.resfail.symlink_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::read3(const RPCProcedure*           proc,
                          const struct NFS3::READ3args* args,
                          const struct NFS3::READ3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ file: " << args->file
            << " offset: " << args->offset
            << " count: "  << args->count
            << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " file attributes: "
                    << res->READ3res_u.resok.file_attributes
                    << " count: "
                    << res->READ3res_u.resok.count
                    << " eof: "
                    << res->READ3res_u.resok.eof;
            }
            else
            {
                out << " symlink attributes: "
                    << res->READ3res_u.resfail.file_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::write3(const RPCProcedure*            proc,
                           const struct NFS3::WRITE3args* args,
                           const struct NFS3::WRITE3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ file: " << args->file
            << " offset: " << args->offset
            << " count: "  << args->count
            << " stable: " << args->stable
            << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " file_wcc: "
                    << res->WRITE3res_u.resok.file_wcc
                    << " count: "
                    << res->WRITE3res_u.resok.count
                    << " committed: "
                    << res->WRITE3res_u.resok.committed
                    << " verf: ";
                print_hex(out,
                          res->WRITE3res_u.resok.verf,
                          NFS3::NFS3_WRITEVERFSIZE);
            }
            else
            {
                out << " file_wcc: "
                    << res->WRITE3res_u.resfail.file_wcc;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::create3(const RPCProcedure*             proc,
                            const struct NFS3::CREATE3args* args,
                            const struct NFS3::CREATE3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
        out << "\tCALL  [ where: " << args->where
            << " how: " << args->how
            << " ]\n";
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj: "
                    << res->CREATE3res_u.resok.obj
                    << " obj attributes: "
                    << res->CREATE3res_u.resok.obj_attributes
                    << " dir_wcc: "
                    << res->CREATE3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->CREATE3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::mkdir3(const RPCProcedure*            proc,
                           const struct NFS3::MKDIR3args* args,
                           const struct NFS3::MKDIR3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
        out << "\tCALL  [ where: " << args->where
            << " attributes: "     << args->attributes
            << " ]\n";
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj: "
                    << res->MKDIR3res_u.resok.obj
                    << " obj attributes: "
                    << res->MKDIR3res_u.resok.obj_attributes
                    << " dir_wcc: "
                    << res->MKDIR3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->MKDIR3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::symlink3(const RPCProcedure*              proc,
                             const struct NFS3::SYMLINK3args* args,
                             const struct NFS3::SYMLINK3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
        out << "\tCALL  [ where: " << args->where
            << " symlink: "        << args->symlink
            << " ]\n";
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj: "
                    << res->SYMLINK3res_u.resok.obj
                    << " obj attributes: "
                    << res->SYMLINK3res_u.resok.obj_attributes
                    << " dir_wcc: "
                    << res->SYMLINK3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->SYMLINK3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::mknod3(const RPCProcedure*            proc,
                           const struct NFS3::MKNOD3args* args,
                           const struct NFS3::MKNOD3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ where: " << args->where
            << " what: "           << args->what
            << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj: "
                    << res->MKNOD3res_u.resok.obj
                    << " obj attributes: "
                    << res->MKNOD3res_u.resok.obj_attributes
                    << " dir_wcc: "
                    << res->MKNOD3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->MKNOD3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::remove3(const RPCProcedure*             proc,
                            const struct NFS3::REMOVE3args* args,
                            const struct NFS3::REMOVE3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ object: " << args->object << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " dir_wcc: "
                    << res->REMOVE3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->REMOVE3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::rmdir3(const RPCProcedure*            proc,
                           const struct NFS3::RMDIR3args* args,
                           const struct NFS3::RMDIR3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ object: " << args->object << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " dir_wcc: "
                    << res->RMDIR3res_u.resok.dir_wcc;
            else
                out << " dir_wcc: "
                    << res->RMDIR3res_u.resfail.dir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::rename3(const RPCProcedure*             proc,
                            const struct NFS3::RENAME3args* args,
                            const struct NFS3::RENAME3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
        out << "\tCALL  [ from: " << args->from
            << " to: "            << args->to
            << " ]\n";
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " from dir_wcc: "
                    << res->RENAME3res_u.resok.fromdir_wcc
                    << " to dir_wcc: "
                    << res->RENAME3res_u.resok.todir_wcc;
            else
                out << " from dir_wcc: "
                    << res->RENAME3res_u.resfail.fromdir_wcc
                    << " to dir_wcc: "
                    << res->RENAME3res_u.resfail.todir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::link3(const RPCProcedure*           proc,
                          const struct NFS3::LINK3args* args,
                          const struct NFS3::LINK3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
        out << "\tCALL  [ file: " << args->file
            << " link: "          << args->link
            << " ]\n";
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " file attributes: "
                    << res->LINK3res_u.resok.file_attributes
                    << " link dir_wcc: "
                    << res->LINK3res_u.resok.linkdir_wcc;
            else
                out << " file attributes: "
                    << res->LINK3res_u.resfail.file_attributes
                    << " link dir_wcc: "
                    << res->LINK3res_u.resfail.linkdir_wcc;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readdir3(const RPCProcedure*              proc,
                             const struct NFS3::READDIR3args* args,
                             const struct NFS3::READDIR3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ dir: " << args->dir
            << " cookie: "       << args->cookie
            << " cookieverf: ";
        print_hex(out,
                  args->cookieverf,
                  NFS3::NFS3_COOKIEVERFSIZE);
        out << " count: " << args->count
            << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " dir attributes: "
                    << res->READDIR3res_u.resok.dir_attributes
                    << " cookieverf: ";
                print_hex(out,
                          res->READDIR3res_u.resok.cookieverf,
                          NFS3::NFS3_COOKIEVERFSIZE);
                out << " reply: "
                    << res->READDIR3res_u.resok.reply;
            }
            else
            {
                out << " dir attributes: "
                    << res->READDIR3res_u.resfail.dir_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::readdirplus3(const RPCProcedure*                  proc,
                                 const struct NFS3::READDIRPLUS3args* args,
                                 const struct NFS3::READDIRPLUS3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ dir: " << args->dir
            << " cookie: "       << args->cookie
            << " cookieverf: ";
        print_hex(out,
                  args->cookieverf,
                  NFS3::NFS3_COOKIEVERFSIZE);
        out << " dir count: " << args->dircount
            << " max count: " << args->maxcount
            << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " dir attributes: "
                    << res->READDIRPLUS3res_u.resok.dir_attributes
                    << " cookieverf: ";
                print_hex(out,
                          res->READDIRPLUS3res_u.resok.cookieverf,
                          NFS3::NFS3_COOKIEVERFSIZE);
                out << " reply: "
                    << res->READDIRPLUS3res_u.resok.reply;
            }
            else
            {
                out << " dir attributes: "
                    << res->READDIRPLUS3res_u.resfail.dir_attributes;
            }
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::fsstat3(const RPCProcedure*             proc,
                            const struct NFS3::FSSTAT3args* args,
                            const struct NFS3::FSSTAT3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ fsroot: " << args->fsroot << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj attributes: "
                    << res->FSSTAT3res_u.resok.obj_attributes
                    << " tbytes: "
                    << res->FSSTAT3res_u.resok.tbytes
                    << " fbytes: "
                    << res->FSSTAT3res_u.resok.fbytes
                    << " abytes: "
                    << res->FSSTAT3res_u.resok.abytes
                    << " tfile: "
                    << res->FSSTAT3res_u.resok.tfiles
                    << " ffile: "
                    << res->FSSTAT3res_u.resok.ffiles
                    << " afile: "
                    << res->FSSTAT3res_u.resok.afiles
                    << " invarsec: "
                    << res->FSSTAT3res_u.resok.invarsec;
            else
                out << " obj attributes: "
                    << res->FSSTAT3res_u.resfail.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::fsinfo3(const RPCProcedure*             proc,
                            const struct NFS3::FSINFO3args* args,
                            const struct NFS3::FSINFO3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ fsroot: " << args->fsroot << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj attributes: "
                    << res->FSINFO3res_u.resok.obj_attributes
                    << " rtmax: "
                    << res->FSINFO3res_u.resok.rtmax
                    << " rtpref: "
                    << res->FSINFO3res_u.resok.rtpref
                    << " rtmult: "
                    << res->FSINFO3res_u.resok.rtmult
                    << " wtmax: "
                    << res->FSINFO3res_u.resok.wtmax
                    << " wtpref: "
                    << res->FSINFO3res_u.resok.wtpref
                    << " wtmult: "
                    << res->FSINFO3res_u.resok.wtmult
                    << " dtpref: "
                    << res->FSINFO3res_u.resok.dtpref
                    << " max file size: "
                    << res->FSINFO3res_u.resok.maxfilesize
                    << " time delta: "
                    << res->FSINFO3res_u.resok.time_delta
                    << " properties: "
                    << res->FSINFO3res_u.resok.properties
                    << " LINK (filesystem supports hard links): "
                    << static_cast<bool>(res->FSINFO3res_u.resok.properties &
                                         NFS3::FSF3_LINK)
                    << " SYMLINK (file system supports symbolic links): "
                    << static_cast<bool>(res->FSINFO3res_u.resok.properties &
                                         NFS3::FSF3_SYMLINK)
                    << " HOMOGENEOUS (PATHCONF: is valid for all files): "
                    << static_cast<bool>(res->FSINFO3res_u.resok.properties &
                                         NFS3::FSF3_HOMOGENEOUS)
                    << " CANSETTIME (SETATTR can set time on server): "
                    << static_cast<bool>(res->FSINFO3res_u.resok.properties &
                                         NFS3::FSF3_CANSETTIME);
            else
                out << " obj attributes: "
                    << res->FSINFO3res_u.resfail.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::pathconf3(const RPCProcedure*               proc,
                              const struct NFS3::PATHCONF3args* args,
                              const struct NFS3::PATHCONF3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
    {
        out << "\tCALL  [ object: " << args->object << " ]\n";
    }
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
                out << " obj attributes: "
                    << res->PATHCONF3res_u.resok.obj_attributes
                    << " link max: "
                    << res->PATHCONF3res_u.resok.linkmax
                    << " name max: "
                    << res->PATHCONF3res_u.resok.name_max
                    << " no trunc: "
                    << res->PATHCONF3res_u.resok.no_trunc
                    << " chwon restricted: "
                    << res->PATHCONF3res_u.resok.chown_restricted
                    << " case insensitive: "
                    << res->PATHCONF3res_u.resok.case_insensitive
                    << " case preserving: "
                    << res->PATHCONF3res_u.resok.case_preserving;
            else
                out << " obj attributes: "
                    << res->PATHCONF3res_u.resfail.obj_attributes;
        }
        out << " ]\n";
    }
}

void PrintAnalyzer::commit3(const RPCProcedure*             proc,
                            const struct NFS3::COMMIT3args* args,
                            const struct NFS3::COMMIT3res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    if (args)
        out << "\tCALL  [ file: " << args->file
            << " offset: "        << args->offset
            << " count: "         << args->count
            << " ]\n";
    if (res)
    {
        out << "\tREPLY [ status: " << res->status;
        if (out_all())
        {
            if (res->status == NFS3::nfsstat3::NFS3_OK)
            {
                out << " file_wcc: "
                    << res->COMMIT3res_u.resok.file_wcc
                    << " verf: ";
                print_hex(out,
                          res->COMMIT3res_u.resok.verf,
                          NFS3::NFS3_WRITEVERFSIZE);
            }
            else
            {
                out << " file_wcc: "
                    << res->COMMIT3res_u.resfail.file_wcc;
            }
        }
        out << " ]\n";
    }
}


// Print NFSv4 procedures
// 1st line - PRC information: src and dst hosts, status of RPC procedure
// 2nd line - <tabulation>related RPC procedure-specific arguments
// 3rd line - <tabulation>related NFSv4-operations
// 4th line - <tabulation>related RPC procedure-specific results
// 5rd line - <tabulation>related NFSv4-operations

void PrintAnalyzer::null4(const RPCProcedure* proc,
                          const struct NFS4::NULL4args*,
                          const struct NFS4::NULL4res*)
{
    if (!print_procedure(out, proc)) { return; }

    out << "\tCALL  []\n\tREPLY []\n";
}

void PrintAnalyzer::compound4(const RPCProcedure*               proc,
                              const struct NFS4::COMPOUND4args* args,
                              const struct NFS4::COMPOUND4res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    const u_int* array_len {};
    if (args)
    {
        array_len = &args->argarray.argarray_len;
        out << "\tCALL  [ operations: " << *array_len
            << " tag: "                 << args->tag
            << " minor version: "       << args->minorversion;
        if (*array_len)
        {
            NFS4::nfs_argop4* current_el {args->argarray.argarray_val};
            for (u_int i = 0; i < *array_len; i++, current_el++)
            {
                out << "\n\t\t[ ";
                nfs4_operation(current_el);
                out << " ] ";
            }
            out << " ]\n";
        }
    }
    if (res)
    {
        array_len = &res->resarray.resarray_len;
        out << "\tREPLY [  operations: " << *array_len;
        if (*array_len)
        {
            NFS4::nfs_resop4* current_el {res->resarray.resarray_val};
            for (u_int i = 0; i < *array_len; i++, current_el++)
            {
                out << "\n\t\t[ ";
                nfs4_operation(current_el);
                out << " ] ";
            }
            out << " ]\n";
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::nfs_argop4* op)
{
    if (op)
    {
        out << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(op->argop))
            << '(' << op->argop << ") [ ";
        switch (op->argop)
        {
        case NFS4::OP_ACCESS:
            return nfs4_operation(&op->nfs_argop4_u.opaccess);
        case NFS4::OP_CLOSE:
            return nfs4_operation(&op->nfs_argop4_u.opclose);
        case NFS4::OP_COMMIT:
            return nfs4_operation(&op->nfs_argop4_u.opcommit);
        case NFS4::OP_CREATE:
            return nfs4_operation(&op->nfs_argop4_u.opcreate);
        case NFS4::OP_DELEGPURGE:
            return nfs4_operation(&op->nfs_argop4_u.opdelegpurge);
        case NFS4::OP_DELEGRETURN:
            return nfs4_operation(&op->nfs_argop4_u.opdelegreturn);
        case NFS4::OP_GETATTR:
            return nfs4_operation(&op->nfs_argop4_u.opgetattr);
        case NFS4::OP_GETFH:
            break; /* no such operation in call procedure */
        case NFS4::OP_LINK:
            return nfs4_operation(&op->nfs_argop4_u.oplink);
        case NFS4::OP_LOCK:
            return nfs4_operation(&op->nfs_argop4_u.oplock);
        case NFS4::OP_LOCKT:
            return nfs4_operation(&op->nfs_argop4_u.oplockt);
        case NFS4::OP_LOCKU:
            return nfs4_operation(&op->nfs_argop4_u.oplocku);
        case NFS4::OP_LOOKUP:
            return nfs4_operation(&op->nfs_argop4_u.oplookup);
        case NFS4::OP_LOOKUPP:
            break; /* no such operation in call procedure */
        case NFS4::OP_NVERIFY:
            return nfs4_operation(&op->nfs_argop4_u.opnverify);
        case NFS4::OP_OPEN:
            return nfs4_operation(&op->nfs_argop4_u.opopen);
        case NFS4::OP_OPENATTR:
            return nfs4_operation(&op->nfs_argop4_u.opopenattr);
        case NFS4::OP_OPEN_CONFIRM:
            return nfs4_operation(&op->nfs_argop4_u.opopen_confirm);
        case NFS4::OP_OPEN_DOWNGRADE:
            return nfs4_operation(&op->nfs_argop4_u.opopen_downgrade);
        case NFS4::OP_PUTFH:
            return nfs4_operation(&op->nfs_argop4_u.opputfh);
        case NFS4::OP_PUTPUBFH:
            break; /* no such operation in call procedure */
        case NFS4::OP_PUTROOTFH:
            break; /* no such operation in call procedure */
        case NFS4::OP_READ:
            return nfs4_operation(&op->nfs_argop4_u.opread);
        case NFS4::OP_READDIR:
            return nfs4_operation(&op->nfs_argop4_u.opreaddir);
        case NFS4::OP_READLINK:
            break; /* no such operation in call procedure */
        case NFS4::OP_REMOVE:
            return nfs4_operation(&op->nfs_argop4_u.opremove);
        case NFS4::OP_RENAME:
            return nfs4_operation(&op->nfs_argop4_u.oprename);
        case NFS4::OP_RENEW:
            return nfs4_operation(&op->nfs_argop4_u.oprenew);
        case NFS4::OP_RESTOREFH:
            break; /* no such operation in call procedure */
        case NFS4::OP_SAVEFH:
            break; /* no such operation in call procedure */
        case NFS4::OP_SECINFO:
            return nfs4_operation(&op->nfs_argop4_u.opsecinfo);
        case NFS4::OP_SETATTR:
            return nfs4_operation(&op->nfs_argop4_u.opsetattr);
        case NFS4::OP_SETCLIENTID:
            return nfs4_operation(&op->nfs_argop4_u.opsetclientid);
        case NFS4::OP_SETCLIENTID_CONFIRM:
            return nfs4_operation(&op->nfs_argop4_u.opsetclientid_confirm);
        case NFS4::OP_VERIFY:
            return nfs4_operation(&op->nfs_argop4_u.opverify);
        case NFS4::OP_WRITE:
            return nfs4_operation(&op->nfs_argop4_u.opwrite);
        case NFS4::OP_RELEASE_LOCKOWNER:
            return nfs4_operation(&op->nfs_argop4_u.oprelease_lockowner);
        case NFS4::OP_GET_DIR_DELEGATION:
            return nfs4_operation(&op->nfs_argop4_u.opget_dir_delegation);
        case NFS4::OP_ILLEGAL:
            break; /* no such operation in call procedure */
        }
        out << " ]";
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::nfs_resop4* op)
{
    if (op)
    {
        out << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(op->resop))
            << '(' << op->resop << ") [ ";
        switch (op->resop)
        {
        case NFS4::OP_ACCESS:
            return nfs4_operation(&op->nfs_resop4_u.opaccess);
        case NFS4::OP_CLOSE:
            return nfs4_operation(&op->nfs_resop4_u.opclose);
        case NFS4::OP_COMMIT:
            return nfs4_operation(&op->nfs_resop4_u.opcommit);
        case NFS4::OP_CREATE:
            return nfs4_operation(&op->nfs_resop4_u.opcreate);
        case NFS4::OP_DELEGPURGE:
            return nfs4_operation(&op->nfs_resop4_u.opdelegpurge);
        case NFS4::OP_DELEGRETURN:
            return nfs4_operation(&op->nfs_resop4_u.opdelegreturn);
        case NFS4::OP_GETATTR:
            return nfs4_operation(&op->nfs_resop4_u.opgetattr);
        case NFS4::OP_GETFH:
            return nfs4_operation(&op->nfs_resop4_u.opgetfh);
        case NFS4::OP_LINK:
            return nfs4_operation(&op->nfs_resop4_u.oplink);
        case NFS4::OP_LOCK:
            return nfs4_operation(&op->nfs_resop4_u.oplock);
        case NFS4::OP_LOCKT:
            return nfs4_operation(&op->nfs_resop4_u.oplockt);
        case NFS4::OP_LOCKU:
            return nfs4_operation(&op->nfs_resop4_u.oplocku);
        case NFS4::OP_LOOKUP:
            return nfs4_operation(&op->nfs_resop4_u.oplookup);
        case NFS4::OP_LOOKUPP:
            return nfs4_operation(&op->nfs_resop4_u.oplookupp);
        case NFS4::OP_NVERIFY:
            return nfs4_operation(&op->nfs_resop4_u.opnverify);
        case NFS4::OP_OPEN:
            return nfs4_operation(&op->nfs_resop4_u.opopen);
        case NFS4::OP_OPENATTR:
            return nfs4_operation(&op->nfs_resop4_u.opopenattr);
        case NFS4::OP_OPEN_CONFIRM:
            return nfs4_operation(&op->nfs_resop4_u.opopen_confirm);
        case NFS4::OP_OPEN_DOWNGRADE:
            return nfs4_operation(&op->nfs_resop4_u.opopen_downgrade);
        case NFS4::OP_PUTFH:
            return nfs4_operation(&op->nfs_resop4_u.opputfh);
        case NFS4::OP_PUTPUBFH:
            return nfs4_operation(&op->nfs_resop4_u.opputpubfh);
        case NFS4::OP_PUTROOTFH:
            return nfs4_operation(&op->nfs_resop4_u.opputrootfh);
        case NFS4::OP_READ:
            return nfs4_operation(&op->nfs_resop4_u.opread);
        case NFS4::OP_READDIR:
            return nfs4_operation(&op->nfs_resop4_u.opreaddir);
        case NFS4::OP_READLINK:
            return nfs4_operation(&op->nfs_resop4_u.opreadlink);
        case NFS4::OP_REMOVE:
            return nfs4_operation(&op->nfs_resop4_u.opremove);
        case NFS4::OP_RENAME:
            return nfs4_operation(&op->nfs_resop4_u.oprename);
        case NFS4::OP_RENEW:
            return nfs4_operation(&op->nfs_resop4_u.oprenew);
        case NFS4::OP_RESTOREFH:
            return nfs4_operation(&op->nfs_resop4_u.oprestorefh);
        case NFS4::OP_SAVEFH:
            return nfs4_operation(&op->nfs_resop4_u.opsavefh);
        case NFS4::OP_SECINFO:
            return nfs4_operation(&op->nfs_resop4_u.opsecinfo);
        case NFS4::OP_SETATTR:
            return nfs4_operation(&op->nfs_resop4_u.opsetattr);
        case NFS4::OP_SETCLIENTID:
            return nfs4_operation(&op->nfs_resop4_u.opsetclientid);
        case NFS4::OP_SETCLIENTID_CONFIRM:
            return nfs4_operation(&op->nfs_resop4_u.opsetclientid_confirm);
        case NFS4::OP_VERIFY:
            return nfs4_operation(&op->nfs_resop4_u.opverify);
        case NFS4::OP_WRITE:
            return nfs4_operation(&op->nfs_resop4_u.opwrite);
        case NFS4::OP_RELEASE_LOCKOWNER:
            return nfs4_operation(&op->nfs_resop4_u.oprelease_lockowner);
        case NFS4::OP_GET_DIR_DELEGATION:
            return nfs4_operation(&op->nfs_resop4_u.opget_dir_delegation);
        case NFS4::OP_ILLEGAL:
            return nfs4_operation(&op->nfs_resop4_u.opillegal);
        }
        out << " ]";
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::ACCESS4args* args)
{
    if (args)
    {
        if ((args->access) & NFS4::ACCESS4_READ) { out << "READ "; }
        if ((args->access) & NFS4::ACCESS4_LOOKUP) { out << "LOOKUP "; }
        if ((args->access) & NFS4::ACCESS4_MODIFY) { out << "MODIFY "; }
        if ((args->access) & NFS4::ACCESS4_EXTEND) { out << "EXTEND "; }
        if ((args->access) & NFS4::ACCESS4_DELETE) { out << "DELETE "; }
        if ((args->access) & NFS4::ACCESS4_EXECUTE) { out << "EXECUTE "; }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::ACCESS4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " supported: ";
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_READ)
            {
                out << "READ ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_LOOKUP)
            {
                out << "LOOKUP ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_MODIFY)
            {
                out << "MODIFY ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_EXTEND)
            {
                out << "EXTEND ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_DELETE)
            {
                out << "DELETE ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS4::ACCESS4_EXECUTE)
            {
                out << "EXECUTE ";
            }
            out << " access: ";
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_READ)
            {
                out << "READ ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_LOOKUP)
            {
                out << "LOOKUP ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_MODIFY)
            {
                out << "MODIFY ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_EXTEND)
            {
                out << "EXTEND ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_DELETE)
            {
                out << "DELETE ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS4::ACCESS4_EXECUTE)
            {
                out << "EXECUTE ";
            }
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::CLOSE4args* args)
{
    if (args)
    {
        out <<  "seqid: "        << std::hex << args->seqid << std::dec
            << " open state id:" << args->open_stateid;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::CLOSE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " open state id:" << res->CLOSE4res_u.open_stateid;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::COMMIT4args* args)
{
    if (args)
    {
        out <<  "offset: " << args->offset
            << " count: "  << args->count;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::COMMIT4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " write verifier: ";
            print_hex(out,
                      res->COMMIT4res_u.resok4.writeverf,
                      NFS4::NFS4_VERIFIER_SIZE);
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::CREATE4args* args)
{
    if (args)
    {
        out <<  "object type: "       << args->objtype
            << " object name: "       << args->objname
            << " create attributes: " << args->createattrs;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::CREATE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << res->CREATE4res_u.resok4.cinfo << ' '
                << res->CREATE4res_u.resok4.attrset;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::DELEGPURGE4args* args)
{
    if (args) { out << "client id: " << std::hex << args->clientid << std::dec; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::DELEGPURGE4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::DELEGRETURN4args* args)
{
    if (args) { out << args->deleg_stateid; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::DELEGRETURN4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GETATTR4args* args)
{
    if (args) { out << args->attr_request; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GETATTR4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << ' ' << res->GETATTR4res_u.resok4.obj_attributes;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LINK4args* args)
{
    if (args) { out << "new name: " << args->newname; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LINK4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << ' ' << res->LINK4res_u.resok4.cinfo;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCK4args* args)
{
    if (args)
    {
        out <<  "lock type: " << args->locktype
            << " reclaim: "   << args->reclaim
            << " offset: "    << args->offset
            << " length: "    << args->length
            << " locker: "    << args->locker;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCK4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all())
        {
            switch (res->status)
            {
            case NFS4::nfsstat4::NFS4_OK:
                out << " lock stat id: "
                    << res->LOCK4res_u.resok4.lock_stateid;
                break;
            case NFS4::nfsstat4::NFS4ERR_DENIED:
                out << " offset: "    << res->LOCK4res_u.denied.offset
                    << " length: "    << res->LOCK4res_u.denied.length
                    << " lock type: " << res->LOCK4res_u.denied.locktype
                    << " owner: "     << res->LOCK4res_u.denied.owner;
                break;
            default:
                break;
            }
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCKT4args* args)
{
    if (args)
    {
        out <<  "lock type: " << args->locktype
            << " offset: "    << args->offset
            << " length: "    << args->length
            << " owner: "     << args->owner;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCKT4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4ERR_DENIED)
            out << " offset: "    << res->LOCKT4res_u.denied.offset
                << " length: "    << res->LOCKT4res_u.denied.length
                << " lock type: " << res->LOCKT4res_u.denied.locktype
                << " owner: "     << res->LOCKT4res_u.denied.owner;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCKU4args* args)
{
    if (args)
    {
        out <<  "lock type: "     << args->locktype
            << " seqid: "       << std::hex << args->seqid << std::dec
            << " lock state id: " << args->lock_stateid
            << " offset: "        << args->offset
            << " length: "        << args->length;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOCKU4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " lock state id: " << res->LOCKU4res_u.lock_stateid;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOOKUP4args* args)
{
    if (args) { out << "object name: " << args->objname; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOOKUP4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::NVERIFY4args* args)
{
    if (args) { out << "object attributes: " << args->obj_attributes; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::NVERIFY4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN4args* args)
{
    static const char* const open4_share_access[4] = {"",    "READ", "WRITE", "BOTH"};
    static const char* const open4_share_deny[4]   = {"NONE", "READ", "WRITE", "BOTH"};

    if (args)
    {
        out <<  "seqid: " << std::hex << args->seqid << std::dec
            << " share access: " << open4_share_access[args->share_access]
            << " share deny: "   << open4_share_deny[args->share_deny]
            << ' ' << args->owner
            << ' ' << args->openhow
            << ' ' << args->claim;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << res->OPEN4res_u.resok4.stateid
                << res->OPEN4res_u.resok4.cinfo
                << " results flags: "
                << std::hex << res->OPEN4res_u.resok4.rflags << std::dec
                << ' ' << res->OPEN4res_u.resok4.attrset
                << ' ' << res->OPEN4res_u.resok4.delegation;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPENATTR4args* args)
{
    if (args) { out << "create directory: " << args->createdir; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPENATTR4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN_CONFIRM4args* args)
{
    if (args)
    {
        out <<  "open state id:" << args->open_stateid
            << " seqid: "        << std::hex << args->seqid << std::dec;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN_CONFIRM4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " open state id:" << res->OPEN_CONFIRM4res_u.resok4.open_stateid;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN_DOWNGRADE4args* args)
{
    if (args)
    {
        out << " open state id: " << args->open_stateid
            << " seqid: "       << std::hex << args->seqid << std::dec
            << " share access: "  << args->share_access
            << " share deny: "    << args->share_deny;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::OPEN_DOWNGRADE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << ' ' << res->OPEN_DOWNGRADE4res_u.resok4.open_stateid;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::PUTFH4args* args)
{
    if (args)
    {
        out << "object: ";
        print_nfs_fh(out, args->object.nfs_fh4_val, args->object.nfs_fh4_len);
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::PUTFH4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READ4args* args)
{
    if (args)
    {
        out << args->stateid
            << " offset: "   << args->offset
            << " count: "    << args->count;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READ4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " eof: " << res->READ4res_u.resok4.eof;
            if (res->READ4res_u.resok4.data.data_len)
            {
                out << " data : " << *res->READ4res_u.resok4.data.data_val;
            }
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READDIR4args* args)
{
    if (args)
    {
        out <<  "cookie: "             << args->cookie
            << " cookieverf: "         << args->cookieverf
            << " dir count: "          << args->dircount
            << " max count: "          << args->maxcount
            << " attributes request: " << args->attr_request;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READDIR4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << " cookie verifier: " << res->READDIR4res_u.resok4.cookieverf
                << " reply: "           << res->READDIR4res_u.resok4.reply;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::REMOVE4args* args)
{
    if (args) { out << "target: " << args->target; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::REMOVE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << ' ' << res->REMOVE4res_u.resok4.cinfo;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RENAME4args* args)
{
    if (args)
    {
        out <<  "old name: " << args->oldname
            << " new name: " << args->newname;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RENAME4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << " source: "
                << res->RENAME4res_u.resok4.source_cinfo
                << " target: "
                << res->RENAME4res_u.resok4.target_cinfo;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RENEW4args* args)
{
    if (args)
    {
        out << "client id: "
            << std::hex << args->clientid << std::dec;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RENEW4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SECINFO4args* args)
{
    if (args) { out << "name: " << args->name; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SECINFO4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            if (res->SECINFO4res_u.resok4.SECINFO4resok_len)
                out << " data : "
                    << *res->SECINFO4res_u.resok4.SECINFO4resok_val;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETATTR4args* args)
{
    if (args)
    {
        out << "state id:" << args->stateid
            << ' ' << args->obj_attributes;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETATTR4res*  res)
{
    if (res)
    {
        out <<  "status: " << res->status;
        if (out_all()) { out << ' ' << res->attrsset; }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETCLIENTID4args* args)
{
    if (args)
    {
        out << args->client
            << " callback: "
            << args->callback
            << " callback ident: "
            << std::hex << args->callback_ident << std::dec;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETCLIENTID4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all())
        {
            switch (res->status)
            {
            case NFS4::nfsstat4::NFS4_OK:
                out << " client id: "
                    << std::hex << res->SETCLIENTID4res_u.resok4.clientid << std::dec
                    << " verifier: ";
                print_hex(out,
                          res->SETCLIENTID4res_u.resok4.setclientid_confirm,
                          NFS4::NFS4_VERIFIER_SIZE);
                break;
            case NFS4::nfsstat4::NFS4ERR_CLID_INUSE:
                out << " client using: " << res->SETCLIENTID4res_u.client_using;
                break;
            default:
                break;
            }
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETCLIENTID_CONFIRM4args* args)
{
    if (args)
    {
        out << " client id: " << std::hex << args->clientid << std::dec
            << " verifier: ";
        print_hex(out, args->setclientid_confirm, NFS4::NFS4_VERIFIER_SIZE);
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SETCLIENTID_CONFIRM4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::VERIFY4args* args)
{
    if (args) { out << "object attributes: " << args->obj_attributes; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::VERIFY4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::WRITE4args* args)
{
    if (args)
    {
        out << args->stateid
            << " offset: "      << args->offset
            << " stable: "      << args->stable
            << " data length: " << args->data.data_len;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::WRITE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " count: "          << res->WRITE4res_u.resok4.count
                << " committed: "       << res->WRITE4res_u.resok4.committed
                << " write verifier: ";
            print_hex(out,
                      res->WRITE4res_u.resok4.writeverf,
                      NFS4::NFS4_VERIFIER_SIZE);
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RELEASE_LOCKOWNER4args* args)
{
    if (args) { out << "lock owner: " << args->lock_owner; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RELEASE_LOCKOWNER4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GET_DIR_DELEGATION4args* args)
{
    if (args)
        out <<  "client id: "                    << args->clientid
            << " notification types: "           << args->notif_types
            << " dir notification delay: "       << args->dir_notif_delay
            << " dir entry notification delay: " << args->dir_entry_notif_delay;
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GET_DIR_DELEGATION4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
            out << ' ' << res->GET_DIR_DELEGATION4res_u.resok4.stateid
                << " status: "
                << res->GET_DIR_DELEGATION4res_u.resok4.status
                << " notification types: "
                << res->GET_DIR_DELEGATION4res_u.resok4.notif_types
                << " dir: "
                << res->GET_DIR_DELEGATION4res_u.resok4.dir_notif_attrs
                << " dir entry: "
                << res->GET_DIR_DELEGATION4res_u.resok4.dir_entry_notif_attrs;
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::GETFH4res* res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " object: " << res->GETFH4res_u.resok4.object;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::LOOKUPP4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::PUTPUBFH4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::PUTROOTFH4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::READLINK4res* res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS4::nfsstat4::NFS4_OK)
        {
            out << " link: " << res->READLINK4res_u.resok4.link;
        }
    }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::RESTOREFH4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::SAVEFH4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs4_operation(const struct NFS4::ILLEGAL4res* res)
{
    if (res) { out << "status: " << res->status; }
}

// Print NFSv4.1 procedures
// 1st line - PRC information: src and dst hosts, status of RPC procedure
// 2nd line - <tabulation>related RPC procedure-specific arguments
// 3rd line - <tabulation>related NFSv4-operations
// 4th line - <tabulation>related RPC procedure-specific results
// 5rd line - <tabulation>related NFSv4-operations


void PrintAnalyzer::compound41(const RPCProcedure*                proc,
                               const struct NFS41::COMPOUND4args* args,
                               const struct NFS41::COMPOUND4res*  res)
{
    if (!print_procedure(out, proc)) { return; }

    const u_int* array_len {};
    if (args)
    {
        array_len = &args->argarray.argarray_len;
        out << "\tCALL  [ operations: " << *array_len
            << " tag: "                 << args->tag
            << " minor version: "       << args->minorversion;

        if (*array_len)
        {
            NFS41::nfs_argop4* current_el {args->argarray.argarray_val};
            for (u_int i {0}; i < *array_len; i++, current_el++)
            {
                out << "\n\t\t[ ";
                nfs41_operation(current_el);
                out << " ] ";
            }
            out << " ]\n";
        }
    }
    if (res)
    {
        array_len = &res->resarray.resarray_len;
        out << "\tREPLY [  operations: " << *array_len
            << " status: "               << res->status
            << " tag: "                  << res->tag;
        if (*array_len)
        {
            NFS41::nfs_resop4* current_el {res->resarray.resarray_val};
            for (u_int i {0}; i < *array_len; i++, current_el++)
            {
                out << "\n\t\t[ ";
                nfs41_operation(current_el);
                out << " ] ";
            }
            out << " ]\n";
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::nfs_argop4* op)
{
    if (op)
    {
        out << print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(op->argop))
            << '(' << op->argop << ") [ ";
        switch (op->argop)
        {
        case NFS41::OP_ACCESS:
            return nfs41_operation(&op->nfs_argop4_u.opaccess);
        case NFS41::OP_CLOSE:
            return nfs41_operation(&op->nfs_argop4_u.opclose);
        case NFS41::OP_COMMIT:
            return nfs41_operation(&op->nfs_argop4_u.opcommit);
        case NFS41::OP_CREATE:
            return nfs41_operation(&op->nfs_argop4_u.opcreate);
        case NFS41::OP_DELEGPURGE:
            return nfs41_operation(&op->nfs_argop4_u.opdelegpurge);
        case NFS41::OP_DELEGRETURN:
            return nfs41_operation(&op->nfs_argop4_u.opdelegreturn);
        case NFS41::OP_GETATTR:
            return nfs41_operation(&op->nfs_argop4_u.opgetattr);
        case NFS41::OP_GETFH:
            break;
        case NFS41::OP_LINK:
            return nfs41_operation(&op->nfs_argop4_u.oplink);
        case NFS41::OP_LOCK:
            return nfs41_operation(&op->nfs_argop4_u.oplock);
        case NFS41::OP_LOCKT:
            return nfs41_operation(&op->nfs_argop4_u.oplockt);
        case NFS41::OP_LOCKU:
            return nfs41_operation(&op->nfs_argop4_u.oplocku);
        case NFS41::OP_LOOKUP:
            return nfs41_operation(&op->nfs_argop4_u.oplookup);
        case NFS41::OP_LOOKUPP:
            break;
        case NFS41::OP_NVERIFY:
            return nfs41_operation(&op->nfs_argop4_u.opnverify);
        case NFS41::OP_OPEN:
            return nfs41_operation(&op->nfs_argop4_u.opopen);
        case NFS41::OP_OPENATTR:
            return nfs41_operation(&op->nfs_argop4_u.opopenattr);
        case NFS41::OP_OPEN_CONFIRM:
            return nfs41_operation(&op->nfs_argop4_u.opopen_confirm);
        case NFS41::OP_OPEN_DOWNGRADE:
            return nfs41_operation(&op->nfs_argop4_u.opopen_downgrade);
        case NFS41::OP_PUTFH:
            return nfs41_operation(&op->nfs_argop4_u.opputfh);
        case NFS41::OP_PUTPUBFH:
            break;
        case NFS41::OP_PUTROOTFH:
            break;
        case NFS41::OP_READ:
            return nfs41_operation(&op->nfs_argop4_u.opread);
        case NFS41::OP_READDIR:
            return nfs41_operation(&op->nfs_argop4_u.opreaddir);
        case NFS41::OP_READLINK:
            break;
        case NFS41::OP_REMOVE:
            return nfs41_operation(&op->nfs_argop4_u.opremove);
        case NFS41::OP_RENAME:
            return nfs41_operation(&op->nfs_argop4_u.oprename);
        case NFS41::OP_RENEW:
            return nfs41_operation(&op->nfs_argop4_u.oprenew);
        case NFS41::OP_RESTOREFH:
            break;
        case NFS41::OP_SAVEFH:
            break;
        case NFS41::OP_SECINFO:
            return nfs41_operation(&op->nfs_argop4_u.opsecinfo);
        case NFS41::OP_SETATTR:
            return nfs41_operation(&op->nfs_argop4_u.opsetattr);
        case NFS41::OP_SETCLIENTID:
            return nfs41_operation(&op->nfs_argop4_u.opsetclientid);
        case NFS41::OP_SETCLIENTID_CONFIRM:
            return nfs41_operation(&op->nfs_argop4_u.opsetclientid_confirm);
        case NFS41::OP_VERIFY:
            return nfs41_operation(&op->nfs_argop4_u.opverify);
        case NFS41::OP_WRITE:
            return nfs41_operation(&op->nfs_argop4_u.opwrite);
        case NFS41::OP_RELEASE_LOCKOWNER:
            return nfs41_operation(&op->nfs_argop4_u.oprelease_lockowner);
        case NFS41::OP_BACKCHANNEL_CTL:
            return nfs41_operation(&op->nfs_argop4_u.opbackchannel_ctl);
        case NFS41::OP_BIND_CONN_TO_SESSION:
            return nfs41_operation(&op->nfs_argop4_u.opbind_conn_to_session);
        case NFS41::OP_EXCHANGE_ID:
            return nfs41_operation(&op->nfs_argop4_u.opexchange_id);
        case NFS41::OP_CREATE_SESSION:
            return nfs41_operation(&op->nfs_argop4_u.opcreate_session);
        case NFS41::OP_DESTROY_SESSION:
            return nfs41_operation(&op->nfs_argop4_u.opdestroy_session);
        case NFS41::OP_FREE_STATEID:
            return nfs41_operation(&op->nfs_argop4_u.opfree_stateid);
        case NFS41::OP_GET_DIR_DELEGATION:
            return nfs41_operation(&op->nfs_argop4_u.opget_dir_delegation);
        case NFS41::OP_GETDEVICEINFO:
            return nfs41_operation(&op->nfs_argop4_u.opgetdeviceinfo);
        case NFS41::OP_GETDEVICELIST:
            return nfs41_operation(&op->nfs_argop4_u.opgetdevicelist);
        case NFS41::OP_LAYOUTCOMMIT:
            return nfs41_operation(&op->nfs_argop4_u.oplayoutcommit);
        case NFS41::OP_LAYOUTGET:
            return nfs41_operation(&op->nfs_argop4_u.oplayoutget);
        case NFS41::OP_LAYOUTRETURN:
            return nfs41_operation(&op->nfs_argop4_u.oplayoutreturn);
        case NFS41::OP_SECINFO_NO_NAME:
            return nfs41_operation(&op->nfs_argop4_u.opsecinfo_no_name);
        case NFS41::OP_SEQUENCE:
            return nfs41_operation(&op->nfs_argop4_u.opsequence);
        case NFS41::OP_SET_SSV:
            return nfs41_operation(&op->nfs_argop4_u.opset_ssv);
        case NFS41::OP_TEST_STATEID:
            return nfs41_operation(&op->nfs_argop4_u.optest_stateid);
        case NFS41::OP_WANT_DELEGATION:
            return nfs41_operation(&op->nfs_argop4_u.opwant_delegation);
        case NFS41::OP_DESTROY_CLIENTID:
            return nfs41_operation(&op->nfs_argop4_u.opdestroy_clientid);
        case NFS41::OP_RECLAIM_COMPLETE:
            return nfs41_operation(&op->nfs_argop4_u.opreclaim_complete);
        case NFS41::OP_ILLEGAL:
            break;
        default:
            break;
        }
        out << " ]";
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::nfs_resop4* op)
{
    if (op)
    {
        out << print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(op->resop))
            << '(' << op->resop << ") [ ";
        switch (op->resop)
        {
        case NFS41::OP_ACCESS:
            return nfs41_operation(&op->nfs_resop4_u.opaccess);
        case NFS41::OP_CLOSE:
            return nfs41_operation(&op->nfs_resop4_u.opclose);
        case NFS41::OP_COMMIT:
            return nfs41_operation(&op->nfs_resop4_u.opcommit);
        case NFS41::OP_CREATE:
            return nfs41_operation(&op->nfs_resop4_u.opcreate);
        case NFS41::OP_DELEGPURGE:
            return nfs41_operation(&op->nfs_resop4_u.opdelegpurge);
        case NFS41::OP_DELEGRETURN:
            return nfs41_operation(&op->nfs_resop4_u.opdelegreturn);
        case NFS41::OP_GETATTR:
            return nfs41_operation(&op->nfs_resop4_u.opgetattr);
        case NFS41::OP_GETFH:
            return nfs41_operation(&op->nfs_resop4_u.opgetfh);
        case NFS41::OP_LINK:
            return nfs41_operation(&op->nfs_resop4_u.oplink);
        case NFS41::OP_LOCK:
            return nfs41_operation(&op->nfs_resop4_u.oplock);
        case NFS41::OP_LOCKT:
            return nfs41_operation(&op->nfs_resop4_u.oplockt);
        case NFS41::OP_LOCKU:
            return nfs41_operation(&op->nfs_resop4_u.oplocku);
        case NFS41::OP_LOOKUP:
            return nfs41_operation(&op->nfs_resop4_u.oplookup);
        case NFS41::OP_LOOKUPP:
            return nfs41_operation(&op->nfs_resop4_u.oplookupp);
        case NFS41::OP_NVERIFY:
            return nfs41_operation(&op->nfs_resop4_u.opnverify);
        case NFS41::OP_OPEN:
            return nfs41_operation(&op->nfs_resop4_u.opopen);
        case NFS41::OP_OPENATTR:
            return nfs41_operation(&op->nfs_resop4_u.opopenattr);
        case NFS41::OP_OPEN_CONFIRM:
            return nfs41_operation(&op->nfs_resop4_u.opopen_confirm);
        case NFS41::OP_OPEN_DOWNGRADE:
            return nfs41_operation(&op->nfs_resop4_u.opopen_downgrade);
        case NFS41::OP_PUTFH:
            return nfs41_operation(&op->nfs_resop4_u.opputfh);
        case NFS41::OP_PUTPUBFH:
            return nfs41_operation(&op->nfs_resop4_u.opputpubfh);
        case NFS41::OP_PUTROOTFH:
            return nfs41_operation(&op->nfs_resop4_u.opputrootfh);
        case NFS41::OP_READ:
            return nfs41_operation(&op->nfs_resop4_u.opread);
        case NFS41::OP_READDIR:
            return nfs41_operation(&op->nfs_resop4_u.opreaddir);
        case NFS41::OP_READLINK:
            return nfs41_operation(&op->nfs_resop4_u.opreadlink);
        case NFS41::OP_REMOVE:
            return nfs41_operation(&op->nfs_resop4_u.opremove);
        case NFS41::OP_RENAME:
            return nfs41_operation(&op->nfs_resop4_u.oprename);
        case NFS41::OP_RENEW:
            return nfs41_operation(&op->nfs_resop4_u.oprenew);
        case NFS41::OP_RESTOREFH:
            return nfs41_operation(&op->nfs_resop4_u.oprestorefh);
        case NFS41::OP_SAVEFH:
            return nfs41_operation(&op->nfs_resop4_u.opsavefh);
        case NFS41::OP_SECINFO:
            return nfs41_operation(&op->nfs_resop4_u.opsecinfo);
        case NFS41::OP_SETATTR:
            return nfs41_operation(&op->nfs_resop4_u.opsetattr);
        case NFS41::OP_SETCLIENTID:
            return nfs41_operation(&op->nfs_resop4_u.opsetclientid);
        case NFS41::OP_SETCLIENTID_CONFIRM:
            return nfs41_operation(&op->nfs_resop4_u.opsetclientid_confirm);
        case NFS41::OP_VERIFY:
            return nfs41_operation(&op->nfs_resop4_u.opverify);
        case NFS41::OP_WRITE:
            return nfs41_operation(&op->nfs_resop4_u.opwrite);
        case NFS41::OP_RELEASE_LOCKOWNER:
            return nfs41_operation(&op->nfs_resop4_u.oprelease_lockowner);
        case NFS41::OP_BACKCHANNEL_CTL:
            return nfs41_operation(&op->nfs_resop4_u.opbackchannel_ctl);
        case NFS41::OP_BIND_CONN_TO_SESSION:
            return nfs41_operation(&op->nfs_resop4_u.opbind_conn_to_session);
        case NFS41::OP_EXCHANGE_ID:
            return nfs41_operation(&op->nfs_resop4_u.opexchange_id);
        case NFS41::OP_CREATE_SESSION:
            return nfs41_operation(&op->nfs_resop4_u.opcreate_session);
        case NFS41::OP_DESTROY_SESSION:
            return nfs41_operation(&op->nfs_resop4_u.opdestroy_session);
        case NFS41::OP_FREE_STATEID:
            return nfs41_operation(&op->nfs_resop4_u.opfree_stateid);
        case NFS41::OP_GET_DIR_DELEGATION:
            return nfs41_operation(&op->nfs_resop4_u.opget_dir_delegation);
        case NFS41::OP_GETDEVICEINFO:
            return nfs41_operation(&op->nfs_resop4_u.opgetdeviceinfo);
        case NFS41::OP_GETDEVICELIST:
            return nfs41_operation(&op->nfs_resop4_u.opgetdevicelist);
        case NFS41::OP_LAYOUTCOMMIT:
            return nfs41_operation(&op->nfs_resop4_u.oplayoutcommit);
        case NFS41::OP_LAYOUTGET:
            return nfs41_operation(&op->nfs_resop4_u.oplayoutget);
        case NFS41::OP_LAYOUTRETURN:
            return nfs41_operation(&op->nfs_resop4_u.oplayoutreturn);
        case NFS41::OP_SECINFO_NO_NAME:
            return nfs41_operation(&op->nfs_resop4_u.opsecinfo_no_name);
        case NFS41::OP_SEQUENCE:
            return nfs41_operation(&op->nfs_resop4_u.opsequence);
        case NFS41::OP_SET_SSV:
            return nfs41_operation(&op->nfs_resop4_u.opset_ssv);
        case NFS41::OP_TEST_STATEID:
            return nfs41_operation(&op->nfs_resop4_u.optest_stateid);
        case NFS41::OP_WANT_DELEGATION:
            return nfs41_operation(&op->nfs_resop4_u.opwant_delegation);
        case NFS41::OP_DESTROY_CLIENTID:
            return nfs41_operation(&op->nfs_resop4_u.opdestroy_clientid);
        case NFS41::OP_RECLAIM_COMPLETE:
            return nfs41_operation(&op->nfs_resop4_u.opreclaim_complete);
        case NFS41::OP_ILLEGAL:
            return nfs41_operation(&op->nfs_resop4_u.opillegal);
        default:
            break;
        }
        out << " ]";
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::ACCESS4args* args)
{
    if (args)
    {
        if ((args->access) & NFS41::ACCESS4_READ) { out << "READ "; }
        if ((args->access) & NFS41::ACCESS4_LOOKUP) { out << "LOOKUP "; }
        if ((args->access) & NFS41::ACCESS4_MODIFY) { out << "MODIFY "; }
        if ((args->access) & NFS41::ACCESS4_EXTEND) { out << "EXTEND "; }
        if ((args->access) & NFS41::ACCESS4_DELETE) { out << "DELETE "; }
        if ((args->access) & NFS41::ACCESS4_EXECUTE) { out << "EXECUTE "; }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::ACCESS4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " supported: ";
            if ((res->ACCESS4res_u.resok4.supported) & NFS41::ACCESS4_READ)
            {
                out << "READ ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS41::ACCESS4_LOOKUP)
            {
                out << "LOOKUP ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS41::ACCESS4_MODIFY)
            {
                out << "MODIFY ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS41::ACCESS4_EXTEND)
            {
                out << "EXTEND ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS41::ACCESS4_DELETE)
            {
                out << "DELETE ";
            }
            if ((res->ACCESS4res_u.resok4.supported) & NFS41::ACCESS4_EXECUTE)
            {
                out << "EXECUTE ";
            }
            out << " access: ";
            if ((res->ACCESS4res_u.resok4.access) & NFS41::ACCESS4_READ)
            {
                out << "READ ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS41::ACCESS4_LOOKUP)
            {
                out << "LOOKUP ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS41::ACCESS4_MODIFY)
            {
                out << "MODIFY ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS41::ACCESS4_EXTEND)
            {
                out << "EXTEND ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS41::ACCESS4_DELETE)
            {
                out << "DELETE ";
            }
            if ((res->ACCESS4res_u.resok4.access) & NFS41::ACCESS4_EXECUTE)
            {
                out << "EXECUTE ";
            }
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::CLOSE4args* args)
{
    if (args)
    {
        out <<  "seqid: "        << std::hex << args->seqid << std::dec
            << " open state id:" << args->open_stateid;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::CLOSE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " open state id:" << res->CLOSE4res_u.open_stateid;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::COMMIT4args* args)
{
    if (args)
    {
        out <<  "offset: " << args->offset
            << " count: "  << args->count;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::COMMIT4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " write verifier: ";
            print_hex(out,
                      res->COMMIT4res_u.resok4.writeverf,
                      NFS41::NFS4_VERIFIER_SIZE);
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::CREATE4args* args)
{
    if (args)
    {
        out <<  "object type: "       << args->objtype
            << " object name: "       << args->objname
            << " create attributes: " << args->createattrs;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::CREATE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
            out << res->CREATE4res_u.resok4.cinfo << ' '
                << res->CREATE4res_u.resok4.attrset;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::DELEGPURGE4args* args)
{
    if (args) { out << "client id: " << std::hex << args->clientid << std::dec; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::DELEGPURGE4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::DELEGRETURN4args* args)
{
    if (args) { out << args->deleg_stateid; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::DELEGRETURN4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::GETATTR4args* args)
{
    if (args) { out << args->attr_request; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::GETATTR4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << ' ' << res->GETATTR4res_u.resok4.obj_attributes;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LINK4args* args)
{
    if (args) { out << "new name: " << args->newname; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LINK4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << ' ' << res->LINK4res_u.resok4.cinfo;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LOCK4args* args)
{
    if (args)
    {
        out <<  "lock type: " << args->locktype
            << " reclaim: "   << args->reclaim
            << " offset: "    << args->offset
            << " length: "    << args->length
            << " locker: "    << args->locker;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LOCK4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all())
        {
            switch (res->status)
            {
            case NFS41::nfsstat4::NFS4_OK:
                out << " lock stat id: "
                    << res->LOCK4res_u.resok4.lock_stateid;
                break;
            case NFS41::nfsstat4::NFS4ERR_DENIED:
                out << " offset: "    << res->LOCK4res_u.denied.offset
                    << " length: "    << res->LOCK4res_u.denied.length
                    << " lock type: " << res->LOCK4res_u.denied.locktype
                    << " owner: "     << res->LOCK4res_u.denied.owner;
                break;
            default:
                break;
            }
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LOCKT4args* args)
{
    if (args)
    {
        out <<  "lock type: " << args->locktype
            << " offset: "    << args->offset
            << " length: "    << args->length
            << " owner: "     << args->owner;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LOCKT4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4ERR_DENIED)
            out << " offset: "    << res->LOCKT4res_u.denied.offset
                << " length: "    << res->LOCKT4res_u.denied.length
                << " lock type: " << res->LOCKT4res_u.denied.locktype
                << " owner: "     << res->LOCKT4res_u.denied.owner;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LOCKU4args* args)
{
    if (args)
    {
        out <<  "lock type: "     << args->locktype
            << " seqid: "       << std::hex << args->seqid << std::dec
            << " lock state id: " << args->lock_stateid
            << " offset: "        << args->offset
            << " length: "        << args->length;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LOCKU4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " lock state id: " << res->LOCKU4res_u.lock_stateid;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LOOKUP4args* args)
{
    if (args) { out << "object name: " << args->objname; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LOOKUP4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::NVERIFY4args* args)
{
    if (args) { out << "object attributes: " << args->obj_attributes; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::NVERIFY4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::OPEN4args* args)
{
    static const char* const open4_share_access[4] = {"",    "READ", "WRITE", "BOTH"};
    static const char* const open4_share_deny[4]   = {"NONE", "READ", "WRITE", "BOTH"};

    if (args)
    {
        out <<  "seqid: " << std::hex << args->seqid << std::dec
            << " share access: " << open4_share_access[args->share_access]
            << " share deny: "   << open4_share_deny[args->share_deny]
            << ' ' << args->owner
            << ' ' << args->openhow
            << ' ' << args->claim;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::OPEN4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
            out << res->OPEN4res_u.resok4.stateid
                << res->OPEN4res_u.resok4.cinfo
                << " results flags: "
                << std::hex << res->OPEN4res_u.resok4.rflags << std::dec
                << ' ' << res->OPEN4res_u.resok4.attrset
                << ' ' << res->OPEN4res_u.resok4.delegation;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::OPENATTR4args* args)
{
    if (args) { out << "create directory: " << args->createdir; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::OPENATTR4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::OPEN_CONFIRM4args* args)
{
    if (args)
    {
        out <<  "open state id:" << args->open_stateid
            << " seqid: "        << std::hex << args->seqid << std::dec;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::OPEN_CONFIRM4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " open state id:" << res->OPEN_CONFIRM4res_u.resok4.open_stateid;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::OPEN_DOWNGRADE4args* args)
{
    if (args)
    {
        out << " open state id: " << args->open_stateid
            << " seqid: "       << std::hex << args->seqid << std::dec
            << " share access: "  << args->share_access
            << " share deny: "    << args->share_deny;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::OPEN_DOWNGRADE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << ' ' << res->OPEN_DOWNGRADE4res_u.resok4.open_stateid;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::PUTFH4args* args)
{
    if (args)
    {
        out << "object: ";
        print_nfs_fh(out, args->object.nfs_fh4_val, args->object.nfs_fh4_len);
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::PUTFH4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::READ4args* args)
{
    if (args)
    {
        out << args->stateid
            << " offset: "   << args->offset
            << " count: "    << args->count;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::READ4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " eof: " << res->READ4res_u.resok4.eof;
            if (res->READ4res_u.resok4.data.data_len)
            {
                out << " data: " << *res->READ4res_u.resok4.data.data_val;
            }
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::READDIR4args* args)
{
    if (args)
    {
        out <<  "cookie: "             << args->cookie
            << " cookieverf: "         << args->cookieverf
            << " dir count: "          << args->dircount
            << " max count: "          << args->maxcount
            << " attributes request: " << args->attr_request;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::READDIR4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
            out << " cookie verifier: " << res->READDIR4res_u.resok4.cookieverf
                << " reply: "           << res->READDIR4res_u.resok4.reply;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::REMOVE4args* args)
{
    if (args) { out << "target: " << args->target; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::REMOVE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << ' ' << res->REMOVE4res_u.resok4.cinfo;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::RENAME4args* args)
{
    if (args)
    {
        out <<  "old name: " << args->oldname
            << " new name: " << args->newname;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::RENAME4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
            out << " source: "
                << res->RENAME4res_u.resok4.source_cinfo
                << " target: "
                << res->RENAME4res_u.resok4.target_cinfo;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::RENEW4args* args)
{
    if (args)
    {
        out << "client id: "
            << std::hex << args->clientid << std::dec;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::RENEW4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SECINFO4args* args)
{
    if (args) { out << "name: " << args->name; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SECINFO4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            if (res->SECINFO4res_u.resok4.SECINFO4resok_len)
            {
                out << *res->SECINFO4res_u.resok4.SECINFO4resok_val;
            }
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SETATTR4args* args)
{
    if (args)
    {
        out << "state id:" << args->stateid
            << ' ' << args->obj_attributes;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SETATTR4res*  res)
{
    if (res)
    {
        out <<  "status: " << res->status;
        if (out_all()) { out << ' ' << res->attrsset; }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SETCLIENTID4args* args)
{
    if (args)
    {
        out << args->client
            << " callback: "
            << args->callback
            << " callback ident: "
            << std::hex << args->callback_ident << std::dec;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SETCLIENTID4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all())
        {
            switch (res->status)
            {
            case NFS41::nfsstat4::NFS4_OK:
                out << " client id: "
                    << std::hex << res->SETCLIENTID4res_u.resok4.clientid << std::dec
                    << " verifier: ";
                print_hex(out,
                          res->SETCLIENTID4res_u.resok4.setclientid_confirm,
                          NFS41::NFS4_VERIFIER_SIZE);
                break;
            case NFS41::nfsstat4::NFS4ERR_CLID_INUSE:
                out << " client using: " << res->SETCLIENTID4res_u.client_using;
                break;
            default:
                break;
            }
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SETCLIENTID_CONFIRM4args* args)
{
    if (args)
    {
        out << " client id: " << std::hex << args->clientid << std::dec
            << " verifier: ";
        print_hex(out, args->setclientid_confirm, NFS41::NFS4_VERIFIER_SIZE);
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SETCLIENTID_CONFIRM4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::VERIFY4args* args)
{
    if (args) { out << "object attributes: " << args->obj_attributes; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::VERIFY4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::WRITE4args* args)
{
    if (args)
    {
        out << args->stateid
            << " offset: "      << args->offset
            << " stable: "      << args->stable
            << " data length: " << args->data.data_len;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::WRITE4res*  res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " count: "          << res->WRITE4res_u.resok4.count
                << " committed: "       << res->WRITE4res_u.resok4.committed
                << " write verifier: ";
            print_hex(out,
                      res->WRITE4res_u.resok4.writeverf,
                      NFS41::NFS4_VERIFIER_SIZE);
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::RELEASE_LOCKOWNER4args* args)
{
    if (args) { out << "lock owner: " << args->lock_owner; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::RELEASE_LOCKOWNER4res*  res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::GETFH4res* res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " object: " << res->GETFH4res_u.resok4.object;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LOOKUPP4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::PUTPUBFH4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::PUTROOTFH4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::READLINK4res* res)
{
    if (res)
    {
        out << "status: " << res->status;
        if (out_all() && res->status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " link: " << res->READLINK4res_u.resok4.link;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::RESTOREFH4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SAVEFH4res* res)
{
    if (res) { out << "status: " << res->status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::GET_DIR_DELEGATION4args* args)
{
    if (args)
        out <<  "signal delegation available: " << args->gdda_signal_deleg_avail
            << " notification types: "          << args->gdda_notification_types
            << " child attr delay: "            << args->gdda_child_attr_delay
            << " dir attr delay: "              << args->gdda_dir_attr_delay
            << " child child attributes: "      << args->gdda_child_attributes
            << " child dir attributes: "        << args->gdda_dir_attributes;
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::GET_DIR_DELEGATION4res*  res)
{
    if (res)
    {
        out << "status: " << res->gddr_status;
        if (out_all() && res->gddr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " status: " << res->GET_DIR_DELEGATION4res_u.gddr_res_non_fatal4.gddrnf_status;
            if (out_all() && res->GET_DIR_DELEGATION4res_u.gddr_res_non_fatal4.gddrnf_status == NFS41::gddrnf4_status::GDD4_OK)
            {
                out <<  " cookieverf: ";
                print_hex(out,
                          res->GET_DIR_DELEGATION4res_u.gddr_res_non_fatal4.GET_DIR_DELEGATION4res_non_fatal_u.gddrnf_resok4.gddr_cookieverf,
                          NFS41::NFS4_VERIFIER_SIZE);
                out << " stateid: "
                    <<  res->GET_DIR_DELEGATION4res_u.gddr_res_non_fatal4.GET_DIR_DELEGATION4res_non_fatal_u.gddrnf_resok4.gddr_stateid
                    << " notification: "
                    <<  res->GET_DIR_DELEGATION4res_u.gddr_res_non_fatal4.GET_DIR_DELEGATION4res_non_fatal_u.gddrnf_resok4.gddr_notification
                    << " child attributes: "
                    <<  res->GET_DIR_DELEGATION4res_u.gddr_res_non_fatal4.GET_DIR_DELEGATION4res_non_fatal_u.gddrnf_resok4.gddr_child_attributes
                    << " dir attributes: "
                    <<  res->GET_DIR_DELEGATION4res_u.gddr_res_non_fatal4.GET_DIR_DELEGATION4res_non_fatal_u.gddrnf_resok4.gddr_dir_attributes;
            }
            else
            {
                out << " will signal deleg avail: "
                    << res->GET_DIR_DELEGATION4res_u.gddr_res_non_fatal4.GET_DIR_DELEGATION4res_non_fatal_u.gddrnf_will_signal_deleg_avail;
            }
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::BACKCHANNEL_CTL4args* args)
{
    if (args)
    {
        out <<  "program: " << args->bca_cb_program
            << " sec parms: ";
        NFS41::callback_sec_parms4* current_el {args->bca_sec_parms.bca_sec_parms_val};
        for (u_int i {0}; i < args->bca_sec_parms.bca_sec_parms_len; i++, current_el++)
        {
            out << ' ' << current_el;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::BACKCHANNEL_CTL4res* res)
{
    if (res) { out << "status: " << res->bcr_status; }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::BIND_CONN_TO_SESSION4args* args)
{
    if (args)
    {
        out <<  "sessid: ";
        print_hex(out,
                  args->bctsa_sessid,
                  NFS41::NFS4_SESSIONID_SIZE);
        out << " dir: "                   << args->bctsa_dir
            << " use conn in rdma mode: " << args->bctsa_use_conn_in_rdma_mode;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::BIND_CONN_TO_SESSION4res* res)
{
    if (res)
    {
        out << "status: " << res->bctsr_status;
        if (out_all() && res->bctsr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " sessid: ";
            print_hex(out,
                      res->BIND_CONN_TO_SESSION4res_u.bctsr_resok4.bctsr_sessid,
                      NFS41::NFS4_SESSIONID_SIZE);
            out << " dir: "
                << res->BIND_CONN_TO_SESSION4res_u.bctsr_resok4.bctsr_dir
                << " use conn in rdma mode: "
                << res->BIND_CONN_TO_SESSION4res_u.bctsr_resok4.bctsr_use_conn_in_rdma_mode;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::EXCHANGE_ID4args* args)
{
    if (args)
    {
        out <<  "client owner: "  << args->eia_clientowner
            << " flags: "         << args->eia_flags
            << " state protect: " << args->eia_state_protect
            << " client impl id: ";
        NFS41::nfs_impl_id4* current_el {args->eia_client_impl_id.eia_client_impl_id_val};
        for (u_int i {0}; i < args->eia_client_impl_id.eia_client_impl_id_len; i++, current_el++)
        {
            out << ' ' << current_el;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::EXCHANGE_ID4res* res)
{
    if (res)
    {
        out << "status: " << res->eir_status;
        if (out_all() && res->eir_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " clientid: "                 << res->EXCHANGE_ID4res_u.eir_resok4.eir_clientid
                << " sequenceid: 0x" << std::hex << res->EXCHANGE_ID4res_u.eir_resok4.eir_sequenceid << std::dec
                << " flags: "                    << res->EXCHANGE_ID4res_u.eir_resok4.eir_flags
                << " state protect: "            << res->EXCHANGE_ID4res_u.eir_resok4.eir_state_protect
                << " server owner: "             << res->EXCHANGE_ID4res_u.eir_resok4.eir_server_owner
                << " server scope: ";
            print_hex(out,
                      res->EXCHANGE_ID4res_u.eir_resok4.eir_server_scope.eir_server_scope_val,
                      res->EXCHANGE_ID4res_u.eir_resok4.eir_server_scope.eir_server_scope_len);
            out << " server impl id:";
            NFS41::nfs_impl_id4* current_el {res->EXCHANGE_ID4res_u.eir_resok4.eir_server_impl_id.eir_server_impl_id_val};
            for (u_int i {0}; i < res->EXCHANGE_ID4res_u.eir_resok4.eir_server_impl_id.eir_server_impl_id_len; i++, current_el++)
            {
                out << ' ' << current_el;
            }
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::CREATE_SESSION4args* args)
{
    if (args)
    {
        out << "clientid: 0x" << std::hex        << args->csa_clientid
            << "; seqid: 0x" << std::hex         << args->csa_sequence << std::dec
            << "; flags: "                       << args->csa_flags
            << "; fore chan attrs: [ "           << args->csa_fore_chan_attrs << " ] "
            << "; fore back attrs: [ "           << args->csa_back_chan_attrs << " ] "
            << "; cb program: 0x" << std::hex    << args->csa_cb_program << std::dec
            << "; callback sec parms:";
        NFS41::callback_sec_parms4* current_el {args->csa_sec_parms.csa_sec_parms_val};
        for (u_int i {0}; i < args->csa_sec_parms.csa_sec_parms_len; i++, current_el++)
        {
            out << ' ' << current_el;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::CREATE_SESSION4res* res)
{
    if (res)
    {
        out << "status: " << res->csr_status;
        if (out_all() && res->csr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " session id: ";
            print_hex(out,
                      res->CREATE_SESSION4res_u.csr_resok4.csr_sessionid,
                      NFS41::NFS4_SESSIONID_SIZE);
            out << " sequenceid: 0x" << std::hex << res->CREATE_SESSION4res_u.csr_resok4.csr_sequence << std::dec
                << " flags: "                    << res->CREATE_SESSION4res_u.csr_resok4.csr_flags
                << " fore chan attrs: "          << res->CREATE_SESSION4res_u.csr_resok4.csr_fore_chan_attrs
                << " fore back attrs: "          << res->CREATE_SESSION4res_u.csr_resok4.csr_back_chan_attrs;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::DESTROY_SESSION4args* args)
{
    if (args)
    {
        out << "session id: ";
        print_hex(out,
                  args->dsa_sessionid,
                  NFS41::NFS4_SESSIONID_SIZE);
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::DESTROY_SESSION4res* res)
{
    if (res)
    {
        out << "status: " << res->dsr_status;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::FREE_STATEID4args* args)
{
    if (args)
    {
        out << "stateid: " << args->fsa_stateid;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::FREE_STATEID4res* res)
{
    if (res)
    {
        out << "status: " << res->fsr_status;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::GETDEVICEINFO4args* args)
{
    if (args)
    {
        out <<  "device id: "    << args->gdia_device_id
            << " layout type: "  << args->gdia_layout_type
            << " maxcount: "     << args->gdia_maxcount
            << " notify types: " << args->gdia_notify_types;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::GETDEVICEINFO4res* res)
{
    if (res)
    {
        out << "status: " << res->gdir_status;
        if (out_all())
        {
            if (res->gdir_status == NFS41::nfsstat4::NFS4_OK)
            {
                out << " device addr: "  << res->GETDEVICEINFO4res_u.gdir_resok4.gdir_device_addr
                    << " notification: " << res->GETDEVICEINFO4res_u.gdir_resok4.gdir_notification;
            }
            if (res->gdir_status == NFS41::nfsstat4::NFS4ERR_TOOSMALL)
            {
                out << " min count: " << res->GETDEVICEINFO4res_u.gdir_mincount;
            }
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::GETDEVICELIST4args* args)
{
    if (args)
    {
        out <<  "layout type: " << args->gdla_layout_type
            << " max devices: " << args->gdla_maxdevices
            << " cookie: "      << args->gdla_cookie
            << " cookieverf: "  << args->gdla_cookieverf;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::GETDEVICELIST4res* res)
{
    if (res)
    {
        out << "status: " << res->gdlr_status;
        if (out_all() && res->gdlr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " cookie: "      << res->GETDEVICELIST4res_u.gdlr_resok4.gdlr_cookie
                << " cookieverf: "  << res->GETDEVICELIST4res_u.gdlr_resok4.gdlr_cookieverf
                << " device id list: ";
            NFS41::deviceid4* current_el {res->GETDEVICELIST4res_u.gdlr_resok4.gdlr_deviceid_list.gdlr_deviceid_list_val};
            for (u_int i {0}; i < res->GETDEVICELIST4res_u.gdlr_resok4.gdlr_deviceid_list.gdlr_deviceid_list_len; i++, current_el++)
            {
                out << ' ' << current_el;
            }
            out << " eof: "  << res->GETDEVICELIST4res_u.gdlr_resok4.gdlr_eof;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LAYOUTCOMMIT4args* args)
{
    if (args)
    {
        out <<  "offset: "             << args->loca_offset
            << " length: "             << args->loca_length
            << " reclaim: "            << args->loca_reclaim
            << " stateid: "            << args->loca_stateid
            << " last write offset: "  << args->loca_last_write_offset
            << " time modify: "        << args->loca_time_modify
            << " tayout update: "      << args->loca_layoutupdate;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LAYOUTCOMMIT4res* res)
{
    if (res)
    {
        out << "status: " << res->locr_status;
        if (out_all() && res->locr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " new size: " << res->LAYOUTCOMMIT4res_u.locr_resok4.locr_newsize;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LAYOUTGET4args* args)
{
    if (args)
    {
        out <<  "signal layout avail: " << args->loga_signal_layout_avail
            << " layout type: "         << args->loga_layout_type
            << " iomode: "              << args->loga_iomode
            << " offset: "              << args->loga_offset
            << " length: "              << args->loga_length
            << " minlength: "           << args->loga_minlength
            << " stateid: "             << args->loga_stateid
            << " maxcount: "            << args->loga_maxcount;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LAYOUTGET4res* res)
{
    if (res)
    {
        out << "status: " << res->logr_status;
        if (out_all())
        {
            if (res->logr_status == NFS41::nfsstat4::NFS4_OK)
            {
                out << " return on close: "
                    << res->LAYOUTGET4res_u.logr_resok4.logr_return_on_close
                    << " stateid: "
                    << res->LAYOUTGET4res_u.logr_resok4.logr_stateid
                    << " layout:x ";
                NFS41::layout4* current_el = res->LAYOUTGET4res_u.logr_resok4.logr_layout.logr_layout_val;
                for (u_int i {0}; i < res->LAYOUTGET4res_u.logr_resok4.logr_layout.logr_layout_len; i++, current_el++)
                {
                    out << ' ' << current_el;
                }
            }
        }
        if (res->logr_status == NFS41::nfsstat4::NFS4ERR_LAYOUTTRYLATER)
        {
            out << "will signal layout avail: "
                << res->LAYOUTGET4res_u.logr_will_signal_layout_avail;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LAYOUTRETURN4args* args)
{
    if (args)
    {
        out <<  "reclaim: "       << args->lora_reclaim
            << " layout type: "   << args->lora_layout_type
            << " iomode: "        << args->lora_iomode
            << " layout return: " << args->lora_layoutreturn;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::LAYOUTRETURN4res* res)
{
    if (res)
    {
        out << "status: " << res->lorr_status;
        if (out_all() && res->lorr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " stateid: " << res->LAYOUTRETURN4res_u.lorr_stateid;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SEQUENCE4args* args)
{
    if (args)
    {
        out <<  "sessionid: ";
        print_hex(out,
                  args->sa_sessionid,
                  NFS41::NFS4_SESSIONID_SIZE);
        out << " sequenceid: 0x" << std::hex << args->sa_sequenceid << std::dec
            << " slotid: "       << args->sa_slotid
            << " cache this: "   << args->sa_cachethis;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SEQUENCE4res* res)
{
    if (res)
    {
        out << "status: " << res->sr_status;
        if (out_all() && res->sr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " session: ";
            print_hex(out,
                      res->SEQUENCE4res_u.sr_resok4.sr_sessionid,
                      NFS41::NFS4_SESSIONID_SIZE);
            out << " sequenceid: 0x" << std::hex << res->SEQUENCE4res_u.sr_resok4.sr_sequenceid << std::dec
                << " slotid: "                   << res->SEQUENCE4res_u.sr_resok4.sr_slotid
                << " highest slotid: "           << res->SEQUENCE4res_u.sr_resok4.sr_highest_slotid
                << " target highest slotid: "    << res->SEQUENCE4res_u.sr_resok4.sr_target_highest_slotid
                << " status flags: "             << res->SEQUENCE4res_u.sr_resok4.sr_status_flags;
        }
    }
}

//SECINFO_NO_NAME4args
void PrintAnalyzer::nfs41_operation(const enum NFS41::secinfo_style4* args)
{
    if (args)
    {
        out << ' ' << *args;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SET_SSV4args* args)
{
    if (args)
    {
        out << "ssv: ";
        out.write(args->ssa_ssv.ssa_ssv_val,
                  args->ssa_ssv.ssa_ssv_len);
        out << " digest: ";
        out.write(args->ssa_digest.ssa_digest_val,
                  args->ssa_digest.ssa_digest_len);
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::SET_SSV4res* res)
{
    if (res)
    {
        out << "status: " << res->ssr_status;
        if (out_all() && res->ssr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " digest: ";
            out.write(res->SET_SSV4res_u.ssr_resok4.ssr_digest.ssr_digest_val,
                      res->SET_SSV4res_u.ssr_resok4.ssr_digest.ssr_digest_len);
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::TEST_STATEID4args* args)
{
    if (args)
    {
        out << "stateids:";
        NFS41::stateid4* current_el = args->ts_stateids.ts_stateids_val;
        for (u_int i {0}; i < args->ts_stateids.ts_stateids_len; i++, current_el++)
        {
            out << ' ' << current_el;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::TEST_STATEID4res* res)
{
    if (res)
    {
        out << "status: " << res->tsr_status;
        if (out_all() && res->tsr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << " status codes: ";
            NFS41::nfsstat4* current_el = res->TEST_STATEID4res_u.tsr_resok4.tsr_status_codes.tsr_status_codes_val;
            for (u_int i {0}; i < res->TEST_STATEID4res_u.tsr_resok4.tsr_status_codes.tsr_status_codes_len; i++, current_el++)
            {
                out << ' ' << current_el;
            }
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::WANT_DELEGATION4args* args)
{
    if (args)
    {
        out <<  "want: "  << args->wda_want
            << " claim: " << args->wda_claim;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::WANT_DELEGATION4res* res)
{
    if (res)
    {
        out << "status: " << res->wdr_status;
        if (out_all() && res->wdr_status == NFS41::nfsstat4::NFS4_OK)
        {
            out << res->WANT_DELEGATION4res_u.wdr_resok4;
        }
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::DESTROY_CLIENTID4args* args)
{
    if (args)
    {
        out << "clientid: " << args->dca_clientid;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::DESTROY_CLIENTID4res* res)
{
    if (res)
    {
        out << "status: " << res->dcr_status;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::RECLAIM_COMPLETE4args* args)
{
    if (args)
    {
        out << "one fs: " << args->rca_one_fs;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::RECLAIM_COMPLETE4res* res)
{
    if (res)
    {
        out << "status: " << res->rcr_status;
    }
}

void PrintAnalyzer::nfs41_operation(const struct NFS41::ILLEGAL4res* res)
{
    if (res) { out << "status: " << res->status; }
}


void PrintAnalyzer::flush_statistics()
{
    // flush is in each handler
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
