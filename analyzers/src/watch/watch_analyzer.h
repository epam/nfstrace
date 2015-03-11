//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for WatchAnalyzer based on TestAnalyzer.h
// Copyright (c) 2014 EPAM Systems. All Rights Reserved.
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
#ifndef WATCH_ANALYZER_H
#define WATCH_ANALYZER_H
//------------------------------------------------------------------------------
#include <atomic>
#include <condition_variable>

#include <api/plugin_api.h> // include plugin development definitions
#include "protocols/nfsv3_protocol.h"
#include "protocols/nfsv4_protocol.h"
#include "protocols/nfsv41_protocol.h"
#include "protocols/cifsv2_protocol.h"
#include "user_gui.h"
//------------------------------------------------------------------------------
class WatchAnalyzer : public IAnalyzer
{
public:
    WatchAnalyzer(const char* opts);
    ~WatchAnalyzer();

    void flush_statistics() override final;
    void on_unix_signal(int signo) override final;
    // NFS v3
    virtual void null(const RPCProcedure*,
                      const struct NFS3::NULL3args*,
                      const struct NFS3::NULL3res*) override final;
    virtual void getattr3(const RPCProcedure*,
                          const struct NFS3::GETATTR3args*,
                          const struct NFS3::GETATTR3res*) override final;
    virtual void setattr3(const RPCProcedure*,
                          const struct NFS3::SETATTR3args*,
                          const struct NFS3::SETATTR3res*) override final;
    virtual void lookup3(const RPCProcedure*,
                         const struct NFS3::LOOKUP3args*,
                         const struct NFS3::LOOKUP3res*) override final;
    virtual void access3(const RPCProcedure*,
                         const struct NFS3::ACCESS3args*,
                         const struct NFS3::ACCESS3res*) override final;
    virtual void readlink3(const RPCProcedure*,
                           const struct NFS3::READLINK3args*,
                           const struct NFS3::READLINK3res*) override final;
    virtual void read3(const RPCProcedure*,
                       const struct NFS3::READ3args*,
                       const struct NFS3::READ3res*) override final;
    virtual void write3(const RPCProcedure*,
                        const struct NFS3::WRITE3args*,
                        const struct NFS3::WRITE3res*) override final;
    virtual void create3(const RPCProcedure*,
                         const struct NFS3::CREATE3args*,
                         const struct NFS3::CREATE3res*) override final;
    virtual void mkdir3(const RPCProcedure*,
                        const struct NFS3::MKDIR3args*,
                        const struct NFS3::MKDIR3res*) override final;
    virtual void symlink3(const RPCProcedure*,
                          const struct NFS3::SYMLINK3args*,
                          const struct NFS3::SYMLINK3res*) override final;
    virtual void mknod3(const RPCProcedure*,
                        const struct NFS3::MKNOD3args*,
                        const struct NFS3::MKNOD3res*) override final;
    virtual void remove3(const RPCProcedure*,
                         const struct NFS3::REMOVE3args*,
                         const struct NFS3::REMOVE3res*) override final;
    virtual void rmdir3(const RPCProcedure*,
                        const struct NFS3::RMDIR3args*,
                        const struct NFS3::RMDIR3res*) override final;
    virtual void rename3(const RPCProcedure*,
                         const struct NFS3::RENAME3args*,
                         const struct NFS3::RENAME3res*) override final;
    virtual void link3(const RPCProcedure*,
                       const struct NFS3::LINK3args*,
                       const struct NFS3::LINK3res*) override final;
    virtual void readdir3(const RPCProcedure*,
                          const struct NFS3::READDIR3args*,
                          const struct NFS3::READDIR3res*) override final;
    virtual void readdirplus3(const RPCProcedure*,
                              const struct NFS3::READDIRPLUS3args*,
                              const struct NFS3::READDIRPLUS3res*) override final;
    virtual void fsstat3(const RPCProcedure*,
                         const struct NFS3::FSSTAT3args*,
                         const struct NFS3::FSSTAT3res*) override final;
    virtual void fsinfo3(const RPCProcedure*,
                         const struct NFS3::FSINFO3args*,
                         const struct NFS3::FSINFO3res*) override final;
    virtual void pathconf3(const RPCProcedure*,
                           const struct NFS3::PATHCONF3args*,
                           const struct NFS3::PATHCONF3res*) override final;
    virtual void commit3(const RPCProcedure*,
                         const struct NFS3::COMMIT3args*,
                         const struct NFS3::COMMIT3res*) override final;
    // NFS v4
    virtual void null4(const RPCProcedure*,
                      const struct NFS4::NULL4args*,
                      const struct NFS4::NULL4res*) override final;
    virtual void compound4(const RPCProcedure*,
                           const struct NFS4::COMPOUND4args*,
                           const struct NFS4::COMPOUND4res*) override final;

    virtual void access40(const RPCProcedure*,
                          const struct NFS4::ACCESS4args*,
                          const struct NFS4::ACCESS4res*) override final;
    virtual void close40(const RPCProcedure*,
                         const struct NFS4::CLOSE4args*,
                         const struct NFS4::CLOSE4res*) override final;
    virtual void commit40(const RPCProcedure*,
                          const struct NFS4::COMMIT4args*,
                          const struct NFS4::COMMIT4res*) override final;
    virtual void create40(const RPCProcedure*,
                          const struct NFS4::CREATE4args*,
                          const struct NFS4::CREATE4res*) override final;
    virtual void delegpurge40(const RPCProcedure*,
                              const struct NFS4::DELEGPURGE4args*,
                              const struct NFS4::DELEGPURGE4res*) override final;
    virtual void delegreturn40(const RPCProcedure*,
                               const struct NFS4::DELEGRETURN4args*,
                               const struct NFS4::DELEGRETURN4res*) override final;
    virtual void getattr40(const RPCProcedure*,
                           const struct NFS4::GETATTR4args*,
                           const struct NFS4::GETATTR4res*) override final;
    virtual void getfh40(const RPCProcedure*,
                         const struct NFS4::GETFH4res*) override final;
    virtual void link40(const RPCProcedure*,
                        const struct NFS4::LINK4args*,
                        const struct NFS4::LINK4res*) override final;
    virtual void lock40(const RPCProcedure*,
                        const struct NFS4::LOCK4args*,
                        const struct NFS4::LOCK4res*) override final;
    virtual void lockt40(const RPCProcedure*,
                         const struct NFS4::LOCKT4args*,
                         const struct NFS4::LOCKT4res*) override final;
    virtual void locku40(const RPCProcedure*,
                         const struct NFS4::LOCKU4args*,
                         const struct NFS4::LOCKU4res*) override final;
    virtual void lookup40(const RPCProcedure*,
                          const struct NFS4::LOOKUP4args*,
                          const struct NFS4::LOOKUP4res*) override final;
    virtual void lookupp40(const RPCProcedure*,
                           const struct NFS4::LOOKUPP4res*) override final;
    virtual void nverify40(const RPCProcedure*,
                           const struct NFS4::NVERIFY4args*,
                           const struct NFS4::NVERIFY4res*) override final;
    virtual void open40(const RPCProcedure*,
                        const struct NFS4::OPEN4args*,
                        const struct NFS4::OPEN4res*) override final;
    virtual void openattr40(const RPCProcedure*,
                            const struct NFS4::OPENATTR4args*,
                            const struct NFS4::OPENATTR4res*) override final;
    virtual void open_confirm40(const RPCProcedure*,
                                const struct NFS4::OPEN_CONFIRM4args*,
                                const struct NFS4::OPEN_CONFIRM4res*) override final;
    virtual void open_downgrade40(const RPCProcedure*,
                                  const struct NFS4::OPEN_DOWNGRADE4args*,
                                  const struct NFS4::OPEN_DOWNGRADE4res*) override final;
    virtual void putfh40(const RPCProcedure*,
                         const struct NFS4::PUTFH4args*,
                         const struct NFS4::PUTFH4res*) override final;
    virtual void putpubfh40(const RPCProcedure*,
                            const struct NFS4::PUTPUBFH4res*) override final;
    virtual void putrootfh40(const RPCProcedure*,
                             const struct NFS4::PUTROOTFH4res*) override final;
    virtual void read40(const RPCProcedure*,
                        const struct NFS4::READ4args*,
                        const struct NFS4::READ4res*) override final;
    virtual void readdir40(const RPCProcedure*,
                           const struct NFS4::READDIR4args*,
                           const struct NFS4::READDIR4res*) override final;
    virtual void readlink40(const RPCProcedure*,
                            const struct NFS4::READLINK4res*) override final;
    virtual void remove40(const RPCProcedure*,
                          const struct NFS4::REMOVE4args*,
                          const struct NFS4::REMOVE4res*) override final;
    virtual void rename40(const RPCProcedure*,
                          const struct NFS4::RENAME4args*,
                          const struct NFS4::RENAME4res*) override final;
    virtual void renew40(const RPCProcedure*,
                         const struct NFS4::RENEW4args*,
                         const struct NFS4::RENEW4res*) override final;
    virtual void restorefh40(const RPCProcedure*,
                             const struct NFS4::RESTOREFH4res*) override final;
    virtual void savefh40(const RPCProcedure*,
                          const struct NFS4::SAVEFH4res*) override final;
    virtual void secinfo40(const RPCProcedure*,
                           const struct NFS4::SECINFO4args*,
                           const struct NFS4::SECINFO4res*) override final;
    virtual void setattr40(const RPCProcedure*,
                           const struct NFS4::SETATTR4args*,
                           const struct NFS4::SETATTR4res*) override final;
    virtual void setclientid40(const RPCProcedure*,
                               const struct NFS4::SETCLIENTID4args*,
                               const struct NFS4::SETCLIENTID4res*) override final;
    virtual void setclientid_confirm40(const RPCProcedure*,
                                       const struct NFS4::SETCLIENTID_CONFIRM4args*,
                                       const struct NFS4::SETCLIENTID_CONFIRM4res*) override final;
    virtual void verify40(const RPCProcedure*,
                          const struct NFS4::VERIFY4args*,
                          const struct NFS4::VERIFY4res*) override final;
    virtual void write40(const RPCProcedure*,
                         const struct NFS4::WRITE4args*,
                         const struct NFS4::WRITE4res*) override final;
    virtual void release_lockowner40(const RPCProcedure*,
                                     const struct NFS4::RELEASE_LOCKOWNER4args*,
                                     const struct NFS4::RELEASE_LOCKOWNER4res*) override final;
    virtual void get_dir_delegation40(const RPCProcedure*,
                                      const struct NFS4::GET_DIR_DELEGATION4args*,
                                      const struct NFS4::GET_DIR_DELEGATION4res*) override final;
    virtual void illegal40(const RPCProcedure*,
                           const struct NFS4::ILLEGAL4res*) override final;
    // NFS v41
    virtual void compound41(const RPCProcedure*,
                            const struct NFS41::COMPOUND4args*,
                            const struct NFS41::COMPOUND4res*) override final;

    virtual void access41(const RPCProcedure*,
                          const struct NFS41::ACCESS4args*,
                          const struct NFS41::ACCESS4res*) override final;
    virtual void close41(const RPCProcedure*,
                         const struct NFS41::CLOSE4args*,
                         const struct NFS41::CLOSE4res*) override final;
    virtual void commit41(const RPCProcedure*,
                          const struct NFS41::COMMIT4args*,
                          const struct NFS41::COMMIT4res*) override final;
    virtual void create41(const RPCProcedure*,
                          const struct NFS41::CREATE4args*,
                          const struct NFS41::CREATE4res*) override final;
    virtual void delegpurge41(const RPCProcedure*,
                              const struct NFS41::DELEGPURGE4args*,
                              const struct NFS41::DELEGPURGE4res*) override final;
    virtual void delegreturn41(const RPCProcedure*,
                               const struct NFS41::DELEGRETURN4args*,
                               const struct NFS41::DELEGRETURN4res*) override final;
    virtual void getattr41(const RPCProcedure*,
                           const struct NFS41::GETATTR4args*,
                           const struct NFS41::GETATTR4res*) override final;
    virtual void getfh41(const RPCProcedure*,
                         const struct NFS41::GETFH4res*) override final;
    virtual void link41(const RPCProcedure*,
                        const struct NFS41::LINK4args*,
                        const struct NFS41::LINK4res*) override final;
    virtual void lock41(const RPCProcedure*,
                        const struct NFS41::LOCK4args*,
                        const struct NFS41::LOCK4res*) override final;
    virtual void lockt41(const RPCProcedure*,
                         const struct NFS41::LOCKT4args*,
                         const struct NFS41::LOCKT4res*) override final;
    virtual void locku41(const RPCProcedure*,
                         const struct NFS41::LOCKU4args*,
                         const struct NFS41::LOCKU4res*) override final;
    virtual void lookup41(const RPCProcedure*,
                          const struct NFS41::LOOKUP4args*,
                          const struct NFS41::LOOKUP4res*) override final;
    virtual void lookupp41(const RPCProcedure*,
                           const struct NFS41::LOOKUPP4res*) override final;
    virtual void nverify41(const RPCProcedure*,
                           const struct NFS41::NVERIFY4args*,
                           const struct NFS41::NVERIFY4res*) override final;
    virtual void open41(const RPCProcedure*,
                        const struct NFS41::OPEN4args*,
                        const struct NFS41::OPEN4res*) override final;
    virtual void openattr41(const RPCProcedure*,
                            const struct NFS41::OPENATTR4args*,
                            const struct NFS41::OPENATTR4res*) override final;
    virtual void open_confirm41(const RPCProcedure*,
                                const struct NFS41::OPEN_CONFIRM4args*,
                                const struct NFS41::OPEN_CONFIRM4res*) override final;
    virtual void open_downgrade41(const RPCProcedure*,
                                  const struct NFS41::OPEN_DOWNGRADE4args*,
                                  const struct NFS41::OPEN_DOWNGRADE4res*) override final;
    virtual void putfh41(const RPCProcedure*,
                         const struct NFS41::PUTFH4args*,
                         const struct NFS41::PUTFH4res*) override final;
    virtual void putpubfh41(const RPCProcedure*,
                            const struct NFS41::PUTPUBFH4res*) override final;
    virtual void putrootfh41(const RPCProcedure*,
                             const struct NFS41::PUTROOTFH4res*) override final;
    virtual void read41(const RPCProcedure*,
                        const struct NFS41::READ4args*,
                        const struct NFS41::READ4res*) override final;
    virtual void readdir41(const RPCProcedure*,
                           const struct NFS41::READDIR4args*,
                           const struct NFS41::READDIR4res*) override final;
    virtual void readlink41(const RPCProcedure*,
                            const struct NFS41::READLINK4res*) override final;
    virtual void remove41(const RPCProcedure*,
                          const struct NFS41::REMOVE4args*,
                          const struct NFS41::REMOVE4res*) override final;
    virtual void rename41(const RPCProcedure*,
                          const struct NFS41::RENAME4args*,
                          const struct NFS41::RENAME4res*) override final;
    virtual void renew41(const RPCProcedure*,
                         const struct NFS41::RENEW4args*,
                         const struct NFS41::RENEW4res*) override final;
    virtual void restorefh41(const RPCProcedure*,
                             const struct NFS41::RESTOREFH4res*) override final;
    virtual void savefh41(const RPCProcedure*,
                          const struct NFS41::SAVEFH4res*) override final;
    virtual void secinfo41(const RPCProcedure*,
                           const struct NFS41::SECINFO4args*,
                           const struct NFS41::SECINFO4res*) override final;
    virtual void setattr41(const RPCProcedure*,
                           const struct NFS41::SETATTR4args*,
                           const struct NFS41::SETATTR4res*) override final;
    virtual void setclientid41(const RPCProcedure*,
                               const struct NFS41::SETCLIENTID4args*,
                               const struct NFS41::SETCLIENTID4res*) override final;
    virtual void setclientid_confirm41(const RPCProcedure*,
                                       const struct NFS41::SETCLIENTID_CONFIRM4args*,
                                       const struct NFS41::SETCLIENTID_CONFIRM4res*) override final;
    virtual void verify41(const RPCProcedure*,
                          const struct NFS41::VERIFY4args*,
                          const struct NFS41::VERIFY4res*) override final;
    virtual void write41(const RPCProcedure*,
                         const struct NFS41::WRITE4args*,
                         const struct NFS41::WRITE4res*) override final;
    virtual void release_lockowner41(const RPCProcedure*,
                                     const struct NFS41::RELEASE_LOCKOWNER4args*,
                                     const struct NFS41::RELEASE_LOCKOWNER4res*) override final;
    virtual void backchannel_ctl41(const RPCProcedure*,
                                   const struct NFS41::BACKCHANNEL_CTL4args*,
                                   const struct NFS41::BACKCHANNEL_CTL4res*) override final;
    virtual void bind_conn_to_session41(const RPCProcedure*,
                                        const struct NFS41::BIND_CONN_TO_SESSION4args*,
                                        const struct NFS41::BIND_CONN_TO_SESSION4res*) override final;
    virtual void exchange_id41(const RPCProcedure*,
                               const struct NFS41::EXCHANGE_ID4args*,
                               const struct NFS41::EXCHANGE_ID4res*) override final;
    virtual void create_session41(const RPCProcedure*,
                                  const struct NFS41::CREATE_SESSION4args*,
                                  const struct NFS41::CREATE_SESSION4res*) override final;
    virtual void destroy_session41(const RPCProcedure*,
                                   const struct NFS41::DESTROY_SESSION4args*,
                                   const struct NFS41::DESTROY_SESSION4res*) override final;
    virtual void free_stateid41(const RPCProcedure*,
                                const struct NFS41::FREE_STATEID4args*,
                                const struct NFS41::FREE_STATEID4res*) override final;
    virtual void get_dir_delegation41(const RPCProcedure*,
                                      const struct NFS41::GET_DIR_DELEGATION4args*,
                                      const struct NFS41::GET_DIR_DELEGATION4res*) override final;
    virtual void getdeviceinfo41(const RPCProcedure*,
                                 const struct NFS41::GETDEVICEINFO4args*,
                                 const struct NFS41::GETDEVICEINFO4res*) override final;
    virtual void getdevicelist41(const RPCProcedure*,
                                 const struct NFS41::GETDEVICELIST4args*,
                                 const struct NFS41::GETDEVICELIST4res*) override final;
    virtual void layoutcommit41(const RPCProcedure*,
                                const struct NFS41::LAYOUTCOMMIT4args*,
                                const struct NFS41::LAYOUTCOMMIT4res*) override final;
    virtual void layoutget41(const RPCProcedure*,
                             const struct NFS41::LAYOUTGET4args*,
                             const struct NFS41::LAYOUTGET4res*) override final;
    virtual void layoutreturn41(const RPCProcedure*,
                                const struct NFS41::LAYOUTRETURN4args*,
                                const struct NFS41::LAYOUTRETURN4res*) override final;
    virtual void secinfo_no_name41(const RPCProcedure*,
                                   const NFS41::SECINFO_NO_NAME4args*,
                                   const NFS41::SECINFO_NO_NAME4res*) override final;
    virtual void sequence41(const RPCProcedure*,
                            const struct NFS41::SEQUENCE4args*,
                            const struct NFS41::SEQUENCE4res*) override final;
    virtual void set_ssv41(const RPCProcedure*,
                           const struct NFS41::SET_SSV4args*,
                           const struct NFS41::SET_SSV4res*) override final;
    virtual void test_stateid41(const RPCProcedure*,
                                const struct NFS41::TEST_STATEID4args*,
                                const struct NFS41::TEST_STATEID4res*) override final;
    virtual void want_delegation41(const RPCProcedure*,
                                   const struct NFS41::WANT_DELEGATION4args*,
                                   const struct NFS41::WANT_DELEGATION4res*) override final;
    virtual void destroy_clientid41(const RPCProcedure*,
                                    const struct NFS41::DESTROY_CLIENTID4args*,
                                    const struct NFS41::DESTROY_CLIENTID4res*) override final;
    virtual void reclaim_complete41(const RPCProcedure*,
                                    const struct NFS41::RECLAIM_COMPLETE4args*,
                                    const struct NFS41::RECLAIM_COMPLETE4res*) override final;
    virtual void illegal41(const RPCProcedure*,
                           const struct NFS41::ILLEGAL4res*) override final;
    // CIFS v2
    virtual void closeFileSMBv2(const SMBv2::CloseFileCommand*, const SMBv2::CloseRequest*, const SMBv2::CloseResponse*) override final;
    virtual void negotiateSMBv2(const SMBv2::NegotiateCommand*, const SMBv2::NegotiateRequest*, const SMBv2::NegotiateResponse*) override final;
    virtual void sessionSetupSMBv2(const SMBv2::SessionSetupCommand*, const SMBv2::SessionSetupRequest*, const SMBv2::SessionSetupResponse*) override final;
    virtual void logOffSMBv2(const SMBv2::LogOffCommand*, const SMBv2::LogOffRequest*, const SMBv2::LogOffResponse*) override final;
    virtual void treeConnectSMBv2(const SMBv2::TreeConnectCommand*, const SMBv2::TreeConnectRequest*, const SMBv2::TreeConnectResponse*) override final;
    virtual void treeDisconnectSMBv2(const SMBv2::TreeDisconnectCommand*, const SMBv2::TreeDisconnectRequest*, const SMBv2::TreeDisconnectResponse*) override final;
    virtual void createSMBv2(const SMBv2::CreateCommand*, const SMBv2::CreateRequest*, const SMBv2::CreateResponse*) override final;
    virtual void flushSMBv2(const SMBv2::FlushCommand*, const SMBv2::FlushRequest*, const SMBv2::FlushResponse*) override final;
    virtual void readSMBv2(const SMBv2::ReadCommand*, const SMBv2::ReadRequest*, const SMBv2::ReadResponse*) override final;
    virtual void writeSMBv2(const SMBv2::WriteCommand*, const SMBv2::WriteRequest*, const SMBv2::WriteResponse*) override final;
    virtual void lockSMBv2(const SMBv2::LockCommand*, const SMBv2::LockRequest*, const SMBv2::LockResponse*) override final;
    virtual void ioctlSMBv2(const SMBv2::IoctlCommand*, const SMBv2::IoCtlRequest*, const SMBv2::IoCtlResponse*) override final;
    virtual void cancelSMBv2(const SMBv2::CancelCommand*, const SMBv2::CancelRequest*, const SMBv2::CancelResponce*) override final;
    virtual void echoSMBv2(const SMBv2::EchoCommand*, const SMBv2::EchoRequest*, const SMBv2::EchoResponse*) override final;
    virtual void queryDirSMBv2(const SMBv2::QueryDirCommand*, const SMBv2::QueryDirRequest*, const SMBv2::QueryDirResponse*) override final;
    virtual void changeNotifySMBv2(const SMBv2::ChangeNotifyCommand*, const SMBv2::ChangeNotifyRequest*, const SMBv2::ChangeNotifyResponse*) override final;
    virtual void queryInfoSMBv2(const SMBv2::QueryInfoCommand*, const SMBv2::QueryInfoRequest*, const SMBv2::QueryInfoResponse*) override final;
    virtual void setInfoSMBv2(const SMBv2::SetInfoCommand*, const SMBv2::SetInfoRequest*, const SMBv2::SetInfoResponse*) override final;
    virtual void breakOplockSMBv2(const SMBv2::BreakOpLockCommand*, const SMBv2::OplockAcknowledgment*, const SMBv2::OplockResponse*) override final;

private:

    template<typename Cmd, typename Code>
    void cifs_account(const Cmd* /*proc*/, Code cmd_code)
    {
        std::vector<std::size_t> cifsv2_proc_count (SMBv2Commands::Commands::CMD_COUNT, 0);
        ++cifsv2_proc_count[static_cast<int>(cmd_code)];
        gui.update(&_cifsv2, cifsv2_proc_count);
    }

    void count_proc(const RPCProcedure* proc);
    void nfs_account(const RPCProcedure*,
                     const unsigned int nfs_minor_vers = NFS_V41);
    void account40_op(const RPCProcedure*, const ProcEnumNFS4::NFSProcedure);
    void account41_op(const RPCProcedure*, const ProcEnumNFS41::NFSProcedure);

    CIFSv2Protocol _cifsv2;
    NFSv41Protocol _nfsv41;
    NFSv4Protocol  _nfsv4;
    NFSv3Protocol  _nfsv3;

    std::vector<AbstractProtocol* > protocols;
    UserGUI gui;
};
//------------------------------------------------------------------------------
#endif // WATCH_ANALYZER_H
//------------------------------------------------------------------------------
