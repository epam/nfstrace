//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: JSON analyzer class declaration
// Copyright (c) 2013-2014 EPAM Systems
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
#ifndef JSON_ANALYZER_H
#define JSON_ANALYZER_H
//------------------------------------------------------------------------------
#include <atomic>

#include "api/ianalyzer_type.h"
#include "json_tcp_service.h"
//------------------------------------------------------------------------------

using namespace NST::API;

class JsonAnalyzer : public IAnalyzer
{
public:
    struct NfsV3Stat
    {
        // Procedures:
        std::atomic_int nullProcsAmount = {0};
        std::atomic_int getattrProcsAmount = {0};
        std::atomic_int setattrProcsAmount = {0};
        std::atomic_int lookupProcsAmount = {0};
        std::atomic_int accessProcsAmount = {0};
        std::atomic_int readlinkProcsAmount = {0};
        std::atomic_int readProcsAmount = {0};
        std::atomic_int writeProcsAmount = {0};
        std::atomic_int createProcsAmount = {0};
        std::atomic_int mkdirProcsAmount = {0};
        std::atomic_int symlinkProcsAmount = {0};
        std::atomic_int mknodProcsAmount = {0};
        std::atomic_int removeProcsAmount = {0};
        std::atomic_int rmdirProcsAmount = {0};
        std::atomic_int renameProcsAmount = {0};
        std::atomic_int linkProcsAmount = {0};
        std::atomic_int readdirProcsAmount = {0};
        std::atomic_int readdirplusProcsAmount = {0};
        std::atomic_int fsstatProcsAmount = {0};
        std::atomic_int fsinfoProcsAmount = {0};
        std::atomic_int pathconfProcsAmount = {0};
        std::atomic_int commitProcsAmount = {0};
    };
    struct NfsV40Stat
    {
        // Procedures:
        std::atomic_int nullProcsAmount = {0};
        std::atomic_int compoundProcsAmount = {0};

        // Operations:
        std::atomic_int accessOpsAmount = {0};
        std::atomic_int closeOpsAmount = {0};
        std::atomic_int commitOpsAmount = {0};
        std::atomic_int createOpsAmount = {0};
        std::atomic_int delegpurgeOpsAmount = {0};
        std::atomic_int delegreturnOpsAmount = {0};
        std::atomic_int getattrOpsAmount = {0};
        std::atomic_int getfhOpsAmount = {0};
        std::atomic_int linkOpsAmount = {0};
        std::atomic_int lockOpsAmount = {0};
        std::atomic_int locktOpsAmount = {0};
        std::atomic_int lockuOpsAmount = {0};
        std::atomic_int lookupOpsAmount = {0};
        std::atomic_int lookuppOpsAmount = {0};
        std::atomic_int nverifyOpsAmount = {0};
        std::atomic_int openOpsAmount = {0};
        std::atomic_int openattrOpsAmount = {0};
        std::atomic_int open_confirmOpsAmount = {0};
        std::atomic_int open_downgradeOpsAmount = {0};
        std::atomic_int putfhOpsAmount = {0};
        std::atomic_int putpubfhOpsAmount = {0};
        std::atomic_int putrootfhOpsAmount = {0};
        std::atomic_int readOpsAmount = {0};
        std::atomic_int readdirOpsAmount = {0};
        std::atomic_int readlinkOpsAmount = {0};
        std::atomic_int removeOpsAmount = {0};
        std::atomic_int renameOpsAmount = {0};
        std::atomic_int renewOpsAmount = {0};
        std::atomic_int restorefhOpsAmount = {0};
        std::atomic_int savefhOpsAmount = {0};
        std::atomic_int secinfoOpsAmount = {0};
        std::atomic_int setattrOpsAmount = {0};
        std::atomic_int setclientidOpsAmount = {0};
        std::atomic_int setclientid_confirmOpsAmount = {0};
        std::atomic_int verifyOpsAmount = {0};
        std::atomic_int writeOpsAmount = {0};
        std::atomic_int release_lockownerOpsAmount = {0};
        std::atomic_int get_dir_delegationOpsAmount = {0};
        std::atomic_int illegalOpsAmount = {0};
    };
    struct NfsV41Stat
    {
        // Procedures:
        std::atomic_int nullProcsAmount = {0};
        std::atomic_int compoundProcsAmount = {0};

        // Operations:
        std::atomic_int accessOpsAmount = {0};
        std::atomic_int closeOpsAmount = {0};
        std::atomic_int commitOpsAmount = {0};
        std::atomic_int createOpsAmount = {0};
        std::atomic_int delegpurgeOpsAmount = {0};
        std::atomic_int delegreturnOpsAmount = {0};
        std::atomic_int getattrOpsAmount = {0};
        std::atomic_int getfhOpsAmount = {0};
        std::atomic_int linkOpsAmount = {0};
        std::atomic_int lockOpsAmount = {0};
        std::atomic_int locktOpsAmount = {0};
        std::atomic_int lockuOpsAmount = {0};
        std::atomic_int lookupOpsAmount = {0};
        std::atomic_int lookuppOpsAmount = {0};
        std::atomic_int nverifyOpsAmount = {0};
        std::atomic_int openOpsAmount = {0};
        std::atomic_int openattrOpsAmount = {0};
        std::atomic_int open_confirmOpsAmount = {0};
        std::atomic_int open_downgradeOpsAmount = {0};
        std::atomic_int putfhOpsAmount = {0};
        std::atomic_int putpubfhOpsAmount = {0};
        std::atomic_int putrootfhOpsAmount = {0};
        std::atomic_int readOpsAmount = {0};
        std::atomic_int readdirOpsAmount = {0};
        std::atomic_int readlinkOpsAmount = {0};
        std::atomic_int removeOpsAmount = {0};
        std::atomic_int renameOpsAmount = {0};
        std::atomic_int renewOpsAmount = {0};
        std::atomic_int restorefhOpsAmount = {0};
        std::atomic_int savefhOpsAmount = {0};
        std::atomic_int secinfoOpsAmount = {0};
        std::atomic_int setattrOpsAmount = {0};
        std::atomic_int setclientidOpsAmount = {0};
        std::atomic_int setclientid_confirmOpsAmount = {0};
        std::atomic_int verifyOpsAmount = {0};
        std::atomic_int writeOpsAmount = {0};
        std::atomic_int release_lockownerOpsAmount = {0};
        std::atomic_int backchannel_ctlOpsAmount = {0};
        std::atomic_int bind_conn_to_sessionOpsAmount = {0};
        std::atomic_int exchange_idOpsAmount = {0};
        std::atomic_int create_sessionOpsAmount = {0};
        std::atomic_int destroy_sessionOpsAmount = {0};
        std::atomic_int free_stateidOpsAmount = {0};
        std::atomic_int get_dir_delegationOpsAmount = {0};
        std::atomic_int getdeviceinfoOpsAmount = {0};
        std::atomic_int getdevicelistOpsAmount = {0};
        std::atomic_int layoutcommitOpsAmount = {0};
        std::atomic_int layoutgetOpsAmount = {0};
        std::atomic_int layoutreturnOpsAmount = {0};
        std::atomic_int secinfo_no_nameOpsAmount = {0};
        std::atomic_int sequenceOpsAmount = {0};
        std::atomic_int set_ssvOpsAmount = {0};
        std::atomic_int test_stateidOpsAmount = {0};
        std::atomic_int want_delegationOpsAmount = {0};
        std::atomic_int destroy_clientidOpsAmount = {0};
        std::atomic_int reclaim_completeOpsAmount = {0};
        std::atomic_int illegalOpsAmount = {0};
    };

    JsonAnalyzer(std::size_t workersAmount, int port, const std::string& host, std::size_t maxServingDurationMs, int backlog);
    ~JsonAnalyzer();

    // NFSv3 procedures

    void null(const RPCProcedure* /*proc*/,
              const struct NFS3::NULL3args* /*args*/,
              const struct NFS3::NULL3res* /*res*/) override final;

    void getattr3(const RPCProcedure* /*proc*/,
                  const struct NFS3::GETATTR3args* /*args*/,
                  const struct NFS3::GETATTR3res* /*res*/) override final;

    void setattr3(const RPCProcedure* /*proc*/,
                  const struct NFS3::SETATTR3args* /*args*/,
                  const struct NFS3::SETATTR3res* /*res*/) override final;

    void lookup3(const RPCProcedure* /*proc*/,
                 const struct NFS3::LOOKUP3args* /*args*/,
                 const struct NFS3::LOOKUP3res* /*res*/) override final;

    void access3(const RPCProcedure* /*proc*/,
                 const struct NFS3::ACCESS3args* /*args*/,
                 const struct NFS3::ACCESS3res* /*res*/) override final;

    void readlink3(const RPCProcedure* /*proc*/,
                   const struct NFS3::READLINK3args* /*args*/,
                   const struct NFS3::READLINK3res* /*res*/) override final;

    void read3(const RPCProcedure* /*proc*/,
               const struct NFS3::READ3args* /*args*/,
               const struct NFS3::READ3res* /*res*/) override final;

    void write3(const RPCProcedure* /*proc*/,
                const struct NFS3::WRITE3args* /*args*/,
                const struct NFS3::WRITE3res* /*res*/) override final;

    void create3(const RPCProcedure* /*proc*/,
                 const struct NFS3::CREATE3args* /*args*/,
                 const struct NFS3::CREATE3res* /*res*/) override final;

    void mkdir3(const RPCProcedure* /*proc*/,
                const struct NFS3::MKDIR3args* /*args*/,
                const struct NFS3::MKDIR3res* /*res*/) override final;

    void symlink3(const RPCProcedure* /*proc*/,
                  const struct NFS3::SYMLINK3args* /*args*/,
                  const struct NFS3::SYMLINK3res* /*res*/) override final;

    void mknod3(const RPCProcedure* /*proc*/,
                const struct NFS3::MKNOD3args* /*args*/,
                const struct NFS3::MKNOD3res* /*res*/) override final;

    void remove3(const RPCProcedure* /*proc*/,
                 const struct NFS3::REMOVE3args* /*args*/,
                 const struct NFS3::REMOVE3res* /*res*/) override final;

    void rmdir3(const RPCProcedure* /*proc*/,
                const struct NFS3::RMDIR3args* /*args*/,
                const struct NFS3::RMDIR3res* /*res*/) override final;

    void rename3(const RPCProcedure* /*proc*/,
                 const struct NFS3::RENAME3args* /*args*/,
                 const struct NFS3::RENAME3res* /*res*/) override final;

    void link3(const RPCProcedure* /*proc*/,
               const struct NFS3::LINK3args* /*args*/,
               const struct NFS3::LINK3res* /*res*/) override final;

    void readdir3(const RPCProcedure* /*proc*/,
                  const struct NFS3::READDIR3args* /*args*/,
                  const struct NFS3::READDIR3res* /*res*/) override final;

    void readdirplus3(const RPCProcedure* /*proc*/,
                      const struct NFS3::READDIRPLUS3args* /*args*/,
                      const struct NFS3::READDIRPLUS3res* /*res*/) override final;

    void fsstat3(const RPCProcedure* /*proc*/,
                 const struct NFS3::FSSTAT3args* /*args*/,
                 const struct NFS3::FSSTAT3res* /*res*/) override final;

    void fsinfo3(const RPCProcedure* /*proc*/,
                 const struct NFS3::FSINFO3args* /*args*/,
                 const struct NFS3::FSINFO3res* /*res*/) override final;

    void pathconf3(const RPCProcedure* /*proc*/,
                   const struct NFS3::PATHCONF3args* /*args*/,
                   const struct NFS3::PATHCONF3res* /*res*/) override final;

    void commit3(const RPCProcedure* /*proc*/,
                 const struct NFS3::COMMIT3args* /*args*/,
                 const struct NFS3::COMMIT3res* /*res*/) override final;

    // NFS4.0 procedures
 
    void null(const RPCProcedure* /*proc*/,
              const struct NFS4::NULL4args* /*args*/,
              const struct NFS4::NULL4res* /*res*/) override final;

    void compound4(const RPCProcedure* /*proc*/,
                   const struct NFS4::COMPOUND4args* /*args*/,
                   const struct NFS4::COMPOUND4res* /*res*/) override final;

    // NFS4.0 operations

    void access40(const RPCProcedure* /* proc */,
                  const struct NFS4::ACCESS4args* /* args */,
                  const struct NFS4::ACCESS4res* res) override final;
    void close40(const RPCProcedure* /* proc */,
                  const struct NFS4::CLOSE4args* /* args */,
                  const struct NFS4::CLOSE4res* res) override final;
    void commit40(const RPCProcedure* /* proc */,
                  const struct NFS4::COMMIT4args* /* args */,
                  const struct NFS4::COMMIT4res* res) override final;
    void create40(const RPCProcedure* /* proc */,
                  const struct NFS4::CREATE4args* /* args */,
                  const struct NFS4::CREATE4res* res) override final;
    void delegpurge40(const RPCProcedure* /* proc */,
                      const struct NFS4::DELEGPURGE4args* /* args */,
                      const struct NFS4::DELEGPURGE4res* res) override final;
    void delegreturn40(const RPCProcedure* /* proc */,
                       const struct NFS4::DELEGRETURN4args* /* args */,
                       const struct NFS4::DELEGRETURN4res* res) override final;
    void getattr40(const RPCProcedure* /* proc */,
                   const struct NFS4::GETATTR4args* /* args */,
                   const struct NFS4::GETATTR4res* res) override final;
    void getfh40(const RPCProcedure* /* proc */,
                 const struct NFS4::GETFH4res* res) override final;
    void link40(const RPCProcedure* /* proc */,
                const struct NFS4::LINK4args* /* args */,
                const struct NFS4::LINK4res* res) override final;
    void lock40(const RPCProcedure* /* proc */,
                const struct NFS4::LOCK4args* /* args */,
                const struct NFS4::LOCK4res* res) override final;
    void lockt40(const RPCProcedure* /* proc */,
                 const struct NFS4::LOCKT4args* /* args */,
                 const struct NFS4::LOCKT4res* res) override final;
    void locku40(const RPCProcedure* /* proc */,
                 const struct NFS4::LOCKU4args* /* args */,
                 const struct NFS4::LOCKU4res* res) override final;
    void lookup40(const RPCProcedure* /* proc */,
                  const struct NFS4::LOOKUP4args* /* args */,
                  const struct NFS4::LOOKUP4res* res) override final;
    void lookupp40(const RPCProcedure* /* proc */,
                   const struct NFS4::LOOKUPP4res* res) override final;
    void nverify40(const RPCProcedure* /* proc */,
                   const struct NFS4::NVERIFY4args* /* args */,
                   const struct NFS4::NVERIFY4res* res) override final;
    void open40(const RPCProcedure* /* proc */,
                const struct NFS4::OPEN4args* /* args */,
                const struct NFS4::OPEN4res* res) override final;
    void openattr40(const RPCProcedure* /* proc */,
                    const struct NFS4::OPENATTR4args* /* args */,
                    const struct NFS4::OPENATTR4res* res) override final;
    void open_confirm40(const RPCProcedure* /* proc */,
                        const struct NFS4::OPEN_CONFIRM4args* /* args */,
                        const struct NFS4::OPEN_CONFIRM4res* res) override final;
    void open_downgrade40(const RPCProcedure* /* proc */,
                          const struct NFS4::OPEN_DOWNGRADE4args* /* args */,
                          const struct NFS4::OPEN_DOWNGRADE4res* res) override final;
    void putfh40(const RPCProcedure* /* proc */,
                 const struct NFS4::PUTFH4args* /* args */,
                 const struct NFS4::PUTFH4res* res) override final;
    void putpubfh40(const RPCProcedure* /* proc */,
                    const struct NFS4::PUTPUBFH4res* res) override final;
    void putrootfh40(const RPCProcedure* /* proc */,
                     const struct NFS4::PUTROOTFH4res* res) override final;
    void read40(const RPCProcedure* /* proc */,
                const struct NFS4::READ4args* /* args */,
                const struct NFS4::READ4res* res) override final;
    void readdir40(const RPCProcedure* /* proc */,
                   const struct NFS4::READDIR4args* /* args */,
                   const struct NFS4::READDIR4res* res) override final;
    void readlink40(const RPCProcedure* /* proc */,
                    const struct NFS4::READLINK4res* res) override final;
    void remove40(const RPCProcedure* /* proc */,
                  const struct NFS4::REMOVE4args* /* args */,
                  const struct NFS4::REMOVE4res* res) override final;
    void rename40(const RPCProcedure* /* proc */,
                  const struct NFS4::RENAME4args* /* args */,
                  const struct NFS4::RENAME4res* res) override final;
    void renew40(const RPCProcedure* /* proc */,
                 const struct NFS4::RENEW4args* /* args */,
                 const struct NFS4::RENEW4res* res) override final;
    void restorefh40(const RPCProcedure* /* proc */,
                     const struct NFS4::RESTOREFH4res* res) override final;
    void savefh40(const RPCProcedure* /* proc */,
                  const struct NFS4::SAVEFH4res* res) override final;
    void secinfo40(const RPCProcedure* /* proc */,
                   const struct NFS4::SECINFO4args* /* args */,
                   const struct NFS4::SECINFO4res* res) override final;
    void setattr40(const RPCProcedure* /* proc */,
                   const struct NFS4::SETATTR4args* /* args */,
                   const struct NFS4::SETATTR4res* res) override final;
    void setclientid40(const RPCProcedure* /* proc */,
                       const struct NFS4::SETCLIENTID4args* /* args */,
                       const struct NFS4::SETCLIENTID4res* res) override final;
    void setclientid_confirm40(const RPCProcedure* /* proc */,
                               const struct NFS4::SETCLIENTID_CONFIRM4args* /* args */,
                               const struct NFS4::SETCLIENTID_CONFIRM4res* res) override final;
    void verify40(const RPCProcedure* /* proc */,
                  const struct NFS4::VERIFY4args* /* args */,
                  const struct NFS4::VERIFY4res* res) override final;
    void write40(const RPCProcedure* /* proc */,
                 const struct NFS4::WRITE4args* /* args */,
                 const struct NFS4::WRITE4res* res) override final;
    void release_lockowner40(const RPCProcedure* /* proc */,
                             const struct NFS4::RELEASE_LOCKOWNER4args* /* args */,
                             const struct NFS4::RELEASE_LOCKOWNER4res* res) override final;
    void get_dir_delegation40(const RPCProcedure* /* proc */,
                              const struct NFS4::GET_DIR_DELEGATION4args* /* args */,
                              const struct NFS4::GET_DIR_DELEGATION4res* res) override final;
    void illegal40(const RPCProcedure* /* proc */,
                   const struct NFS4::ILLEGAL4res* res) override final;

    // NFSv4.1 procedures
 
    void null41(const RPCProcedure* /*proc*/,
                const struct NFS41::NULL4args* /*args*/,
                const struct NFS41::NULL4res* /*res*/) override final;

    void compound41(const RPCProcedure* /*proc*/,
                    const struct NFS41::COMPOUND4args* /*args*/,
                    const struct NFS41::COMPOUND4res* /*res*/) override final;

    // NFSv4.1 operations

    void access41(const RPCProcedure* /* proc */,
                  const struct NFS41::ACCESS4args* /* args */,
                  const struct NFS41::ACCESS4res* res) override final;
    void close41(const RPCProcedure* /* proc */,
                  const struct NFS41::CLOSE4args* /* args */,
                  const struct NFS41::CLOSE4res* res) override final;
    void commit41(const RPCProcedure* /* proc */,
                  const struct NFS41::COMMIT4args* /* args */,
                  const struct NFS41::COMMIT4res* res) override final;
    void create41(const RPCProcedure* /* proc */,
                  const struct NFS41::CREATE4args* /* args */,
                  const struct NFS41::CREATE4res* res) override final;
    void delegpurge41(const RPCProcedure* /* proc */,
                      const struct NFS41::DELEGPURGE4args* /* args */,
                      const struct NFS41::DELEGPURGE4res* res) override final;
    void delegreturn41(const RPCProcedure* /* proc */,
                       const struct NFS41::DELEGRETURN4args* /* args */,
                       const struct NFS41::DELEGRETURN4res* res) override final;
    void getattr41(const RPCProcedure* /* proc */,
                   const struct NFS41::GETATTR4args* /* args */,
                   const struct NFS41::GETATTR4res* res) override final;
    void getfh41(const RPCProcedure* /* proc */,
                 const struct NFS41::GETFH4res* res) override final;
    void link41(const RPCProcedure* /* proc */,
                const struct NFS41::LINK4args* /* args */,
                const struct NFS41::LINK4res* res) override final;
    void lock41(const RPCProcedure* /* proc */,
                const struct NFS41::LOCK4args* /* args */,
                const struct NFS41::LOCK4res* res) override final;
    void lockt41(const RPCProcedure* /* proc */,
                 const struct NFS41::LOCKT4args* /* args */,
                 const struct NFS41::LOCKT4res* res) override final;
    void locku41(const RPCProcedure* /* proc */,
                 const struct NFS41::LOCKU4args* /* args */,
                 const struct NFS41::LOCKU4res* res) override final;
    void lookup41(const RPCProcedure* /* proc */,
                  const struct NFS41::LOOKUP4args* /* args */,
                  const struct NFS41::LOOKUP4res* res) override final;
    void lookupp41(const RPCProcedure* /* proc */,
                   const struct NFS41::LOOKUPP4res* res) override final;
    void nverify41(const RPCProcedure* /* proc */,
                   const struct NFS41::NVERIFY4args* /* args */,
                   const struct NFS41::NVERIFY4res* res) override final;
    void open41(const RPCProcedure* /* proc */,
                const struct NFS41::OPEN4args* /* args */,
                const struct NFS41::OPEN4res* res) override final;
    void openattr41(const RPCProcedure* /* proc */,
                    const struct NFS41::OPENATTR4args* /* args */,
                    const struct NFS41::OPENATTR4res* res) override final;
    void open_confirm41(const RPCProcedure* /* proc */,
                        const struct NFS41::OPEN_CONFIRM4args* /* args */,
                        const struct NFS41::OPEN_CONFIRM4res* res) override final;
    void open_downgrade41(const RPCProcedure* /* proc */,
                          const struct NFS41::OPEN_DOWNGRADE4args* /* args */,
                          const struct NFS41::OPEN_DOWNGRADE4res* res) override final;
    void putfh41(const RPCProcedure* /* proc */,
                 const struct NFS41::PUTFH4args* /* args */,
                 const struct NFS41::PUTFH4res* res) override final;
    void putpubfh41(const RPCProcedure* /* proc */,
                    const struct NFS41::PUTPUBFH4res* res) override final;
    void putrootfh41(const RPCProcedure* /* proc */,
                     const struct NFS41::PUTROOTFH4res* res) override final;
    void read41(const RPCProcedure* /* proc */,
                const struct NFS41::READ4args* /* args */,
                const struct NFS41::READ4res* res) override final;
    void readdir41(const RPCProcedure* /* proc */,
                   const struct NFS41::READDIR4args* /* args */,
                   const struct NFS41::READDIR4res* res) override final;
    void readlink41(const RPCProcedure* /* proc */,
                    const struct NFS41::READLINK4res* res) override final;
    void remove41(const RPCProcedure* /* proc */,
                  const struct NFS41::REMOVE4args* /* args */,
                  const struct NFS41::REMOVE4res* res) override final;
    void rename41(const RPCProcedure* /* proc */,
                  const struct NFS41::RENAME4args* /* args */,
                  const struct NFS41::RENAME4res* res) override final;
    void renew41(const RPCProcedure* /* proc */,
                 const struct NFS41::RENEW4args* /* args */,
                 const struct NFS41::RENEW4res* res) override final;
    void restorefh41(const RPCProcedure* /* proc */,
                     const struct NFS41::RESTOREFH4res* res) override final;
    void savefh41(const RPCProcedure* /* proc */,
                  const struct NFS41::SAVEFH4res* res) override final;
    void secinfo41(const RPCProcedure* /* proc */,
                   const struct NFS41::SECINFO4args* /* args */,
                   const struct NFS41::SECINFO4res* res) override final;
    void setattr41(const RPCProcedure* /* proc */,
                   const struct NFS41::SETATTR4args* /* args */,
                   const struct NFS41::SETATTR4res* res) override final;
    void setclientid41(const RPCProcedure* /* proc */,
                       const struct NFS41::SETCLIENTID4args* /* args */,
                       const struct NFS41::SETCLIENTID4res* res) override final;
    void setclientid_confirm41(const RPCProcedure* /* proc */,
                               const struct NFS41::SETCLIENTID_CONFIRM4args* /* args */,
                               const struct NFS41::SETCLIENTID_CONFIRM4res* res) override final;
    void verify41(const RPCProcedure* /* proc */,
                  const struct NFS41::VERIFY4args* /* args */,
                  const struct NFS41::VERIFY4res* res) override final;
    void write41(const RPCProcedure* /* proc */,
                 const struct NFS41::WRITE4args* /* args */,
                 const struct NFS41::WRITE4res* res) override final;
    void release_lockowner41(const RPCProcedure* /* proc */,
                             const struct NFS41::RELEASE_LOCKOWNER4args* /* args */,
                             const struct NFS41::RELEASE_LOCKOWNER4res* res) override final;
    void backchannel_ctl41(const RPCProcedure* /* proc */,
                           const struct NFS41::BACKCHANNEL_CTL4args* /* args */,
                           const struct NFS41::BACKCHANNEL_CTL4res* res) override final;
    void bind_conn_to_session41(const RPCProcedure* /* proc */,
                                const struct NFS41::BIND_CONN_TO_SESSION4args* /* args */, 
                                const struct NFS41::BIND_CONN_TO_SESSION4res* res) override final;
    void exchange_id41(const RPCProcedure* /* proc */,
                       const struct NFS41::EXCHANGE_ID4args* /* args */,
                       const struct NFS41::EXCHANGE_ID4res* res) override final;
    void create_session41(const RPCProcedure* /* proc */,
                          const struct NFS41::CREATE_SESSION4args* /* args */,
                          const struct NFS41::CREATE_SESSION4res* res) override final;
    void destroy_session41(const RPCProcedure* /* proc */,
                           const struct NFS41::DESTROY_SESSION4args* /* args */,
                           const struct NFS41::DESTROY_SESSION4res* res) override final;
    void free_stateid41(const RPCProcedure* /* proc */,
                        const struct NFS41::FREE_STATEID4args* /* args */,
                        const struct NFS41::FREE_STATEID4res* res) override final;
    void get_dir_delegation41(const RPCProcedure* /* proc */,
                              const struct NFS41::GET_DIR_DELEGATION4args* /* args */,
                              const struct NFS41::GET_DIR_DELEGATION4res* res) override final;
    void getdeviceinfo41(const RPCProcedure* /* proc */,
                         const struct NFS41::GETDEVICEINFO4args* /* args */,
                         const struct NFS41::GETDEVICEINFO4res* res) override final;
    void getdevicelist41(const RPCProcedure* /* proc */,
                         const struct NFS41::GETDEVICELIST4args* /* args */,
                         const struct NFS41::GETDEVICELIST4res* res) override final;
    void layoutcommit41(const RPCProcedure* /* proc */,
                        const struct NFS41::LAYOUTCOMMIT4args* /* args */,
                        const struct NFS41::LAYOUTCOMMIT4res* res) override final;
    void layoutget41(const RPCProcedure* /* proc */,
                     const struct NFS41::LAYOUTGET4args* /* args */,
                     const struct NFS41::LAYOUTGET4res* res) override final;
    void layoutreturn41(const RPCProcedure* /* proc */,
                        const struct NFS41::LAYOUTRETURN4args* /* args */,
                        const struct NFS41::LAYOUTRETURN4res* res) override final;
    void secinfo_no_name41(const RPCProcedure* /* proc */,
                              const NFS41::SECINFO_NO_NAME4args* /* args */,
                              const NFS41::SECINFO_NO_NAME4res* res) override final;
    void sequence41(const RPCProcedure* /* proc */,
                    const struct NFS41::SEQUENCE4args* /* args */,
                    const struct NFS41::SEQUENCE4res* res) override final;
    void set_ssv41(const RPCProcedure* /* proc */,
                   const struct NFS41::SET_SSV4args* /* args */,
                   const struct NFS41::SET_SSV4res* res) override final;
    void test_stateid41(const RPCProcedure* /* proc */,
                        const struct NFS41::TEST_STATEID4args* /* args */,
                        const struct NFS41::TEST_STATEID4res* res) override final;
    void want_delegation41(const RPCProcedure* /* proc */,
                           const struct NFS41::WANT_DELEGATION4args* /* args */,
                           const struct NFS41::WANT_DELEGATION4res* res) override final;
    void destroy_clientid41(const RPCProcedure* /* proc */,
                            const struct NFS41::DESTROY_CLIENTID4args* /* args */,
                            const struct NFS41::DESTROY_CLIENTID4res* res) override final;
    void reclaim_complete41(const RPCProcedure* /* proc */,
                            const struct NFS41::RECLAIM_COMPLETE4args* /* args */,
                            const struct NFS41::RECLAIM_COMPLETE4res* res) override final;
    void illegal41(const RPCProcedure* /* proc */,
                   const struct NFS41::ILLEGAL4res* res) override final;

    void flush_statistics() override final;

    inline const NfsV3Stat& getNfsV3Stat() const
    {
        return _nfsV3Stat;
    }

    inline const NfsV40Stat& getNfsV40Stat() const
    {
        return _nfsV40Stat;
    }

    inline const NfsV41Stat& getNfsV41Stat() const
    {
        return _nfsV41Stat;
    }

private:
    JsonTcpService _jsonTcpService;
    NfsV3Stat  _nfsV3Stat;
    NfsV40Stat _nfsV40Stat;
    NfsV41Stat _nfsV41Stat;
};
//------------------------------------------------------------------------------
#endif // JSON_ANALYZER_H
//------------------------------------------------------------------------------
