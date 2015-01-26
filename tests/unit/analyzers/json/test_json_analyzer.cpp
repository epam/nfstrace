//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: JSON analyzer tests executable
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
#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <json.h>

#include "json_analyzer.h"
//------------------------------------------------------------------------------
using namespace NST::net;

static constexpr std::size_t AwaitForServiceStartupMs = 250U;
static constexpr std::size_t WorkersAmount = 100U;
static constexpr int ListenPort = 8888;
static constexpr const char* ListenHost = IpEndpoint::LoopbackAddress;
static constexpr std::size_t MaxServingDurationMs = 200;
static constexpr int ListenBacklog = 15;
static constexpr std::size_t ReceiveBufferSize = 4096U;
static constexpr std::size_t SlowClientTimeoutMs = 300U;

// NFS3 procedures:
static constexpr int NfsV3NullProcsAmount = 25;
static constexpr int NfsV3GetattrProcsAmount = 35;
static constexpr int NfsV3SetattrProcsAmount = 80;
static constexpr int NfsV3LookupProcsAmount = 76;
static constexpr int NfsV3AccessProcsAmount = 42;
static constexpr int NfsV3ReadlinkProcsAmount = 24;
static constexpr int NfsV3ReadProcsAmount = 56;
static constexpr int NfsV3WriteProcsAmount = 152;
static constexpr int NfsV3CreateProcsAmount = 31;
static constexpr int NfsV3MkdirProcsAmount = 97;
static constexpr int NfsV3SymlinkProcsAmount = 69;
static constexpr int NfsV3MknodProcsAmount = 73;
static constexpr int NfsV3RemoveProcsAmount = 36;
static constexpr int NfsV3RmdirProcsAmount = 27;
static constexpr int NfsV3RenameProcsAmount = 59;
static constexpr int NfsV3LinkProcsAmount = 28;
static constexpr int NfsV3ReaddirProcsAmount = 83;
static constexpr int NfsV3ReaddirplusProcsAmount = 74;
static constexpr int NfsV3FsstatProcsAmount = 95;
static constexpr int NfsV3FsinfoProcsAmount = 57;
static constexpr int NfsV3PathconfProcsAmount = 26;
static constexpr int NfsV3CommitProcsAmount = 79;

// NFS4.0 procedures:
static constexpr int NfsV40NullProcsAmount = 81;
static constexpr int NfsV40CompoundProcsAmount = 18;

// NFS4.0 operations:
static constexpr int NfsV40accessOpsAmount = 32;
static constexpr int NfsV40closeOpsAmount = 42;
static constexpr int NfsV40commitOpsAmount = 35;
static constexpr int NfsV40createOpsAmount = 65;
static constexpr int NfsV40delegpurgeOpsAmount = 98;
static constexpr int NfsV40delegreturnOpsAmount = 76;
static constexpr int NfsV40getattrOpsAmount = 34;
static constexpr int NfsV40getfhOpsAmount = 76;
static constexpr int NfsV40linkOpsAmount = 90;
static constexpr int NfsV40lockOpsAmount = 78;
static constexpr int NfsV40locktOpsAmount = 35;
static constexpr int NfsV40lockuOpsAmount = 67;
static constexpr int NfsV40lookupOpsAmount = 23;
static constexpr int NfsV40lookuppOpsAmount = 77;
static constexpr int NfsV40nverifyOpsAmount = 59;
static constexpr int NfsV40openOpsAmount = 34;
static constexpr int NfsV40openattrOpsAmount = 54;
static constexpr int NfsV40open_confirmOpsAmount = 54;
static constexpr int NfsV40open_downgradeOpsAmount = 36;
static constexpr int NfsV40putfhOpsAmount = 78;
static constexpr int NfsV40putpubfhOpsAmount = 96;
static constexpr int NfsV40putrootfhOpsAmount = 56;
static constexpr int NfsV40readOpsAmount = 36;
static constexpr int NfsV40readdirOpsAmount = 59;
static constexpr int NfsV40readlinkOpsAmount = 53;
static constexpr int NfsV40removeOpsAmount = 88;
static constexpr int NfsV40renameOpsAmount = 34;
static constexpr int NfsV40renewOpsAmount = 68;
static constexpr int NfsV40restorefhOpsAmount = 37;
static constexpr int NfsV40savefhOpsAmount = 84;
static constexpr int NfsV40secinfoOpsAmount = 69;
static constexpr int NfsV40setattrOpsAmount = 33;
static constexpr int NfsV40setclientidOpsAmount = 25;
static constexpr int NfsV40setclientid_confirmOpsAmount = 36;
static constexpr int NfsV40verifyOpsAmount = 76;
static constexpr int NfsV40writeOpsAmount = 55;
static constexpr int NfsV40release_lockownerOpsAmount = 18;
static constexpr int NfsV40get_dir_delegationOpsAmount = 54;
static constexpr int NfsV40illegalOpsAmount = 38;
 
// NFS4.1 procedures:
static constexpr int NfsV41NullProcsAmount = 81;
static constexpr int NfsV41CompoundProcsAmount = 18;

// NFS4.1 operations:
static constexpr int NfsV41accessOpsAmount = 37;
static constexpr int NfsV41closeOpsAmount = 23;
static constexpr int NfsV41commitOpsAmount = 19;
static constexpr int NfsV41createOpsAmount = 37;
static constexpr int NfsV41delegpurgeOpsAmount = 22;
static constexpr int NfsV41delegreturnOpsAmount = 64;
static constexpr int NfsV41getattrOpsAmount = 95;
static constexpr int NfsV41getfhOpsAmount = 34;
static constexpr int NfsV41linkOpsAmount = 95;
static constexpr int NfsV41lockOpsAmount = 37;
static constexpr int NfsV41locktOpsAmount = 96;
static constexpr int NfsV41lockuOpsAmount = 45;
static constexpr int NfsV41lookupOpsAmount = 52;
static constexpr int NfsV41lookuppOpsAmount = 25;
static constexpr int NfsV41nverifyOpsAmount = 44;
static constexpr int NfsV41openOpsAmount = 93;
static constexpr int NfsV41openattrOpsAmount = 77;
static constexpr int NfsV41open_confirmOpsAmount = 56;
static constexpr int NfsV41open_downgradeOpsAmount = 98;
static constexpr int NfsV41putfhOpsAmount = 34;
static constexpr int NfsV41putpubfhOpsAmount = 80;
static constexpr int NfsV41putrootfhOpsAmount = 66;
static constexpr int NfsV41readOpsAmount = 89;
static constexpr int NfsV41readdirOpsAmount = 87;
static constexpr int NfsV41readlinkOpsAmount = 65;
static constexpr int NfsV41removeOpsAmount = 23;
static constexpr int NfsV41renameOpsAmount = 34;
static constexpr int NfsV41renewOpsAmount = 68;
static constexpr int NfsV41restorefhOpsAmount = 44;
static constexpr int NfsV41savefhOpsAmount = 67;
static constexpr int NfsV41secinfoOpsAmount = 98;
static constexpr int NfsV41setattrOpsAmount = 87;
static constexpr int NfsV41setclientidOpsAmount = 65;
static constexpr int NfsV41setclientid_confirmOpsAmount = 98;
static constexpr int NfsV41verifyOpsAmount = 45;
static constexpr int NfsV41writeOpsAmount = 23;
static constexpr int NfsV41release_lockownerOpsAmount = 56;
static constexpr int NfsV41backchannel_ctlOpsAmount = 98;
static constexpr int NfsV41bind_conn_to_sessionOpsAmount = 67;
static constexpr int NfsV41exchange_idOpsAmount = 34;
static constexpr int NfsV41create_sessionOpsAmount = 15;
static constexpr int NfsV41destroy_sessionOpsAmount = 99;
static constexpr int NfsV41free_stateidOpsAmount = 26;
static constexpr int NfsV41get_dir_delegationOpsAmount = 54;
static constexpr int NfsV41getdeviceinfoOpsAmount = 59;
static constexpr int NfsV41getdevicelistOpsAmount = 13;
static constexpr int NfsV41layoutcommitOpsAmount = 64;
static constexpr int NfsV41layoutgetOpsAmount = 34;
static constexpr int NfsV41layoutreturnOpsAmount = 75;
static constexpr int NfsV41secinfo_no_nameOpsAmount = 79;
static constexpr int NfsV41sequenceOpsAmount = 88;
static constexpr int NfsV41set_ssvOpsAmount = 45;
static constexpr int NfsV41test_stateidOpsAmount = 74;
static constexpr int NfsV41want_delegationOpsAmount = 56;
static constexpr int NfsV41destroy_clientidOpsAmount = 72;
static constexpr int NfsV41reclaim_completeOpsAmount = 45;
static constexpr int NfsV41illegalOpsAmount = 43;

class JsonAnalyzerCase : public ::testing::Test
{
protected:
    virtual void SetUp() override final
    {
        // Starting service
        analyzer.reset(new JsonAnalyzer{WorkersAmount, ListenPort, ListenHost, MaxServingDurationMs, ListenBacklog});
        std::this_thread::sleep_for(std::chrono::milliseconds{AwaitForServiceStartupMs});
        // Setting up analyzer (NFSv3)
        for (int i = 0; i < NfsV3NullProcsAmount; ++i)
        {
            analyzer->null(static_cast<const struct RPCProcedure*>(nullptr),
                           static_cast<const struct NFS3::NULL3args*>(nullptr),
                           static_cast<const struct NFS3::NULL3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3GetattrProcsAmount; ++i)
        {
            analyzer->getattr3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS3::GETATTR3args*>(nullptr),
                               static_cast<const struct NFS3::GETATTR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3SetattrProcsAmount; ++i)
        {
            analyzer->setattr3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS3::SETATTR3args*>(nullptr),
                               static_cast<const struct NFS3::SETATTR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3LookupProcsAmount; ++i)
        {
            analyzer->lookup3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS3::LOOKUP3args*>(nullptr),
                              static_cast<const struct NFS3::LOOKUP3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3AccessProcsAmount; ++i)
        {
            analyzer->access3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS3::ACCESS3args*>(nullptr),
                              static_cast<const struct NFS3::ACCESS3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3ReadlinkProcsAmount; ++i)
        {
            analyzer->readlink3(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS3::READLINK3args*>(nullptr),
                                static_cast<const struct NFS3::READLINK3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3ReadProcsAmount; ++i)
        {
            analyzer->read3(static_cast<const struct RPCProcedure*>(nullptr),
                            static_cast<const struct NFS3::READ3args*>(nullptr),
                            static_cast<const struct NFS3::READ3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3WriteProcsAmount; ++i)
        {
            analyzer->write3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS3::WRITE3args*>(nullptr),
                             static_cast<const struct NFS3::WRITE3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3CreateProcsAmount; ++i)
        {
            analyzer->create3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS3::CREATE3args*>(nullptr),
                              static_cast<const struct NFS3::CREATE3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3MkdirProcsAmount; ++i)
        {
            analyzer->mkdir3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS3::MKDIR3args*>(nullptr),
                             static_cast<const struct NFS3::MKDIR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3SymlinkProcsAmount; ++i)
        {
            analyzer->symlink3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS3::SYMLINK3args*>(nullptr),
                               static_cast<const struct NFS3::SYMLINK3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3MknodProcsAmount; ++i)
        {
            analyzer->mknod3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS3::MKNOD3args*>(nullptr),
                             static_cast<const struct NFS3::MKNOD3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3RemoveProcsAmount; ++i)
        {
            analyzer->remove3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS3::REMOVE3args*>(nullptr),
                              static_cast<const struct NFS3::REMOVE3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3RmdirProcsAmount; ++i)
        {
            analyzer->rmdir3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS3::RMDIR3args*>(nullptr),
                             static_cast<const struct NFS3::RMDIR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3RenameProcsAmount; ++i)
        {
            analyzer->rename3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS3::RENAME3args*>(nullptr),
                              static_cast<const struct NFS3::RENAME3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3LinkProcsAmount; ++i)
        {
            analyzer->link3(static_cast<const struct RPCProcedure*>(nullptr),
                            static_cast<const struct NFS3::LINK3args*>(nullptr),
                            static_cast<const struct NFS3::LINK3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3ReaddirProcsAmount; ++i)
        {
            analyzer->readdir3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS3::READDIR3args*>(nullptr),
                               static_cast<const struct NFS3::READDIR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3ReaddirplusProcsAmount; ++i)
        {
            analyzer->readdirplus3(static_cast<const struct RPCProcedure*>(nullptr),
                                   static_cast<const struct NFS3::READDIRPLUS3args*>(nullptr),
                                   static_cast<const struct NFS3::READDIRPLUS3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3FsstatProcsAmount; ++i)
        {
            analyzer->fsstat3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS3::FSSTAT3args*>(nullptr),
                              static_cast<const struct NFS3::FSSTAT3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3FsinfoProcsAmount; ++i)
        {
            analyzer->fsinfo3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS3::FSINFO3args*>(nullptr),
                              static_cast<const struct NFS3::FSINFO3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3PathconfProcsAmount; ++i)
        {
            analyzer->pathconf3(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS3::PATHCONF3args*>(nullptr),
                                static_cast<const struct NFS3::PATHCONF3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3CommitProcsAmount; ++i)
        {
            analyzer->commit3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS3::COMMIT3args*>(nullptr),
                              static_cast<const struct NFS3::COMMIT3res*>(nullptr));
        }

        // Setting up analyzer (NFSv4.0 procedures)
        for (int i = 0; i < NfsV40NullProcsAmount; ++i)
        {
            analyzer->null(static_cast<const struct RPCProcedure*>(nullptr),
                           static_cast<const struct NFS4::NULL4args*>(nullptr),
                           static_cast<const struct NFS4::NULL4res*>(nullptr));
        }
        for (int i = 0; i < NfsV40CompoundProcsAmount; ++i)
        {
            analyzer->compound4(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS4::COMPOUND4args*>(nullptr),
                                static_cast<const struct NFS4::COMPOUND4res*>(nullptr));
        }

        // Setting up analyzer (NFSv4.0 operations)
        const struct NFS4::ACCESS4res access40 {};
        for (int i = 0; i < NfsV40accessOpsAmount; ++i)
        {
            analyzer->access40(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS4::ACCESS4args*>(nullptr),
                               &access40);
        }
        const struct NFS4::CLOSE4res close40 {};
        for (int i = 0; i < NfsV40closeOpsAmount; ++i)
        {
            analyzer->close40(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS4::CLOSE4args*>(nullptr),
                              &close40);
        }
        const struct NFS4::COMMIT4res commit40 {};
        for (int i = 0; i < NfsV40commitOpsAmount; ++i)
        {
            analyzer->commit40(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS4::COMMIT4args*>(nullptr),
                               &commit40);
        }
        const struct NFS4::CREATE4res create40 {};
        for (int i = 0; i < NfsV40createOpsAmount; ++i)
        {
            analyzer->create40(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS4::CREATE4args*>(nullptr),
                               &create40);
        }
        const struct NFS4::DELEGPURGE4res delegpurge40 {};
        for (int i = 0; i < NfsV40delegpurgeOpsAmount; ++i)
        {
            analyzer->delegpurge40(static_cast<const struct RPCProcedure*>(nullptr),
                                   static_cast<const struct NFS4::DELEGPURGE4args*>(nullptr),
                                   &delegpurge40);
        }
        const struct NFS4::DELEGRETURN4res delegreturn40 {};
        for (int i = 0; i < NfsV40delegreturnOpsAmount; ++i)
        {
            analyzer->delegreturn40(static_cast<const struct RPCProcedure*>(nullptr),
                                    static_cast<const struct NFS4::DELEGRETURN4args*>(nullptr),
                                    &delegreturn40);
        }
        const struct NFS4::GETATTR4res getattr40 {};
        for (int i = 0; i < NfsV40getattrOpsAmount; ++i)
        {
            analyzer->getattr40(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS4::GETATTR4args*>(nullptr),
                                &getattr40);
        }
        const struct NFS4::GETFH4res getfh40 {};
        for (int i = 0; i < NfsV40getfhOpsAmount; ++i)
        {
            analyzer->getfh40(static_cast<const struct RPCProcedure*>(nullptr),
                              &getfh40);
        }
        const struct NFS4::LINK4res link40 {};
        for (int i = 0; i < NfsV40linkOpsAmount; ++i)
        {
            analyzer->link40(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS4::LINK4args*>(nullptr),
                             &link40);
        }
        const struct NFS4::LOCK4res lock40 {};
        for (int i = 0; i < NfsV40lockOpsAmount; ++i)
        {
            analyzer->lock40(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS4::LOCK4args*>(nullptr),
                             &lock40);
        }
        const struct NFS4::LOCKT4res lockt40 {};
        for (int i = 0; i < NfsV40locktOpsAmount; ++i)
        {
            analyzer->lockt40(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS4::LOCKT4args*>(nullptr),
                              &lockt40);
        }
        const struct NFS4::LOCKU4res locku40 {};
        for (int i = 0; i < NfsV40lockuOpsAmount; ++i)
        {
            analyzer->locku40(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS4::LOCKU4args*>(nullptr),
                              &locku40);
        }
        const struct NFS4::LOOKUP4res lookup40 {};
        for (int i = 0; i < NfsV40lookupOpsAmount; ++i)
        {
            analyzer->lookup40(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS4::LOOKUP4args*>(nullptr),
                               &lookup40);
        }
        const struct NFS4::LOOKUPP4res lookupp40 {};
        for (int i = 0; i < NfsV40lookuppOpsAmount; ++i)
        {
            analyzer->lookupp40(static_cast<const struct RPCProcedure*>(nullptr),
                                &lookupp40);
        }
        const struct NFS4::NVERIFY4res nverify40 {};
        for (int i = 0; i < NfsV40nverifyOpsAmount; ++i)
        {
            analyzer->nverify40(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS4::NVERIFY4args*>(nullptr),
                                &nverify40);
        }
        const struct NFS4::OPEN4res open40 {};
        for (int i = 0; i < NfsV40openOpsAmount; ++i)
        {
            analyzer->open40(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS4::OPEN4args*>(nullptr),
                             &open40);
        }
        const struct NFS4::OPENATTR4res openattr40 {};
        for (int i = 0; i < NfsV40openattrOpsAmount; ++i)
        {
            analyzer->openattr40(static_cast<const struct RPCProcedure*>(nullptr),
                                 static_cast<const struct NFS4::OPENATTR4args*>(nullptr),
                                 &openattr40);
        }
        const struct NFS4::OPEN_CONFIRM4res open_confirm40 {};
        for (int i = 0; i < NfsV40open_confirmOpsAmount; ++i)
        {
            analyzer->open_confirm40(static_cast<const struct RPCProcedure*>(nullptr),
                                     static_cast<const struct NFS4::OPEN_CONFIRM4args*>(nullptr),
                                     &open_confirm40);
        }
        const struct NFS4::OPEN_DOWNGRADE4res open_downgrade40 {};
        for (int i = 0; i < NfsV40open_downgradeOpsAmount; ++i)
        {
            analyzer->open_downgrade40(static_cast<const struct RPCProcedure*>(nullptr),
                                       static_cast<const struct NFS4::OPEN_DOWNGRADE4args*>(nullptr),
                                       &open_downgrade40);
        }
        const struct NFS4::PUTFH4res putfh40 {};
        for (int i = 0; i < NfsV40putfhOpsAmount; ++i)
        {
            analyzer->putfh40(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS4::PUTFH4args*>(nullptr),
                              &putfh40);
        }
        const struct NFS4::PUTPUBFH4res putpubfh40 {};
        for (int i = 0; i < NfsV40putpubfhOpsAmount; ++i)
        {
            analyzer->putpubfh40(static_cast<const struct RPCProcedure*>(nullptr),
                                 &putpubfh40);
        }
        const struct NFS4::PUTROOTFH4res putrootfh40 {};
        for (int i = 0; i < NfsV40putrootfhOpsAmount; ++i)
        {
            analyzer->putrootfh40(static_cast<const struct RPCProcedure*>(nullptr),
                                  &putrootfh40);
        }
        const struct NFS4::READ4res read40 {};
        for (int i = 0; i < NfsV40readOpsAmount; ++i)
        {
            analyzer->read40(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS4::READ4args*>(nullptr),
                             &read40);
        }
        const struct NFS4::READDIR4res readdir40 {};
        for (int i = 0; i < NfsV40readdirOpsAmount; ++i)
        {
            analyzer->readdir40(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS4::READDIR4args*>(nullptr),
                                &readdir40);
        }
        const struct NFS4::READLINK4res readlink40 {};
        for (int i = 0; i < NfsV40readlinkOpsAmount; ++i)
        {
            analyzer->readlink40(static_cast<const struct RPCProcedure*>(nullptr),
                                 &readlink40);
        }
        const struct NFS4::REMOVE4res remove40 {};
        for (int i = 0; i < NfsV40removeOpsAmount; ++i)
        {
            analyzer->remove40(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS4::REMOVE4args*>(nullptr),
                               &remove40);
        }
        const struct NFS4::RENAME4res rename40 {};
        for (int i = 0; i < NfsV40renameOpsAmount; ++i)
        {
            analyzer->rename40(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS4::RENAME4args*>(nullptr),
                               &rename40);
        }
        const struct NFS4::RENEW4res renew40 {};
        for (int i = 0; i < NfsV40renewOpsAmount; ++i)
        {
            analyzer->renew40(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS4::RENEW4args*>(nullptr),
                              &renew40);
        }
        const struct NFS4::RESTOREFH4res restorefh40 {};
        for (int i = 0; i < NfsV40restorefhOpsAmount; ++i)
        {
            analyzer->restorefh40(static_cast<const struct RPCProcedure*>(nullptr),
                              &restorefh40);
        }
        const struct NFS4::SAVEFH4res savefh40 {};
        for (int i = 0; i < NfsV40savefhOpsAmount; ++i)
        {
            analyzer->savefh40(static_cast<const struct RPCProcedure*>(nullptr),
                               &savefh40);
        }
        const struct NFS4::SECINFO4res secinfo40 {};
        for (int i = 0; i < NfsV40secinfoOpsAmount; ++i)
        {
            analyzer->secinfo40(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS4::SECINFO4args*>(nullptr),
                                &secinfo40);
        }
        const struct NFS4::SETATTR4res setattr40 {};
        for (int i = 0; i < NfsV40setattrOpsAmount; ++i)
        {
            analyzer->setattr40(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS4::SETATTR4args*>(nullptr),
                                &setattr40);
        }
        const struct NFS4::SETCLIENTID4res setclientid40 {};
        for (int i = 0; i < NfsV40setclientidOpsAmount; ++i)
        {
            analyzer->setclientid40(static_cast<const struct RPCProcedure*>(nullptr),
                                    static_cast<const struct NFS4::SETCLIENTID4args*>(nullptr),
                                    &setclientid40);
        }
        const struct NFS4::SETCLIENTID_CONFIRM4res setclientid_confirm40 {};
        for (int i = 0; i < NfsV40setclientid_confirmOpsAmount; ++i)
        {
            analyzer->setclientid_confirm40(static_cast<const struct RPCProcedure*>(nullptr),
                                            static_cast<const struct NFS4::SETCLIENTID_CONFIRM4args*>(nullptr),
                                            &setclientid_confirm40);
        }
        const struct NFS4::VERIFY4res verify40 {};
        for (int i = 0; i < NfsV40verifyOpsAmount; ++i)
        {
            analyzer->verify40(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS4::VERIFY4args*>(nullptr),
                               &verify40);
        }
        const struct NFS4::WRITE4res write40 {};
        for (int i = 0; i < NfsV40writeOpsAmount; ++i)
        {
            analyzer->write40(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS4::WRITE4args*>(nullptr),
                              &write40);
        }
        const struct NFS4::RELEASE_LOCKOWNER4res release_lockowner40 {};
        for (int i = 0; i < NfsV40release_lockownerOpsAmount; ++i)
        {
            analyzer->release_lockowner40(static_cast<const struct RPCProcedure*>(nullptr),
                                          static_cast<const struct NFS4::RELEASE_LOCKOWNER4args*>(nullptr),
                                          &release_lockowner40);
        }
        const struct NFS4::GET_DIR_DELEGATION4res get_dir_delegation40 {};
        for (int i = 0; i < NfsV40get_dir_delegationOpsAmount; ++i)
        {
            analyzer->get_dir_delegation40(static_cast<const struct RPCProcedure*>(nullptr),
                                           static_cast<const struct NFS4::GET_DIR_DELEGATION4args*>(nullptr),
                                           &get_dir_delegation40);
        }
        const struct NFS4::ILLEGAL4res illegal40 {};
        for (int i = 0; i < NfsV40illegalOpsAmount; ++i)
        {
            analyzer->illegal40(static_cast<const struct RPCProcedure*>(nullptr),
                                &illegal40);
        }

        // Setting up analyzer (NFSv4.1 procedures)
        for (int i = 0; i < NfsV41NullProcsAmount; ++i)
        {
            analyzer->null41(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS41::NULL4args*>(nullptr),
                             static_cast<const struct NFS41::NULL4res*>(nullptr));
        }
        for (int i = 0; i < NfsV41CompoundProcsAmount; ++i)
        {
            analyzer->compound41(static_cast<const struct RPCProcedure*>(nullptr),
                                 static_cast<const struct NFS41::COMPOUND4args*>(nullptr),
                                 static_cast<const struct NFS41::COMPOUND4res*>(nullptr));
        }

        // Setting up analyzer (NFSv4.1 operations)
        const struct NFS41::ACCESS4res access41 {};
        for (int i = 0; i < NfsV41accessOpsAmount; ++i)
        {
            analyzer->access41(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS41::ACCESS4args*>(nullptr),
                               &access41);
        }
        const struct NFS41::CLOSE4res close41 {};
        for (int i = 0; i < NfsV41closeOpsAmount; ++i)
        {
            analyzer->close41(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS41::CLOSE4args*>(nullptr),
                              &close41);
        }
        const struct NFS41::COMMIT4res commit41 {};
        for (int i = 0; i < NfsV41commitOpsAmount; ++i)
        {
            analyzer->commit41(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS41::COMMIT4args*>(nullptr),
                               &commit41);
        }
        const struct NFS41::CREATE4res create41 {};
        for (int i = 0; i < NfsV41createOpsAmount; ++i)
        {
            analyzer->create41(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS41::CREATE4args*>(nullptr),
                               &create41);
        }
        const struct NFS41::DELEGPURGE4res delegpurge41 {};
        for (int i = 0; i < NfsV41delegpurgeOpsAmount; ++i)
        {
            analyzer->delegpurge41(static_cast<const struct RPCProcedure*>(nullptr),
                                   static_cast<const struct NFS41::DELEGPURGE4args*>(nullptr),
                                   &delegpurge41);
        }
        const struct NFS41::DELEGRETURN4res delegreturn41 {};
        for (int i = 0; i < NfsV41delegreturnOpsAmount; ++i)
        {
            analyzer->delegreturn41(static_cast<const struct RPCProcedure*>(nullptr),
                                    static_cast<const struct NFS41::DELEGRETURN4args*>(nullptr),
                                    &delegreturn41);
        }
        const struct NFS41::GETATTR4res getattr41 {};
        for (int i = 0; i < NfsV41getattrOpsAmount; ++i)
        {
            analyzer->getattr41(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS41::GETATTR4args*>(nullptr),
                                &getattr41);
        }
        const struct NFS41::GETFH4res getfh41 {};
        for (int i = 0; i < NfsV41getfhOpsAmount; ++i)
        {
            analyzer->getfh41(static_cast<const struct RPCProcedure*>(nullptr),
                              &getfh41);
        }
        const struct NFS41::LINK4res link41 {};
        for (int i = 0; i < NfsV41linkOpsAmount; ++i)
        {
            analyzer->link41(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS41::LINK4args*>(nullptr),
                             &link41);
        }
        const struct NFS41::LOCK4res lock41 {};
        for (int i = 0; i < NfsV41lockOpsAmount; ++i)
        {
            analyzer->lock41(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS41::LOCK4args*>(nullptr),
                             &lock41);
        }
        const struct NFS41::LOCKT4res lockt41 {};
        for (int i = 0; i < NfsV41locktOpsAmount; ++i)
        {
            analyzer->lockt41(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS41::LOCKT4args*>(nullptr),
                              &lockt41);
        }
        const struct NFS41::LOCKU4res locku41 {};
        for (int i = 0; i < NfsV41lockuOpsAmount; ++i)
        {
            analyzer->locku41(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS41::LOCKU4args*>(nullptr),
                              &locku41);
        }
        const struct NFS41::LOOKUP4res lookup41 {};
        for (int i = 0; i < NfsV41lookupOpsAmount; ++i)
        {
            analyzer->lookup41(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS41::LOOKUP4args*>(nullptr),
                               &lookup41);
        }
        const struct NFS41::LOOKUPP4res lookupp41 {};
        for (int i = 0; i < NfsV41lookuppOpsAmount; ++i)
        {
            analyzer->lookupp41(static_cast<const struct RPCProcedure*>(nullptr),
                                &lookupp41);
        }
        const struct NFS41::NVERIFY4res nverify41 {};
        for (int i = 0; i < NfsV41nverifyOpsAmount; ++i)
        {
            analyzer->nverify41(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS41::NVERIFY4args*>(nullptr),
                                &nverify41);
        }
        const struct NFS41::OPEN4res open41 {};
        for (int i = 0; i < NfsV41openOpsAmount; ++i)
        {
            analyzer->open41(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS41::OPEN4args*>(nullptr),
                             &open41);
        }
        const struct NFS41::OPENATTR4res openattr41 {};
        for (int i = 0; i < NfsV41openattrOpsAmount; ++i)
        {
            analyzer->openattr41(static_cast<const struct RPCProcedure*>(nullptr),
                                 static_cast<const struct NFS41::OPENATTR4args*>(nullptr),
                                 &openattr41);
        }
        const struct NFS41::OPEN_CONFIRM4res open_confirm41 {};
        for (int i = 0; i < NfsV41open_confirmOpsAmount; ++i)
        {
            analyzer->open_confirm41(static_cast<const struct RPCProcedure*>(nullptr),
                                     static_cast<const struct NFS41::OPEN_CONFIRM4args*>(nullptr),
                                     &open_confirm41);
        }
        const struct NFS41::OPEN_DOWNGRADE4res open_downgrade41 {};
        for (int i = 0; i < NfsV41open_downgradeOpsAmount; ++i)
        {
            analyzer->open_downgrade41(static_cast<const struct RPCProcedure*>(nullptr),
                                       static_cast<const struct NFS41::OPEN_DOWNGRADE4args*>(nullptr),
                                       &open_downgrade41);
        }
        const struct NFS41::PUTFH4res putfh41 {};
        for (int i = 0; i < NfsV41putfhOpsAmount; ++i)
        {
            analyzer->putfh41(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS41::PUTFH4args*>(nullptr),
                              &putfh41);
        }
        const struct NFS41::PUTPUBFH4res putpubfh41 {};
        for (int i = 0; i < NfsV41putpubfhOpsAmount; ++i)
        {
            analyzer->putpubfh41(static_cast<const struct RPCProcedure*>(nullptr),
                                 &putpubfh41);
        }
        const struct NFS41::PUTROOTFH4res putrootfh41 {};
        for (int i = 0; i < NfsV41putrootfhOpsAmount; ++i)
        {
            analyzer->putrootfh41(static_cast<const struct RPCProcedure*>(nullptr),
                                  &putrootfh41);
        }
        const struct NFS41::READ4res read41 {};
        for (int i = 0; i < NfsV41readOpsAmount; ++i)
        {
            analyzer->read41(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct NFS41::READ4args*>(nullptr),
                             &read41);
        }
        const struct NFS41::READDIR4res readdir41 {};
        for (int i = 0; i < NfsV41readdirOpsAmount; ++i)
        {
            analyzer->readdir41(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS41::READDIR4args*>(nullptr),
                                &readdir41);
        }
        const struct NFS41::READLINK4res readlink41 {};
        for (int i = 0; i < NfsV41readlinkOpsAmount; ++i)
        {
            analyzer->readlink41(static_cast<const struct RPCProcedure*>(nullptr),
                                 &readlink41);
        }
        const struct NFS41::REMOVE4res remove41 {};
        for (int i = 0; i < NfsV41removeOpsAmount; ++i)
        {
            analyzer->remove41(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS41::REMOVE4args*>(nullptr),
                               &remove41);
        }
        const struct NFS41::RENAME4res rename41 {};
        for (int i = 0; i < NfsV41renameOpsAmount; ++i)
        {
            analyzer->rename41(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS41::RENAME4args*>(nullptr),
                               &rename41);
        }
        const struct NFS41::RENEW4res renew41 {};
        for (int i = 0; i < NfsV41renewOpsAmount; ++i)
        {
            analyzer->renew41(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS41::RENEW4args*>(nullptr),
                              &renew41);
        }
        const struct NFS41::RESTOREFH4res restorefh41 {};
        for (int i = 0; i < NfsV41restorefhOpsAmount; ++i)
        {
            analyzer->restorefh41(static_cast<const struct RPCProcedure*>(nullptr),
                              &restorefh41);
        }
        const struct NFS41::SAVEFH4res savefh41 {};
        for (int i = 0; i < NfsV41savefhOpsAmount; ++i)
        {
            analyzer->savefh41(static_cast<const struct RPCProcedure*>(nullptr),
                               &savefh41);
        }
        const struct NFS41::SECINFO4res secinfo41 {};
        for (int i = 0; i < NfsV41secinfoOpsAmount; ++i)
        {
            analyzer->secinfo41(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS41::SECINFO4args*>(nullptr),
                                &secinfo41);
        }
        const struct NFS41::SETATTR4res setattr41 {};
        for (int i = 0; i < NfsV41setattrOpsAmount; ++i)
        {
            analyzer->setattr41(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS41::SETATTR4args*>(nullptr),
                                &setattr41);
        }
        const struct NFS41::SETCLIENTID4res setclientid41 {};
        for (int i = 0; i < NfsV41setclientidOpsAmount; ++i)
        {
            analyzer->setclientid41(static_cast<const struct RPCProcedure*>(nullptr),
                                    static_cast<const struct NFS41::SETCLIENTID4args*>(nullptr),
                                    &setclientid41);
        }
        const struct NFS41::SETCLIENTID_CONFIRM4res setclientid_confirm41 {};
        for (int i = 0; i < NfsV41setclientid_confirmOpsAmount; ++i)
        {
            analyzer->setclientid_confirm41(static_cast<const struct RPCProcedure*>(nullptr),
                                            static_cast<const struct NFS41::SETCLIENTID_CONFIRM4args*>(nullptr),
                                            &setclientid_confirm41);
        }
        const struct NFS41::VERIFY4res verify41 {};
        for (int i = 0; i < NfsV41verifyOpsAmount; ++i)
        {
            analyzer->verify41(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct NFS41::VERIFY4args*>(nullptr),
                               &verify41);
        }
        const struct NFS41::WRITE4res write41 {};
        for (int i = 0; i < NfsV41writeOpsAmount; ++i)
        {
            analyzer->write41(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct NFS41::WRITE4args*>(nullptr),
                              &write41);
        }
        const struct NFS41::RELEASE_LOCKOWNER4res release_lockowner41 {};
        for (int i = 0; i < NfsV41release_lockownerOpsAmount; ++i)
        {
            analyzer->release_lockowner41(static_cast<const struct RPCProcedure*>(nullptr),
                                          static_cast<const struct NFS41::RELEASE_LOCKOWNER4args*>(nullptr),
                                          &release_lockowner41);
        }
        const struct NFS41::BACKCHANNEL_CTL4res backchannel_ctl41 {};
        for (int i = 0; i < NfsV41backchannel_ctlOpsAmount; ++i)
        {
            analyzer->backchannel_ctl41(static_cast<const struct RPCProcedure*>(nullptr),
                                        static_cast<const struct NFS41::BACKCHANNEL_CTL4args*>(nullptr),
                                        &backchannel_ctl41);
        }
        const struct NFS41::BIND_CONN_TO_SESSION4res bind_conn_to_session41 {};
        for (int i = 0; i < NfsV41bind_conn_to_sessionOpsAmount; ++i)
        {
            analyzer->bind_conn_to_session41(static_cast<const struct RPCProcedure*>(nullptr),
                                             static_cast<const struct NFS41::BIND_CONN_TO_SESSION4args*>(nullptr),
                                             &bind_conn_to_session41);
        }
        const struct NFS41::EXCHANGE_ID4res exchange_id41 {};
        for (int i = 0; i < NfsV41exchange_idOpsAmount; ++i)
        {
            analyzer->exchange_id41(static_cast<const struct RPCProcedure*>(nullptr),
                                    static_cast<const struct NFS41::EXCHANGE_ID4args*>(nullptr),
                                    &exchange_id41);
        }
        const struct NFS41::CREATE_SESSION4res create_session41 {};
        for (int i = 0; i < NfsV41create_sessionOpsAmount; ++i)
        {
            analyzer->create_session41(static_cast<const struct RPCProcedure*>(nullptr),
                                       static_cast<const struct NFS41::CREATE_SESSION4args*>(nullptr),
                                       &create_session41);
        }
        const struct NFS41::DESTROY_SESSION4res destroy_session41 {};
        for (int i = 0; i < NfsV41destroy_sessionOpsAmount; ++i)
        {
            analyzer->destroy_session41(static_cast<const struct RPCProcedure*>(nullptr),
                                        static_cast<const struct NFS41::DESTROY_SESSION4args*>(nullptr),
                                        &destroy_session41);
        }
        const struct NFS41::FREE_STATEID4res free_stateid41 {};
        for (int i = 0; i < NfsV41free_stateidOpsAmount; ++i)
        {
            analyzer->free_stateid41(static_cast<const struct RPCProcedure*>(nullptr),
                                     static_cast<const struct NFS41::FREE_STATEID4args*>(nullptr),
                                     &free_stateid41);
        }
        const struct NFS41::GET_DIR_DELEGATION4res get_dir_delegation41 {};
        for (int i = 0; i < NfsV41get_dir_delegationOpsAmount; ++i)
        {
            analyzer->get_dir_delegation41(static_cast<const struct RPCProcedure*>(nullptr),
                                           static_cast<const struct NFS41::GET_DIR_DELEGATION4args*>(nullptr),
                                           &get_dir_delegation41);
        }
        const struct NFS41::GETDEVICEINFO4res getdeviceinfo41 {};
        for (int i = 0; i < NfsV41getdeviceinfoOpsAmount; ++i)
        {
            analyzer->getdeviceinfo41(static_cast<const struct RPCProcedure*>(nullptr),
                                      static_cast<const struct NFS41::GETDEVICEINFO4args*>(nullptr),
                                      &getdeviceinfo41);
        }
        const struct NFS41::GETDEVICELIST4res getdevicelist41 {};
        for (int i = 0; i < NfsV41getdevicelistOpsAmount; ++i)
        {
            analyzer->getdevicelist41(static_cast<const struct RPCProcedure*>(nullptr),
                                      static_cast<const struct NFS41::GETDEVICELIST4args*>(nullptr),
                                      &getdevicelist41);
        }
        const struct NFS41::LAYOUTCOMMIT4res layoutcommit41 {};
        for (int i = 0; i < NfsV41layoutcommitOpsAmount; ++i)
        {
            analyzer->layoutcommit41(static_cast<const struct RPCProcedure*>(nullptr),
                                     static_cast<const struct NFS41::LAYOUTCOMMIT4args*>(nullptr),
                                     &layoutcommit41);
        }
        const struct NFS41::LAYOUTGET4res layoutget41 {};
        for (int i = 0; i < NfsV41layoutgetOpsAmount; ++i)
        {
            analyzer->layoutget41(static_cast<const struct RPCProcedure*>(nullptr),
                                  static_cast<const struct NFS41::LAYOUTGET4args*>(nullptr),
                                  &layoutget41);
        }
        const struct NFS41::LAYOUTRETURN4res layoutreturn41 {};
        for (int i = 0; i < NfsV41layoutreturnOpsAmount; ++i)
        {
            analyzer->layoutreturn41(static_cast<const struct RPCProcedure*>(nullptr),
                                     static_cast<const struct NFS41::LAYOUTRETURN4args*>(nullptr),
                                     &layoutreturn41);
        }
        const NFS41::SECINFO_NO_NAME4res secinfo_no_name41 {};
        for (int i = 0; i < NfsV41secinfo_no_nameOpsAmount; ++i)
        {
            analyzer->secinfo_no_name41(static_cast<const struct RPCProcedure*>(nullptr),
                                        static_cast<const NFS41::SECINFO_NO_NAME4args*>(nullptr),
                                        &secinfo_no_name41);
        }
        const struct NFS41::SEQUENCE4res sequence41 {};
        for (int i = 0; i < NfsV41sequenceOpsAmount; ++i)
        {
            analyzer->sequence41(static_cast<const struct RPCProcedure*>(nullptr),
                                 static_cast<const struct NFS41::SEQUENCE4args*>(nullptr),
                                 &sequence41);
        }
        const struct NFS41::SET_SSV4res set_ssv41 {};
        for (int i = 0; i < NfsV41set_ssvOpsAmount; ++i)
        {
            analyzer->set_ssv41(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct NFS41::SET_SSV4args*>(nullptr),
                                &set_ssv41);
        }
        const struct NFS41::TEST_STATEID4res test_stateid41 {};
        for (int i = 0; i < NfsV41test_stateidOpsAmount; ++i)
        {
            analyzer->test_stateid41(static_cast<const struct RPCProcedure*>(nullptr),
                                     static_cast<const struct NFS41::TEST_STATEID4args*>(nullptr),
                                     &test_stateid41);
        }
        const struct NFS41::WANT_DELEGATION4res want_delegation41 {};
        for (int i = 0; i < NfsV41want_delegationOpsAmount; ++i)
        {
            analyzer->want_delegation41(static_cast<const struct RPCProcedure*>(nullptr),
                                        static_cast<const struct NFS41::WANT_DELEGATION4args*>(nullptr),
                                        &want_delegation41);
        }
        const struct NFS41::DESTROY_CLIENTID4res destroy_clientid41 {};
        for (int i = 0; i < NfsV41destroy_clientidOpsAmount; ++i)
        {
            analyzer->destroy_clientid41(static_cast<const struct RPCProcedure*>(nullptr),
                                         static_cast<const struct NFS41::DESTROY_CLIENTID4args*>(nullptr),
                                         &destroy_clientid41);
        }
        const struct NFS41::RECLAIM_COMPLETE4res reclaim_complete41 {};
        for (int i = 0; i < NfsV41reclaim_completeOpsAmount; ++i)
        {
            analyzer->reclaim_complete41(static_cast<const struct RPCProcedure*>(nullptr),
                                         static_cast<const struct NFS41::RECLAIM_COMPLETE4args*>(nullptr),
                                         &reclaim_complete41);
        }
        const struct NFS41::ILLEGAL4res illegal41 {};
        for (int i = 0; i < NfsV41illegalOpsAmount; ++i)
        {
            analyzer->illegal41(static_cast<const struct RPCProcedure*>(nullptr),
                                &illegal41);
        }
 

    }
    virtual void TearDown() override final
    {
        analyzer.reset();
    }

    std::unique_ptr<JsonAnalyzer> analyzer;
};

TEST_F(JsonAnalyzerCase, collectStatistics)
{
    // NFS3 procedures
    EXPECT_EQ(NfsV3NullProcsAmount, analyzer->getNfsV3Stat().nullProcsAmount.load());
    EXPECT_EQ(NfsV3GetattrProcsAmount, analyzer->getNfsV3Stat().getattrProcsAmount.load());
    EXPECT_EQ(NfsV3SetattrProcsAmount, analyzer->getNfsV3Stat().setattrProcsAmount.load());
    EXPECT_EQ(NfsV3AccessProcsAmount, analyzer->getNfsV3Stat().accessProcsAmount.load());
    EXPECT_EQ(NfsV3ReadlinkProcsAmount, analyzer->getNfsV3Stat().readlinkProcsAmount.load());
    EXPECT_EQ(NfsV3ReadProcsAmount, analyzer->getNfsV3Stat().readProcsAmount.load());
    EXPECT_EQ(NfsV3WriteProcsAmount, analyzer->getNfsV3Stat().writeProcsAmount.load());
    EXPECT_EQ(NfsV3CreateProcsAmount, analyzer->getNfsV3Stat().createProcsAmount.load());
    EXPECT_EQ(NfsV3MkdirProcsAmount, analyzer->getNfsV3Stat().mkdirProcsAmount.load());
    EXPECT_EQ(NfsV3SymlinkProcsAmount, analyzer->getNfsV3Stat().symlinkProcsAmount.load());
    EXPECT_EQ(NfsV3MknodProcsAmount, analyzer->getNfsV3Stat().mknodProcsAmount.load());
    EXPECT_EQ(NfsV3RemoveProcsAmount, analyzer->getNfsV3Stat().removeProcsAmount.load());
    EXPECT_EQ(NfsV3RmdirProcsAmount, analyzer->getNfsV3Stat().rmdirProcsAmount.load());
    EXPECT_EQ(NfsV3RenameProcsAmount, analyzer->getNfsV3Stat().renameProcsAmount.load());
    EXPECT_EQ(NfsV3LinkProcsAmount, analyzer->getNfsV3Stat().linkProcsAmount.load());
    EXPECT_EQ(NfsV3ReaddirProcsAmount, analyzer->getNfsV3Stat().readdirProcsAmount.load());
    EXPECT_EQ(NfsV3ReaddirplusProcsAmount, analyzer->getNfsV3Stat().readdirplusProcsAmount.load());
    EXPECT_EQ(NfsV3FsstatProcsAmount, analyzer->getNfsV3Stat().fsstatProcsAmount.load());
    EXPECT_EQ(NfsV3FsinfoProcsAmount, analyzer->getNfsV3Stat().fsinfoProcsAmount.load());
    EXPECT_EQ(NfsV3PathconfProcsAmount, analyzer->getNfsV3Stat().pathconfProcsAmount.load());
    EXPECT_EQ(NfsV3CommitProcsAmount, analyzer->getNfsV3Stat().commitProcsAmount.load());

    // NFS 4.0 procedures
    EXPECT_EQ(NfsV40NullProcsAmount, analyzer->getNfsV40Stat().nullProcsAmount.load());
    EXPECT_EQ(NfsV40CompoundProcsAmount, analyzer->getNfsV40Stat().compoundProcsAmount.load());

    // NFS 4.0 operations
    EXPECT_EQ(NfsV40accessOpsAmount, analyzer->getNfsV40Stat().accessOpsAmount.load());
    EXPECT_EQ(NfsV40closeOpsAmount, analyzer->getNfsV40Stat().closeOpsAmount.load());
    EXPECT_EQ(NfsV40commitOpsAmount, analyzer->getNfsV40Stat().commitOpsAmount.load());
    EXPECT_EQ(NfsV40createOpsAmount, analyzer->getNfsV40Stat().createOpsAmount.load());
    EXPECT_EQ(NfsV40delegpurgeOpsAmount, analyzer->getNfsV40Stat().delegpurgeOpsAmount.load());
    EXPECT_EQ(NfsV40delegreturnOpsAmount, analyzer->getNfsV40Stat().delegreturnOpsAmount.load());
    EXPECT_EQ(NfsV40getattrOpsAmount, analyzer->getNfsV40Stat().getattrOpsAmount.load());
    EXPECT_EQ(NfsV40getfhOpsAmount, analyzer->getNfsV40Stat().getfhOpsAmount.load());
    EXPECT_EQ(NfsV40linkOpsAmount, analyzer->getNfsV40Stat().linkOpsAmount.load());
    EXPECT_EQ(NfsV40lockOpsAmount, analyzer->getNfsV40Stat().lockOpsAmount.load());
    EXPECT_EQ(NfsV40locktOpsAmount, analyzer->getNfsV40Stat().locktOpsAmount.load());
    EXPECT_EQ(NfsV40lockuOpsAmount, analyzer->getNfsV40Stat().lockuOpsAmount.load());
    EXPECT_EQ(NfsV40lookupOpsAmount, analyzer->getNfsV40Stat().lookupOpsAmount.load());
    EXPECT_EQ(NfsV40lookuppOpsAmount, analyzer->getNfsV40Stat().lookuppOpsAmount.load());
    EXPECT_EQ(NfsV40nverifyOpsAmount, analyzer->getNfsV40Stat().nverifyOpsAmount.load());
    EXPECT_EQ(NfsV40openOpsAmount, analyzer->getNfsV40Stat().openOpsAmount.load());
    EXPECT_EQ(NfsV40openattrOpsAmount, analyzer->getNfsV40Stat().openattrOpsAmount.load());
    EXPECT_EQ(NfsV40open_confirmOpsAmount, analyzer->getNfsV40Stat().open_confirmOpsAmount.load());
    EXPECT_EQ(NfsV40open_downgradeOpsAmount, analyzer->getNfsV40Stat().open_downgradeOpsAmount.load());
    EXPECT_EQ(NfsV40putfhOpsAmount, analyzer->getNfsV40Stat().putfhOpsAmount.load());
    EXPECT_EQ(NfsV40putpubfhOpsAmount, analyzer->getNfsV40Stat().putpubfhOpsAmount.load());
    EXPECT_EQ(NfsV40putrootfhOpsAmount, analyzer->getNfsV40Stat().putrootfhOpsAmount.load());
    EXPECT_EQ(NfsV40readOpsAmount, analyzer->getNfsV40Stat().readOpsAmount.load());
    EXPECT_EQ(NfsV40readdirOpsAmount, analyzer->getNfsV40Stat().readdirOpsAmount.load());
    EXPECT_EQ(NfsV40readlinkOpsAmount, analyzer->getNfsV40Stat().readlinkOpsAmount.load());
    EXPECT_EQ(NfsV40removeOpsAmount, analyzer->getNfsV40Stat().removeOpsAmount.load());
    EXPECT_EQ(NfsV40renameOpsAmount, analyzer->getNfsV40Stat().renameOpsAmount.load());
    EXPECT_EQ(NfsV40renewOpsAmount, analyzer->getNfsV40Stat().renewOpsAmount.load());
    EXPECT_EQ(NfsV40restorefhOpsAmount, analyzer->getNfsV40Stat().restorefhOpsAmount.load());
    EXPECT_EQ(NfsV40savefhOpsAmount, analyzer->getNfsV40Stat().savefhOpsAmount.load());
    EXPECT_EQ(NfsV40secinfoOpsAmount, analyzer->getNfsV40Stat().secinfoOpsAmount.load());
    EXPECT_EQ(NfsV40setattrOpsAmount, analyzer->getNfsV40Stat().setattrOpsAmount.load());
    EXPECT_EQ(NfsV40setclientidOpsAmount, analyzer->getNfsV40Stat().setclientidOpsAmount.load());
    EXPECT_EQ(NfsV40setclientid_confirmOpsAmount, analyzer->getNfsV40Stat().setclientid_confirmOpsAmount.load());
    EXPECT_EQ(NfsV40verifyOpsAmount, analyzer->getNfsV40Stat().verifyOpsAmount.load());
    EXPECT_EQ(NfsV40writeOpsAmount, analyzer->getNfsV40Stat().writeOpsAmount.load());
    EXPECT_EQ(NfsV40release_lockownerOpsAmount, analyzer->getNfsV40Stat().release_lockownerOpsAmount.load());
    EXPECT_EQ(NfsV40get_dir_delegationOpsAmount, analyzer->getNfsV40Stat().get_dir_delegationOpsAmount.load());
    EXPECT_EQ(NfsV40illegalOpsAmount, analyzer->getNfsV40Stat().illegalOpsAmount.load());

    // NFS 4.1 procedures
    EXPECT_EQ(NfsV41NullProcsAmount, analyzer->getNfsV41Stat().nullProcsAmount.load());
    EXPECT_EQ(NfsV41CompoundProcsAmount, analyzer->getNfsV41Stat().compoundProcsAmount.load());

    // NFS 4.1 operations
    EXPECT_EQ(NfsV41accessOpsAmount, analyzer->getNfsV41Stat().accessOpsAmount.load());
    EXPECT_EQ(NfsV41closeOpsAmount, analyzer->getNfsV41Stat().closeOpsAmount.load());
    EXPECT_EQ(NfsV41commitOpsAmount, analyzer->getNfsV41Stat().commitOpsAmount.load());
    EXPECT_EQ(NfsV41createOpsAmount, analyzer->getNfsV41Stat().createOpsAmount.load());
    EXPECT_EQ(NfsV41delegpurgeOpsAmount, analyzer->getNfsV41Stat().delegpurgeOpsAmount.load());
    EXPECT_EQ(NfsV41delegreturnOpsAmount, analyzer->getNfsV41Stat().delegreturnOpsAmount.load());
    EXPECT_EQ(NfsV41getattrOpsAmount, analyzer->getNfsV41Stat().getattrOpsAmount.load());
    EXPECT_EQ(NfsV41getfhOpsAmount, analyzer->getNfsV41Stat().getfhOpsAmount.load());
    EXPECT_EQ(NfsV41linkOpsAmount, analyzer->getNfsV41Stat().linkOpsAmount.load());
    EXPECT_EQ(NfsV41lockOpsAmount, analyzer->getNfsV41Stat().lockOpsAmount.load());
    EXPECT_EQ(NfsV41locktOpsAmount, analyzer->getNfsV41Stat().locktOpsAmount.load());
    EXPECT_EQ(NfsV41lockuOpsAmount, analyzer->getNfsV41Stat().lockuOpsAmount.load());
    EXPECT_EQ(NfsV41lookupOpsAmount, analyzer->getNfsV41Stat().lookupOpsAmount.load());
    EXPECT_EQ(NfsV41lookuppOpsAmount, analyzer->getNfsV41Stat().lookuppOpsAmount.load());
    EXPECT_EQ(NfsV41nverifyOpsAmount, analyzer->getNfsV41Stat().nverifyOpsAmount.load());
    EXPECT_EQ(NfsV41openOpsAmount, analyzer->getNfsV41Stat().openOpsAmount.load());
    EXPECT_EQ(NfsV41openattrOpsAmount, analyzer->getNfsV41Stat().openattrOpsAmount.load());
    EXPECT_EQ(NfsV41open_confirmOpsAmount, analyzer->getNfsV41Stat().open_confirmOpsAmount.load());
    EXPECT_EQ(NfsV41open_downgradeOpsAmount, analyzer->getNfsV41Stat().open_downgradeOpsAmount.load());
    EXPECT_EQ(NfsV41putfhOpsAmount, analyzer->getNfsV41Stat().putfhOpsAmount.load());
    EXPECT_EQ(NfsV41putpubfhOpsAmount, analyzer->getNfsV41Stat().putpubfhOpsAmount.load());
    EXPECT_EQ(NfsV41putrootfhOpsAmount, analyzer->getNfsV41Stat().putrootfhOpsAmount.load());
    EXPECT_EQ(NfsV41readOpsAmount, analyzer->getNfsV41Stat().readOpsAmount.load());
    EXPECT_EQ(NfsV41readdirOpsAmount, analyzer->getNfsV41Stat().readdirOpsAmount.load());
    EXPECT_EQ(NfsV41readlinkOpsAmount, analyzer->getNfsV41Stat().readlinkOpsAmount.load());
    EXPECT_EQ(NfsV41removeOpsAmount, analyzer->getNfsV41Stat().removeOpsAmount.load());
    EXPECT_EQ(NfsV41renameOpsAmount, analyzer->getNfsV41Stat().renameOpsAmount.load());
    EXPECT_EQ(NfsV41renewOpsAmount, analyzer->getNfsV41Stat().renewOpsAmount.load());
    EXPECT_EQ(NfsV41restorefhOpsAmount, analyzer->getNfsV41Stat().restorefhOpsAmount.load());
    EXPECT_EQ(NfsV41savefhOpsAmount, analyzer->getNfsV41Stat().savefhOpsAmount.load());
    EXPECT_EQ(NfsV41secinfoOpsAmount, analyzer->getNfsV41Stat().secinfoOpsAmount.load());
    EXPECT_EQ(NfsV41setattrOpsAmount, analyzer->getNfsV41Stat().setattrOpsAmount.load());
    EXPECT_EQ(NfsV41setclientidOpsAmount, analyzer->getNfsV41Stat().setclientidOpsAmount.load());
    EXPECT_EQ(NfsV41setclientid_confirmOpsAmount, analyzer->getNfsV41Stat().setclientid_confirmOpsAmount.load());
    EXPECT_EQ(NfsV41verifyOpsAmount, analyzer->getNfsV41Stat().verifyOpsAmount.load());
    EXPECT_EQ(NfsV41writeOpsAmount, analyzer->getNfsV41Stat().writeOpsAmount.load());
    EXPECT_EQ(NfsV41release_lockownerOpsAmount, analyzer->getNfsV41Stat().release_lockownerOpsAmount.load());
    EXPECT_EQ(NfsV41backchannel_ctlOpsAmount, analyzer->getNfsV41Stat().backchannel_ctlOpsAmount.load());
    EXPECT_EQ(NfsV41bind_conn_to_sessionOpsAmount, analyzer->getNfsV41Stat().bind_conn_to_sessionOpsAmount.load());
    EXPECT_EQ(NfsV41exchange_idOpsAmount, analyzer->getNfsV41Stat().exchange_idOpsAmount.load());
    EXPECT_EQ(NfsV41create_sessionOpsAmount, analyzer->getNfsV41Stat().create_sessionOpsAmount.load());
    EXPECT_EQ(NfsV41destroy_sessionOpsAmount, analyzer->getNfsV41Stat().destroy_sessionOpsAmount.load());
    EXPECT_EQ(NfsV41free_stateidOpsAmount, analyzer->getNfsV41Stat().free_stateidOpsAmount.load());
    EXPECT_EQ(NfsV41get_dir_delegationOpsAmount, analyzer->getNfsV41Stat().get_dir_delegationOpsAmount.load());
    EXPECT_EQ(NfsV41getdeviceinfoOpsAmount, analyzer->getNfsV41Stat().getdeviceinfoOpsAmount.load());
    EXPECT_EQ(NfsV41getdevicelistOpsAmount, analyzer->getNfsV41Stat().getdevicelistOpsAmount.load());
    EXPECT_EQ(NfsV41layoutcommitOpsAmount, analyzer->getNfsV41Stat().layoutcommitOpsAmount.load());
    EXPECT_EQ(NfsV41layoutgetOpsAmount, analyzer->getNfsV41Stat().layoutgetOpsAmount.load());
    EXPECT_EQ(NfsV41layoutreturnOpsAmount, analyzer->getNfsV41Stat().layoutreturnOpsAmount.load());
    EXPECT_EQ(NfsV41secinfo_no_nameOpsAmount, analyzer->getNfsV41Stat().secinfo_no_nameOpsAmount.load());
    EXPECT_EQ(NfsV41sequenceOpsAmount, analyzer->getNfsV41Stat().sequenceOpsAmount.load());
    EXPECT_EQ(NfsV41set_ssvOpsAmount, analyzer->getNfsV41Stat().set_ssvOpsAmount.load());
    EXPECT_EQ(NfsV41test_stateidOpsAmount, analyzer->getNfsV41Stat().test_stateidOpsAmount.load());
    EXPECT_EQ(NfsV41want_delegationOpsAmount, analyzer->getNfsV41Stat().want_delegationOpsAmount.load());
    EXPECT_EQ(NfsV41destroy_clientidOpsAmount, analyzer->getNfsV41Stat().destroy_clientidOpsAmount.load());
    EXPECT_EQ(NfsV41reclaim_completeOpsAmount, analyzer->getNfsV41Stat().reclaim_completeOpsAmount.load());
    EXPECT_EQ(NfsV41illegalOpsAmount, analyzer->getNfsV41Stat().illegalOpsAmount.load());
}

TEST_F(JsonAnalyzerCase, requestResponse)
{
    // Connecting to service
    int s = socket(PF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    IpEndpoint endpoint{ListenHost, ListenPort};
    ASSERT_EQ(0, connect(s, endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen));
    char receiveBuffer[ReceiveBufferSize];
    ssize_t bytesReceived = recv(s, receiveBuffer, sizeof(receiveBuffer), 0);
    EXPECT_GT(bytesReceived, 0);
    // Decoding and checking response
    json_object* root = json_tokener_parse(std::string(receiveBuffer, bytesReceived).c_str());
    EXPECT_NE(nullptr, root);
    EXPECT_EQ(json_type_object, json_object_get_type(root));

    // Checking NFSv3 statistics
    struct json_object* nfsV3Stat;
    EXPECT_TRUE(json_object_object_get_ex(root, "nfs_v3", &nfsV3Stat));
    EXPECT_NE(nullptr, nfsV3Stat);
    EXPECT_EQ(json_type_object, json_object_get_type(nfsV3Stat));

    struct json_object* val;
    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "null", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3NullProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "getattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3GetattrProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "setattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3SetattrProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "lookup", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3LookupProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "access", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3AccessProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "readlink", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3ReadlinkProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "read", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3ReadProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "write", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3WriteProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "create", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3CreateProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "mkdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3MkdirProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "symlink", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3SymlinkProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "mkdnod", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3MknodProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "remove", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3RemoveProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "rmdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3RmdirProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "rename", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3RenameProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "link", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3LinkProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "readdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3ReaddirProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "readdirplus", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3ReaddirplusProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "fsstat", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3FsstatProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "fsinfo", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3FsinfoProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "pathconf", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3PathconfProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "commit", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3CommitProcsAmount, json_object_get_int64(val));

    // Checking NFSv4.0 statistics
    struct json_object* nfsV40Stat;
    EXPECT_TRUE(json_object_object_get_ex(root, "nfs_v40", &nfsV40Stat));
    EXPECT_NE(nullptr, nfsV40Stat);

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "null", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40NullProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "compound", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40CompoundProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "access", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40accessOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "close", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40closeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "commit", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40commitOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "create", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40createOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "delegpurge", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40delegpurgeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "delegreturn", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40delegreturnOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "getattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40getattrOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "getfh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40getfhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "link", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40linkOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "lock", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40lockOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "lockt", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40locktOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "locku", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40lockuOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "lookup", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40lookupOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "lookupp", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40lookuppOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "nverify", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40nverifyOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "open", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40openOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "openattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40openattrOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "open_confirm", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40open_confirmOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "open_downgrade", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40open_downgradeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "putfh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40putfhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "putpubfh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40putpubfhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "putrootfh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40putrootfhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "read", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40readOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "readdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40readdirOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "readlink", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40readlinkOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "remove", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40removeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "rename", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40renameOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "renew", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40renewOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "restorefh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40restorefhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "savefh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40savefhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "secinfo", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40secinfoOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "setattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40setattrOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "setclientid", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40setclientidOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "setclientid_confirm", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40setclientid_confirmOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "verify", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40verifyOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "write", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40writeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "release_lockowner", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40release_lockownerOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "get_dir_delegation", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40get_dir_delegationOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV40Stat, "illegal", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV40illegalOpsAmount, json_object_get_int64(val));

    // Checking NFSv4.1 statistics
    struct json_object* nfsV41Stat;
    EXPECT_TRUE(json_object_object_get_ex(root, "nfs_v41", &nfsV41Stat));
    EXPECT_NE(nullptr, nfsV41Stat);

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "null", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41NullProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "compound", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41CompoundProcsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "access", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41accessOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "close", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41closeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "commit", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41commitOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "create", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41createOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "delegpurge", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41delegpurgeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "delegreturn", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41delegreturnOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "getattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41getattrOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "getfh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41getfhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "link", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41linkOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "lock", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41lockOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "lockt", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41locktOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "locku", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41lockuOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "lookup", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41lookupOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "lookupp", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41lookuppOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "nverify", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41nverifyOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "open", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41openOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "openattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41openattrOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "open_confirm", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41open_confirmOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "open_downgrade", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41open_downgradeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "putfh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41putfhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "putpubfh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41putpubfhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "putrootfh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41putrootfhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "read", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41readOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "readdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41readdirOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "readlink", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41readlinkOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "remove", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41removeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "rename", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41renameOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "renew", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41renewOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "restorefh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41restorefhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "savefh", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41savefhOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "secinfo", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41secinfoOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "setattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41setattrOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "setclientid", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41setclientidOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "setclientid_confirm", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41setclientid_confirmOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "verify", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41verifyOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "write", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41writeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "release_lockowner", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41release_lockownerOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "backchannel_ctl", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41backchannel_ctlOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "bind_conn_to_session", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41bind_conn_to_sessionOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "exchange_id", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41exchange_idOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "create_session", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41create_sessionOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "destroy_session", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41destroy_sessionOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "free_stateid", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41free_stateidOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "get_dir_delegation", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41get_dir_delegationOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "getdeviceinfo", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41getdeviceinfoOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "getdevicelist", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41getdevicelistOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "layoutcommit", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41layoutcommitOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "layoutget", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41layoutgetOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "layoutreturn", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41layoutreturnOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "secinfo_no_name", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41secinfo_no_nameOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "sequence", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41sequenceOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "set_ssv", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41set_ssvOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "test_stateid", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41test_stateidOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "want_delegation", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41want_delegationOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "destroy_clientid", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41destroy_clientidOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "reclaim_complete", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41reclaim_completeOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV41Stat, "illegal", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV41illegalOpsAmount, json_object_get_int64(val));

    // Collecting garbage
    json_object_put(root);
    EXPECT_EQ(0, close(s));
}

TEST_F(JsonAnalyzerCase, slowClient)
{
    int s = socket(PF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    IpEndpoint endpoint{ListenHost, ListenPort};
    ASSERT_EQ(0, connect(s, endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen));
    std::this_thread::sleep_for(std::chrono::milliseconds{SlowClientTimeoutMs});
    char receiveBuffer[ReceiveBufferSize];
    ssize_t bytesReceived = recv(s, receiveBuffer, sizeof(receiveBuffer), 0);
    EXPECT_GT(bytesReceived, 0);
    EXPECT_EQ(0, close(s));
}

int main(int argc, char** argv)
{
    setenv("LANG", "C", 1);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
