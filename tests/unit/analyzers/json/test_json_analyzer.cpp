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
static constexpr const char* ListenHost = TcpEndpoint::LoopbackAddress;
static constexpr std::size_t MaxServingDurationMs = 200;
static constexpr int ListenBacklog = 15;
static constexpr std::size_t ReceiveBufferSize = 4096U;
static constexpr std::size_t SlowClientTimeoutMs = 300U;

static constexpr int NfsV3NullOpsAmount = 25;
static constexpr int NfsV3GetattrOpsAmount = 35;
static constexpr int NfsV3SetattrOpsAmount = 80;
static constexpr int NfsV3LookupOpsAmount = 76;
static constexpr int NfsV3AccessOpsAmount = 42;
static constexpr int NfsV3ReadlinkOpsAmount = 24;
static constexpr int NfsV3ReadOpsAmount = 56;
static constexpr int NfsV3WriteOpsAmount = 152;
static constexpr int NfsV3CreateOpsAmount = 31;
static constexpr int NfsV3MkdirOpsAmount = 97;
static constexpr int NfsV3SymlinkOpsAmount = 69;
static constexpr int NfsV3MknodOpsAmount = 73;
static constexpr int NfsV3RemoveOpsAmount = 36;
static constexpr int NfsV3RmdirOpsAmount = 27;
static constexpr int NfsV3RenameOpsAmount = 59;
static constexpr int NfsV3LinkOpsAmount = 28;
static constexpr int NfsV3ReaddirOpsAmount = 83;
static constexpr int NfsV3ReaddirplusOpsAmount = 74;
static constexpr int NfsV3FsstatOpsAmount = 95;
static constexpr int NfsV3FsinfoOpsAmount = 57;
static constexpr int NfsV3PathconfOpsAmount = 26;
static constexpr int NfsV3CommitOpsAmount = 79;

static constexpr int NfsV4NullOpsAmount = 81;
static constexpr int NfsV4CompoundOpsAmount = 18;

class JsonAnalyzerCase : public ::testing::Test
{
protected:
    virtual void SetUp() override final
    {
        // Starting service
        analyzer.reset(new JsonAnalyzer{WorkersAmount, ListenPort, ListenHost, MaxServingDurationMs, ListenBacklog});
        std::this_thread::sleep_for(std::chrono::milliseconds{AwaitForServiceStartupMs});
        // Setting up analyzer (NFSv3)
        for (int i = 0; i < NfsV3NullOpsAmount; ++i)
        {
            analyzer->null(static_cast<const struct RPCProcedure*>(nullptr),
                           static_cast<const struct rpcgen::NULL3args*>(nullptr),
                           static_cast<const struct rpcgen::NULL3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3GetattrOpsAmount; ++i)
        {
            analyzer->getattr3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct rpcgen::GETATTR3args*>(nullptr),
                               static_cast<const struct rpcgen::GETATTR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3SetattrOpsAmount; ++i)
        {
            analyzer->setattr3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct rpcgen::SETATTR3args*>(nullptr),
                               static_cast<const struct rpcgen::SETATTR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3LookupOpsAmount; ++i)
        {
            analyzer->lookup3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::LOOKUP3args*>(nullptr),
                              static_cast<const struct rpcgen::LOOKUP3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3AccessOpsAmount; ++i)
        {
            analyzer->access3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::ACCESS3args*>(nullptr),
                              static_cast<const struct rpcgen::ACCESS3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3ReadlinkOpsAmount; ++i)
        {
            analyzer->readlink3(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct rpcgen::READLINK3args*>(nullptr),
                                static_cast<const struct rpcgen::READLINK3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3ReadOpsAmount; ++i)
        {
            analyzer->read3(static_cast<const struct RPCProcedure*>(nullptr),
                            static_cast<const struct rpcgen::READ3args*>(nullptr),
                            static_cast<const struct rpcgen::READ3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3WriteOpsAmount; ++i)
        {
            analyzer->write3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct rpcgen::WRITE3args*>(nullptr),
                             static_cast<const struct rpcgen::WRITE3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3CreateOpsAmount; ++i)
        {
            analyzer->create3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::CREATE3args*>(nullptr),
                              static_cast<const struct rpcgen::CREATE3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3MkdirOpsAmount; ++i)
        {
            analyzer->mkdir3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct rpcgen::MKDIR3args*>(nullptr),
                             static_cast<const struct rpcgen::MKDIR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3SymlinkOpsAmount; ++i)
        {
            analyzer->symlink3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct rpcgen::SYMLINK3args*>(nullptr),
                               static_cast<const struct rpcgen::SYMLINK3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3MknodOpsAmount; ++i)
        {
            analyzer->mknod3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct rpcgen::MKNOD3args*>(nullptr),
                             static_cast<const struct rpcgen::MKNOD3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3RemoveOpsAmount; ++i)
        {
            analyzer->remove3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::REMOVE3args*>(nullptr),
                              static_cast<const struct rpcgen::REMOVE3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3RmdirOpsAmount; ++i)
        {
            analyzer->rmdir3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct rpcgen::RMDIR3args*>(nullptr),
                             static_cast<const struct rpcgen::RMDIR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3RenameOpsAmount; ++i)
        {
            analyzer->rename3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::RENAME3args*>(nullptr),
                              static_cast<const struct rpcgen::RENAME3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3LinkOpsAmount; ++i)
        {
            analyzer->link3(static_cast<const struct RPCProcedure*>(nullptr),
                            static_cast<const struct rpcgen::LINK3args*>(nullptr),
                            static_cast<const struct rpcgen::LINK3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3ReaddirOpsAmount; ++i)
        {
            analyzer->readdir3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct rpcgen::READDIR3args*>(nullptr),
                               static_cast<const struct rpcgen::READDIR3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3ReaddirplusOpsAmount; ++i)
        {
            analyzer->readdirplus3(static_cast<const struct RPCProcedure*>(nullptr),
                                   static_cast<const struct rpcgen::READDIRPLUS3args*>(nullptr),
                                   static_cast<const struct rpcgen::READDIRPLUS3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3FsstatOpsAmount; ++i)
        {
            analyzer->fsstat3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::FSSTAT3args*>(nullptr),
                              static_cast<const struct rpcgen::FSSTAT3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3FsinfoOpsAmount; ++i)
        {
            analyzer->fsinfo3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::FSINFO3args*>(nullptr),
                              static_cast<const struct rpcgen::FSINFO3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3PathconfOpsAmount; ++i)
        {
            analyzer->pathconf3(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct rpcgen::PATHCONF3args*>(nullptr),
                                static_cast<const struct rpcgen::PATHCONF3res*>(nullptr));
        }
        for (int i = 0; i < NfsV3CommitOpsAmount; ++i)
        {
            analyzer->commit3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::COMMIT3args*>(nullptr),
                              static_cast<const struct rpcgen::COMMIT3res*>(nullptr));
        }
        // Setting up analyzer (NFSv4)
        for (int i = 0; i < NfsV4NullOpsAmount; ++i)
        {
            analyzer->null(static_cast<const struct RPCProcedure*>(nullptr),
                           static_cast<const struct rpcgen::NULL4args*>(nullptr),
                           static_cast<const struct rpcgen::NULL4res*>(nullptr));
        }
        for (int i = 0; i < NfsV4CompoundOpsAmount; ++i)
        {
            analyzer->compound4(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct rpcgen::COMPOUND4args*>(nullptr),
                                static_cast<const struct rpcgen::COMPOUND4res*>(nullptr));
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
    EXPECT_EQ(NfsV3NullOpsAmount, analyzer->getNfsV3Stat().nullOpsAmount.load());
    EXPECT_EQ(NfsV3GetattrOpsAmount, analyzer->getNfsV3Stat().getattrOpsAmount.load());
    EXPECT_EQ(NfsV3SetattrOpsAmount, analyzer->getNfsV3Stat().setattrOpsAmount.load());
    EXPECT_EQ(NfsV3AccessOpsAmount, analyzer->getNfsV3Stat().accessOpsAmount.load());
    EXPECT_EQ(NfsV3ReadlinkOpsAmount, analyzer->getNfsV3Stat().readlinkOpsAmount.load());
    EXPECT_EQ(NfsV3ReadOpsAmount, analyzer->getNfsV3Stat().readOpsAmount.load());
    EXPECT_EQ(NfsV3WriteOpsAmount, analyzer->getNfsV3Stat().writeOpsAmount.load());
    EXPECT_EQ(NfsV3CreateOpsAmount, analyzer->getNfsV3Stat().createOpsAmount.load());
    EXPECT_EQ(NfsV3MkdirOpsAmount, analyzer->getNfsV3Stat().mkdirOpsAmount.load());
    EXPECT_EQ(NfsV3SymlinkOpsAmount, analyzer->getNfsV3Stat().symlinkOpsAmount.load());
    EXPECT_EQ(NfsV3MknodOpsAmount, analyzer->getNfsV3Stat().mknodOpsAmount.load());
    EXPECT_EQ(NfsV3RemoveOpsAmount, analyzer->getNfsV3Stat().removeOpsAmount.load());
    EXPECT_EQ(NfsV3RmdirOpsAmount, analyzer->getNfsV3Stat().rmdirOpsAmount.load());
    EXPECT_EQ(NfsV3RenameOpsAmount, analyzer->getNfsV3Stat().renameOpsAmount.load());
    EXPECT_EQ(NfsV3LinkOpsAmount, analyzer->getNfsV3Stat().linkOpsAmount.load());
    EXPECT_EQ(NfsV3ReaddirOpsAmount, analyzer->getNfsV3Stat().readdirOpsAmount.load());
    EXPECT_EQ(NfsV3ReaddirplusOpsAmount, analyzer->getNfsV3Stat().readdirplusOpsAmount.load());
    EXPECT_EQ(NfsV3FsstatOpsAmount, analyzer->getNfsV3Stat().fsstatOpsAmount.load());
    EXPECT_EQ(NfsV3FsinfoOpsAmount, analyzer->getNfsV3Stat().fsinfoOpsAmount.load());
    EXPECT_EQ(NfsV3PathconfOpsAmount, analyzer->getNfsV3Stat().pathconfOpsAmount.load());
    EXPECT_EQ(NfsV3CommitOpsAmount, analyzer->getNfsV3Stat().commitOpsAmount.load());

    EXPECT_EQ(NfsV4NullOpsAmount, analyzer->getNfsV4Stat().nullOpsAmount.load());
    EXPECT_EQ(NfsV4CompoundOpsAmount, analyzer->getNfsV4Stat().compoundOpsAmount.load());
}

TEST_F(JsonAnalyzerCase, requestResponse)
{
    // Connecting to service
    int s = socket(PF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    TcpEndpoint endpoint{ListenHost, ListenPort};
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
    EXPECT_EQ(NfsV3NullOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "getattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3GetattrOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "setattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3SetattrOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "lookup", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3LookupOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "access", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3AccessOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "readlink", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3ReadlinkOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "read", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3ReadOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "write", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3WriteOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "create", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3CreateOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "mkdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3MkdirOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "symlink", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3SymlinkOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "mkdnod", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3MknodOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "remove", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3RemoveOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "rmdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3RmdirOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "rename", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3RenameOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "link", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3LinkOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "readdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3ReaddirOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "readdirplus", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3ReaddirplusOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "fsstat", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3FsstatOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "fsinfo", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3FsinfoOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "pathconf", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3PathconfOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "commit", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV3CommitOpsAmount, json_object_get_int64(val));

    // Checking NFSv4 statistics
    struct json_object* nfsV4Stat;
    EXPECT_TRUE(json_object_object_get_ex(root, "nfs_v4", &nfsV4Stat));
    EXPECT_NE(nullptr, nfsV4Stat);

    EXPECT_TRUE(json_object_object_get_ex(nfsV4Stat, "null", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV4NullOpsAmount, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV4Stat, "compound", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NfsV4CompoundOpsAmount, json_object_get_int64(val));

    // Collecting garbage
    json_object_put(root);
    EXPECT_EQ(0, close(s));
}

TEST_F(JsonAnalyzerCase, slowClient)
{
    int s = socket(PF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    TcpEndpoint endpoint{ListenHost, ListenPort};
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
