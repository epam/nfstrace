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

#define AWAIT_FOR_SERVICE_STARTUP_MS 250
#define WORKERS_AMOUNT 100
#define LISTEN_PORT 8888
#define LISTEN_HOST NST::net::TcpEndpoint::LoopbackAddress
#define MAX_SERVING_DURATION_MS 200
#define LISTEN_BACKLOG 15
#define RECEIVE_BUFFER_SIZE 4096
#define SLOW_CLIENT_TIMEOUT_MS 300

#define NFSV3_NULL_OPS_AMOUNT 25
#define NFSV3_GETATTR_OPS_AMOUNT 35
#define NFSV3_SETATTR_OPS_AMOUNT 80
#define NFSV3_LOOKUP_OPS_AMOUNT 76
#define NFSV3_ACCESS_OPS_AMOUNT 42
#define NFSV3_READLINK_OPS_AMOUNT 24
#define NFSV3_READ_OPS_AMOUNT 56
#define NFSV3_WRITE_OPS_AMOUNT 152
#define NFSV3_CREATE_OPS_AMOUNT 31
#define NFSV3_MKDIR_OPS_AMOUNT 97
#define NFSV3_SYMLINK_OPS_AMOUNT 69
#define NFSV3_MKNOD_OPS_AMOUNT 73
#define NFSV3_REMOVE_OPS_AMOUNT 36
#define NFSV3_RMDIR_OPS_AMOUNT 27
#define NFSV3_RENAME_OPS_AMOUNT 59
#define NFSV3_LINK_OPS_AMOUNT 28
#define NFSV3_READDIR_OPS_AMOUNT 83
#define NFSV3_READDIRPLUS_OPS_AMOUNT 74
#define NFSV3_FSSTAT_OPS_AMOUNT 95
#define NFSV3_FSINFO_OPS_AMOUNT 57
#define NFSV3_PATHCONF_OPS_AMOUNT 26
#define NFSV3_COMMIT_OPS_AMOUNT 79

#define NFSV4_NULL_OPS_AMOUNT 81
#define NFSV4_COMPOUND_OPS_AMOUNT 18

#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <json.h>

#include "json_analyzer.h"

class JsonAnalyzerCase : public ::testing::Test
{
protected:
    virtual void SetUp() override final
    {
        // Starting service
        analyzer.reset(new JsonAnalyzer(WORKERS_AMOUNT, LISTEN_PORT, LISTEN_HOST, MAX_SERVING_DURATION_MS, LISTEN_BACKLOG));
        std::this_thread::sleep_for(std::chrono::milliseconds(AWAIT_FOR_SERVICE_STARTUP_MS));
        // Setting up analyzer (NFSv3)
        for (int i = 0; i < NFSV3_NULL_OPS_AMOUNT; ++i)
        {
            analyzer->null(static_cast<const struct RPCProcedure*>(nullptr),
                           static_cast<const struct rpcgen::NULL3args*>(nullptr),
                           static_cast<const struct rpcgen::NULL3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_GETATTR_OPS_AMOUNT; ++i)
        {
            analyzer->getattr3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct rpcgen::GETATTR3args*>(nullptr),
                               static_cast<const struct rpcgen::GETATTR3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_SETATTR_OPS_AMOUNT; ++i)
        {
            analyzer->setattr3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct rpcgen::SETATTR3args*>(nullptr),
                               static_cast<const struct rpcgen::SETATTR3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_LOOKUP_OPS_AMOUNT; ++i)
        {
            analyzer->lookup3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::LOOKUP3args*>(nullptr),
                              static_cast<const struct rpcgen::LOOKUP3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_ACCESS_OPS_AMOUNT; ++i)
        {
            analyzer->access3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::ACCESS3args*>(nullptr),
                              static_cast<const struct rpcgen::ACCESS3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_READLINK_OPS_AMOUNT; ++i)
        {
            analyzer->readlink3(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct rpcgen::READLINK3args*>(nullptr),
                                static_cast<const struct rpcgen::READLINK3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_READ_OPS_AMOUNT; ++i)
        {
            analyzer->read3(static_cast<const struct RPCProcedure*>(nullptr),
                            static_cast<const struct rpcgen::READ3args*>(nullptr),
                            static_cast<const struct rpcgen::READ3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_WRITE_OPS_AMOUNT; ++i)
        {
            analyzer->write3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct rpcgen::WRITE3args*>(nullptr),
                             static_cast<const struct rpcgen::WRITE3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_CREATE_OPS_AMOUNT; ++i)
        {
            analyzer->create3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::CREATE3args*>(nullptr),
                              static_cast<const struct rpcgen::CREATE3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_MKDIR_OPS_AMOUNT; ++i)
        {
            analyzer->mkdir3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct rpcgen::MKDIR3args*>(nullptr),
                             static_cast<const struct rpcgen::MKDIR3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_SYMLINK_OPS_AMOUNT; ++i)
        {
            analyzer->symlink3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct rpcgen::SYMLINK3args*>(nullptr),
                               static_cast<const struct rpcgen::SYMLINK3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_MKNOD_OPS_AMOUNT; ++i)
        {
            analyzer->mknod3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct rpcgen::MKNOD3args*>(nullptr),
                             static_cast<const struct rpcgen::MKNOD3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_REMOVE_OPS_AMOUNT; ++i)
        {
            analyzer->remove3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::REMOVE3args*>(nullptr),
                              static_cast<const struct rpcgen::REMOVE3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_RMDIR_OPS_AMOUNT; ++i)
        {
            analyzer->rmdir3(static_cast<const struct RPCProcedure*>(nullptr),
                             static_cast<const struct rpcgen::RMDIR3args*>(nullptr),
                             static_cast<const struct rpcgen::RMDIR3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_RENAME_OPS_AMOUNT; ++i)
        {
            analyzer->rename3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::RENAME3args*>(nullptr),
                              static_cast<const struct rpcgen::RENAME3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_LINK_OPS_AMOUNT; ++i)
        {
            analyzer->link3(static_cast<const struct RPCProcedure*>(nullptr),
                            static_cast<const struct rpcgen::LINK3args*>(nullptr),
                            static_cast<const struct rpcgen::LINK3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_READDIR_OPS_AMOUNT; ++i)
        {
            analyzer->readdir3(static_cast<const struct RPCProcedure*>(nullptr),
                               static_cast<const struct rpcgen::READDIR3args*>(nullptr),
                               static_cast<const struct rpcgen::READDIR3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_READDIRPLUS_OPS_AMOUNT; ++i)
        {
            analyzer->readdirplus3(static_cast<const struct RPCProcedure*>(nullptr),
                                   static_cast<const struct rpcgen::READDIRPLUS3args*>(nullptr),
                                   static_cast<const struct rpcgen::READDIRPLUS3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_FSSTAT_OPS_AMOUNT; ++i)
        {
            analyzer->fsstat3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::FSSTAT3args*>(nullptr),
                              static_cast<const struct rpcgen::FSSTAT3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_FSINFO_OPS_AMOUNT; ++i)
        {
            analyzer->fsinfo3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::FSINFO3args*>(nullptr),
                              static_cast<const struct rpcgen::FSINFO3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_PATHCONF_OPS_AMOUNT; ++i)
        {
            analyzer->pathconf3(static_cast<const struct RPCProcedure*>(nullptr),
                                static_cast<const struct rpcgen::PATHCONF3args*>(nullptr),
                                static_cast<const struct rpcgen::PATHCONF3res*>(nullptr));
        }
        for (int i = 0; i < NFSV3_COMMIT_OPS_AMOUNT; ++i)
        {
            analyzer->commit3(static_cast<const struct RPCProcedure*>(nullptr),
                              static_cast<const struct rpcgen::COMMIT3args*>(nullptr),
                              static_cast<const struct rpcgen::COMMIT3res*>(nullptr));
        }
        // Setting up analyzer (NFSv4)
        for (int i = 0; i < NFSV4_NULL_OPS_AMOUNT; ++i)
        {
            analyzer->null(static_cast<const struct RPCProcedure*>(nullptr),
                           static_cast<const struct rpcgen::NULL4args*>(nullptr),
                           static_cast<const struct rpcgen::NULL4res*>(nullptr));
        }
        for (int i = 0; i < NFSV4_COMPOUND_OPS_AMOUNT; ++i)
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
    EXPECT_EQ(NFSV3_NULL_OPS_AMOUNT, analyzer->getNfsV3Stat().nullOpsAmount.load());
    EXPECT_EQ(NFSV3_GETATTR_OPS_AMOUNT, analyzer->getNfsV3Stat().getattrOpsAmount.load());
    EXPECT_EQ(NFSV3_SETATTR_OPS_AMOUNT, analyzer->getNfsV3Stat().setattrOpsAmount.load());
    EXPECT_EQ(NFSV3_ACCESS_OPS_AMOUNT, analyzer->getNfsV3Stat().accessOpsAmount.load());
    EXPECT_EQ(NFSV3_READLINK_OPS_AMOUNT, analyzer->getNfsV3Stat().readlinkOpsAmount.load());
    EXPECT_EQ(NFSV3_READ_OPS_AMOUNT, analyzer->getNfsV3Stat().readOpsAmount.load());
    EXPECT_EQ(NFSV3_WRITE_OPS_AMOUNT, analyzer->getNfsV3Stat().writeOpsAmount.load());
    EXPECT_EQ(NFSV3_CREATE_OPS_AMOUNT, analyzer->getNfsV3Stat().createOpsAmount.load());
    EXPECT_EQ(NFSV3_MKDIR_OPS_AMOUNT, analyzer->getNfsV3Stat().mkdirOpsAmount.load());
    EXPECT_EQ(NFSV3_SYMLINK_OPS_AMOUNT, analyzer->getNfsV3Stat().symlinkOpsAmount.load());
    EXPECT_EQ(NFSV3_MKNOD_OPS_AMOUNT, analyzer->getNfsV3Stat().mknodOpsAmount.load());
    EXPECT_EQ(NFSV3_REMOVE_OPS_AMOUNT, analyzer->getNfsV3Stat().removeOpsAmount.load());
    EXPECT_EQ(NFSV3_RMDIR_OPS_AMOUNT, analyzer->getNfsV3Stat().rmdirOpsAmount.load());
    EXPECT_EQ(NFSV3_RENAME_OPS_AMOUNT, analyzer->getNfsV3Stat().renameOpsAmount.load());
    EXPECT_EQ(NFSV3_LINK_OPS_AMOUNT, analyzer->getNfsV3Stat().linkOpsAmount.load());
    EXPECT_EQ(NFSV3_READDIR_OPS_AMOUNT, analyzer->getNfsV3Stat().readdirOpsAmount.load());
    EXPECT_EQ(NFSV3_READDIRPLUS_OPS_AMOUNT, analyzer->getNfsV3Stat().readdirplusOpsAmount.load());
    EXPECT_EQ(NFSV3_FSSTAT_OPS_AMOUNT, analyzer->getNfsV3Stat().fsstatOpsAmount.load());
    EXPECT_EQ(NFSV3_FSINFO_OPS_AMOUNT, analyzer->getNfsV3Stat().fsinfoOpsAmount.load());
    EXPECT_EQ(NFSV3_PATHCONF_OPS_AMOUNT, analyzer->getNfsV3Stat().pathconfOpsAmount.load());
    EXPECT_EQ(NFSV3_COMMIT_OPS_AMOUNT, analyzer->getNfsV3Stat().commitOpsAmount.load());

    EXPECT_EQ(NFSV4_NULL_OPS_AMOUNT, analyzer->getNfsV4Stat().nullOpsAmount.load());
    EXPECT_EQ(NFSV4_COMPOUND_OPS_AMOUNT, analyzer->getNfsV4Stat().compoundOpsAmount.load());
}

TEST_F(JsonAnalyzerCase, requestResponse)
{
    // Connecting to service
    int s = socket(PF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    TcpEndpoint endpoint(LISTEN_HOST, LISTEN_PORT);
    ASSERT_EQ(0, connect(s, endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen));
    char receiveBuffer[RECEIVE_BUFFER_SIZE];
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
    EXPECT_EQ(NFSV3_NULL_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "getattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_GETATTR_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "setattr", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_SETATTR_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "lookup", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_LOOKUP_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "access", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_ACCESS_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "readlink", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_READLINK_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "read", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_READ_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "write", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_WRITE_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "create", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_CREATE_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "mkdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_MKDIR_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "symlink", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_SYMLINK_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "mkdnod", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_MKNOD_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "remove", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_REMOVE_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "rmdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_RMDIR_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "rename", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_RENAME_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "link", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_LINK_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "readdir", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_READDIR_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "readdirplus", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_READDIRPLUS_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "fsstat", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_FSSTAT_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "fsinfo", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_FSINFO_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "pathconf", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_PATHCONF_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV3Stat, "commit", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV3_COMMIT_OPS_AMOUNT, json_object_get_int64(val));

    // Checking NFSv4 statistics
    struct json_object* nfsV4Stat;
    EXPECT_TRUE(json_object_object_get_ex(root, "nfs_v4", &nfsV4Stat));
    EXPECT_NE(nullptr, nfsV4Stat);

    EXPECT_TRUE(json_object_object_get_ex(nfsV4Stat, "null", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV4_NULL_OPS_AMOUNT, json_object_get_int64(val));

    EXPECT_TRUE(json_object_object_get_ex(nfsV4Stat, "compound", &val));
    EXPECT_NE(nullptr, val);
    EXPECT_EQ(json_type_int, json_object_get_type(val));
    EXPECT_EQ(NFSV4_COMPOUND_OPS_AMOUNT, json_object_get_int64(val));

    // Collecting garbage
    json_object_put(root);
    EXPECT_EQ(0, close(s));
}

TEST_F(JsonAnalyzerCase, slowClient)
{
    int s = socket(PF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    TcpEndpoint endpoint(LISTEN_HOST, LISTEN_PORT);
    ASSERT_EQ(0, connect(s, endpoint.addrinfo()->ai_addr, endpoint.addrinfo()->ai_addrlen));
    std::this_thread::sleep_for(std::chrono::milliseconds(SLOW_CLIENT_TIMEOUT_MS));
    char receiveBuffer[RECEIVE_BUFFER_SIZE];
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
