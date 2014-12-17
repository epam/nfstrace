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
        std::atomic_int nullOpsAmount;
        std::atomic_int getattrOpsAmount;
        std::atomic_int setattrOpsAmount;
        std::atomic_int lookupOpsAmount;
        std::atomic_int accessOpsAmount;
        std::atomic_int readlinkOpsAmount;
        std::atomic_int readOpsAmount;
        std::atomic_int writeOpsAmount;
        std::atomic_int createOpsAmount;
        std::atomic_int mkdirOpsAmount;
        std::atomic_int symlinkOpsAmount;
        std::atomic_int mknodOpsAmount;
        std::atomic_int removeOpsAmount;
        std::atomic_int rmdirOpsAmount;
        std::atomic_int renameOpsAmount;
        std::atomic_int linkOpsAmount;
        std::atomic_int readdirOpsAmount;
        std::atomic_int readdirplusOpsAmount;
        std::atomic_int fsstatOpsAmount;
        std::atomic_int fsinfoOpsAmount;
        std::atomic_int pathconfOpsAmount;
        std::atomic_int commitOpsAmount;

        NfsV3Stat() :
            nullOpsAmount(0),
            getattrOpsAmount(0),
            setattrOpsAmount(0),
            lookupOpsAmount(0),
            accessOpsAmount(0),
            readlinkOpsAmount(0),
            readOpsAmount(0),
            writeOpsAmount(0),
            createOpsAmount(0),
            mkdirOpsAmount(0),
            symlinkOpsAmount(0),
            mknodOpsAmount(0),
            removeOpsAmount(0),
            rmdirOpsAmount(0),
            renameOpsAmount(0),
            linkOpsAmount(0),
            readdirOpsAmount(0),
            readdirplusOpsAmount(0),
            fsstatOpsAmount(0),
            fsinfoOpsAmount(0),
            pathconfOpsAmount(0),
            commitOpsAmount(0)
        {}
    };
    struct NfsV4Stat
    {
        std::atomic_int nullOpsAmount;
        std::atomic_int compoundOpsAmount;

        NfsV4Stat() :
            nullOpsAmount(0),
            compoundOpsAmount(0)
        {}
    };

    JsonAnalyzer(std::size_t workersAmount, int port, const std::string& host, std::size_t maxServingDurationMs, int backlog);

    void null(const struct RPCProcedure* /*proc*/,
              const struct rpcgen::NULL3args* /*args*/,
              const struct rpcgen::NULL3res* /*res*/) override final;

    void getattr3(const struct RPCProcedure* /*proc*/,
                  const struct rpcgen::GETATTR3args* /*args*/,
                  const struct rpcgen::GETATTR3res* /*res*/) override final;

    void setattr3(const struct RPCProcedure* /*proc*/,
                  const struct rpcgen::SETATTR3args* /*args*/,
                  const struct rpcgen::SETATTR3res* /*res*/) override final;

    void lookup3(const struct RPCProcedure* /*proc*/,
                 const struct rpcgen::LOOKUP3args* /*args*/,
                 const struct rpcgen::LOOKUP3res* /*res*/) override final;

    void access3(const struct RPCProcedure* /*proc*/,
                 const struct rpcgen::ACCESS3args* /*args*/,
                 const struct rpcgen::ACCESS3res* /*res*/) override final;

    void readlink3(const struct RPCProcedure* /*proc*/,
                   const struct rpcgen::READLINK3args* /*args*/,
                   const struct rpcgen::READLINK3res* /*res*/) override final;

    void read3(const struct RPCProcedure* /*proc*/,
               const struct rpcgen::READ3args* /*args*/,
               const struct rpcgen::READ3res* /*res*/) override final;

    void write3(const struct RPCProcedure* /*proc*/,
                const struct rpcgen::WRITE3args* /*args*/,
                const struct rpcgen::WRITE3res* /*res*/) override final;

    void create3(const struct RPCProcedure* /*proc*/,
                 const struct rpcgen::CREATE3args* /*args*/,
                 const struct rpcgen::CREATE3res* /*res*/) override final;

    void mkdir3(const struct RPCProcedure* /*proc*/,
                const struct rpcgen::MKDIR3args* /*args*/,
                const struct rpcgen::MKDIR3res* /*res*/) override final;

    void symlink3(const struct RPCProcedure* /*proc*/,
                  const struct rpcgen::SYMLINK3args* /*args*/,
                  const struct rpcgen::SYMLINK3res* /*res*/) override final;

    void mknod3(const struct RPCProcedure* /*proc*/,
                const struct rpcgen::MKNOD3args* /*args*/,
                const struct rpcgen::MKNOD3res* /*res*/) override final;

    void remove3(const struct RPCProcedure* /*proc*/,
                 const struct rpcgen::REMOVE3args* /*args*/,
                 const struct rpcgen::REMOVE3res* /*res*/) override final;

    void rmdir3(const struct RPCProcedure* /*proc*/,
                const struct rpcgen::RMDIR3args* /*args*/,
                const struct rpcgen::RMDIR3res* /*res*/) override final;

    void rename3(const struct RPCProcedure* /*proc*/,
                 const struct rpcgen::RENAME3args* /*args*/,
                 const struct rpcgen::RENAME3res* /*res*/) override final;

    void link3(const struct RPCProcedure* /*proc*/,
               const struct rpcgen::LINK3args* /*args*/,
               const struct rpcgen::LINK3res* /*res*/) override final;

    void readdir3(const struct RPCProcedure* /*proc*/,
                  const struct rpcgen::READDIR3args* /*args*/,
                  const struct rpcgen::READDIR3res* /*res*/) override final;

    void readdirplus3(const struct RPCProcedure* /*proc*/,
                      const struct rpcgen::READDIRPLUS3args* /*args*/,
                      const struct rpcgen::READDIRPLUS3res* /*res*/) override final;

    void fsstat3(const struct RPCProcedure* /*proc*/,
                 const struct rpcgen::FSSTAT3args* /*args*/,
                 const struct rpcgen::FSSTAT3res* /*res*/) override final;

    void fsinfo3(const struct RPCProcedure* /*proc*/,
                 const struct rpcgen::FSINFO3args* /*args*/,
                 const struct rpcgen::FSINFO3res* /*res*/) override final;

    void pathconf3(const struct RPCProcedure* /*proc*/,
                   const struct rpcgen::PATHCONF3args* /*args*/,
                   const struct rpcgen::PATHCONF3res* /*res*/) override final;

    void commit3(const struct RPCProcedure* /*proc*/,
                 const struct rpcgen::COMMIT3args* /*args*/,
                 const struct rpcgen::COMMIT3res* /*res*/) override final;

    void null(const struct RPCProcedure* /*proc*/,
              const struct rpcgen::NULL4args* /*args*/,
              const struct rpcgen::NULL4res* /*res*/) override final;

    void compound4(const struct RPCProcedure* /*proc*/,
                   const struct rpcgen::COMPOUND4args* /*args*/,
                   const struct rpcgen::COMPOUND4res* /*res*/) override final;

    void flush_statistics() override final;

    inline const NfsV3Stat& getNfsV3Stat() const
    {
        return _nfsV3Stat;
    }

    inline const NfsV4Stat& getNfsV4Stat() const
    {
        return _nfsV4Stat;
    }
private:
    JsonTcpService _jsonTcpService;
    NfsV3Stat _nfsV3Stat;
    NfsV4Stat _nfsV4Stat;
};
//------------------------------------------------------------------------------
#endif // JSON_ANALYZER_H
//------------------------------------------------------------------------------
