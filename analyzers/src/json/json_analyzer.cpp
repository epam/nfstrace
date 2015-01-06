//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: JSON analyzer class definition
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
#include "json_analyzer.h"
//------------------------------------------------------------------------------

JsonAnalyzer::JsonAnalyzer(std::size_t workersAmount, int port, const std::string& host, std::size_t maxServingDurationMs, int backlog) :
    _jsonTcpService{*this, workersAmount, port, host, maxServingDurationMs, backlog},
    _nfsV3Stat{},
    _nfsV4Stat{}
{
    _jsonTcpService.start();
}

JsonAnalyzer::~JsonAnalyzer()
{
    _jsonTcpService.stop();
}

void JsonAnalyzer::null(const struct RPCProcedure* /*proc*/,
                        const struct NFS3::NULL3args* /*args*/,
                        const struct NFS3::NULL3res* /*res*/)
{
    _nfsV3Stat.nullOpsAmount++;
}

void JsonAnalyzer::getattr3(const struct RPCProcedure* /*proc*/,
                            const struct NFS3::GETATTR3args* /*args*/,
                            const struct NFS3::GETATTR3res* /*res*/)
{
    _nfsV3Stat.getattrOpsAmount++;
}

void JsonAnalyzer::setattr3(const struct RPCProcedure* /*proc*/,
                            const struct NFS3::SETATTR3args* /*args*/,
                            const struct NFS3::SETATTR3res* /*res*/)
{
    _nfsV3Stat.setattrOpsAmount++;
}

void JsonAnalyzer::lookup3(const struct RPCProcedure* /*proc*/,
                           const struct NFS3::LOOKUP3args* /*args*/,
                           const struct NFS3::LOOKUP3res* /*res*/)
{
    _nfsV3Stat.lookupOpsAmount++;
}

void JsonAnalyzer::access3(const struct RPCProcedure* /*proc*/,
                           const struct NFS3::ACCESS3args* /*args*/,
                           const struct NFS3::ACCESS3res* /*res*/)
{
    _nfsV3Stat.accessOpsAmount++;
}

void JsonAnalyzer::readlink3(const struct RPCProcedure* /*proc*/,
                             const struct NFS3::READLINK3args* /*args*/,
                             const struct NFS3::READLINK3res* /*res*/)
{
    _nfsV3Stat.readlinkOpsAmount++;
}

void JsonAnalyzer::read3(const struct RPCProcedure* /*proc*/,
                         const struct NFS3::READ3args* /*args*/,
                         const struct NFS3::READ3res* /*res*/)
{
    _nfsV3Stat.readOpsAmount++;
}

void JsonAnalyzer::write3(const struct RPCProcedure* /*proc*/,
                          const struct NFS3::WRITE3args* /*args*/,
                          const struct NFS3::WRITE3res* /*res*/)
{
    _nfsV3Stat.writeOpsAmount++;
}

void JsonAnalyzer::create3(const struct RPCProcedure* /*proc*/,
                           const struct NFS3::CREATE3args* /*args*/,
                           const struct NFS3::CREATE3res* /*res*/)
{
    _nfsV3Stat.createOpsAmount++;
}

void JsonAnalyzer::mkdir3(const struct RPCProcedure* /*proc*/,
                          const struct NFS3::MKDIR3args* /*args*/,
                          const struct NFS3::MKDIR3res* /*res*/)
{
    _nfsV3Stat.mkdirOpsAmount++;
}

void JsonAnalyzer::symlink3(const struct RPCProcedure* /*proc*/,
                            const struct NFS3::SYMLINK3args* /*args*/,
                            const struct NFS3::SYMLINK3res* /*res*/)
{
    _nfsV3Stat.symlinkOpsAmount++;
}

void JsonAnalyzer::mknod3(const struct RPCProcedure* /*proc*/,
                          const struct NFS3::MKNOD3args* /*args*/,
                          const struct NFS3::MKNOD3res* /*res*/)
{
    _nfsV3Stat.mknodOpsAmount++;
}

void JsonAnalyzer::remove3(const struct RPCProcedure* /*proc*/,
                           const struct NFS3::REMOVE3args* /*args*/,
                           const struct NFS3::REMOVE3res* /*res*/)
{
    _nfsV3Stat.removeOpsAmount++;
}

void JsonAnalyzer::rmdir3(const struct RPCProcedure* /*proc*/,
                          const struct NFS3::RMDIR3args* /*args*/,
                          const struct NFS3::RMDIR3res* /*res*/)
{
    _nfsV3Stat.rmdirOpsAmount++;
}

void JsonAnalyzer::rename3(const struct RPCProcedure* /*proc*/,
                           const struct NFS3::RENAME3args* /*args*/,
                           const struct NFS3::RENAME3res* /*res*/)
{
    _nfsV3Stat.renameOpsAmount++;
}

void JsonAnalyzer::link3(const struct RPCProcedure* /*proc*/,
                         const struct NFS3::LINK3args* /*args*/,
                         const struct NFS3::LINK3res* /*res*/)
{
    _nfsV3Stat.linkOpsAmount++;
}

void JsonAnalyzer::readdir3(const struct RPCProcedure* /*proc*/,
                            const struct NFS3::READDIR3args* /*args*/,
                            const struct NFS3::READDIR3res* /*res*/)
{
    _nfsV3Stat.readdirOpsAmount++;
}

void JsonAnalyzer::readdirplus3(const struct RPCProcedure* /*proc*/,
                                const struct NFS3::READDIRPLUS3args* /*args*/,
                                const struct NFS3::READDIRPLUS3res* /*res*/)
{
    _nfsV3Stat.readdirplusOpsAmount++;
}

void JsonAnalyzer::fsstat3(const struct RPCProcedure* /*proc*/,
                           const struct NFS3::FSSTAT3args* /*args*/,
                           const struct NFS3::FSSTAT3res* /*res*/)
{
    _nfsV3Stat.fsstatOpsAmount++;
}

void JsonAnalyzer::fsinfo3(const struct RPCProcedure* /*proc*/,
                           const struct NFS3::FSINFO3args* /*args*/,
                           const struct NFS3::FSINFO3res* /*res*/)
{
    _nfsV3Stat.fsinfoOpsAmount++;
}

void JsonAnalyzer::pathconf3(const struct RPCProcedure* /*proc*/,
                             const struct NFS3::PATHCONF3args* /*args*/,
                             const struct NFS3::PATHCONF3res* /*res*/)
{
    _nfsV3Stat.pathconfOpsAmount++;
}

void JsonAnalyzer::commit3(const struct RPCProcedure* /*proc*/,
                           const struct NFS3::COMMIT3args* /*args*/,
                           const struct NFS3::COMMIT3res* /*res*/)
{
    _nfsV3Stat.commitOpsAmount++;
}

void JsonAnalyzer::null(const struct RPCProcedure* /*proc*/,
                        const struct NFS4::NULL4args* /*args*/,
                        const struct NFS4::NULL4res* /*res*/)
{
    _nfsV4Stat.nullOpsAmount++;
}
void JsonAnalyzer::compound4(const struct RPCProcedure* /*proc*/,
                             const struct NFS4::COMPOUND4args* /*args*/,
                             const struct NFS4::COMPOUND4res* /*res*/)
{
    _nfsV4Stat.compoundOpsAmount++;
}

void JsonAnalyzer::flush_statistics()
{
}
//------------------------------------------------------------------------------
