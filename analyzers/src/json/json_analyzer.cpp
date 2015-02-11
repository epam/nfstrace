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
    _nfsV40Stat{},
    _nfsV41Stat{}
{
    _jsonTcpService.start();
}

JsonAnalyzer::~JsonAnalyzer()
{
    _jsonTcpService.stop();
}

// NFS3
// Procedures: 

void JsonAnalyzer::null(const RPCProcedure* /*proc*/,
                        const struct NFS3::NULL3args* /*args*/,
                        const struct NFS3::NULL3res* /*res*/)
{
    _nfsV3Stat.nullProcsAmount++;
}

void JsonAnalyzer::getattr3(const RPCProcedure* /*proc*/,
                            const struct NFS3::GETATTR3args* /*args*/,
                            const struct NFS3::GETATTR3res* /*res*/)
{
    _nfsV3Stat.getattrProcsAmount++;
}

void JsonAnalyzer::setattr3(const RPCProcedure* /*proc*/,
                            const struct NFS3::SETATTR3args* /*args*/,
                            const struct NFS3::SETATTR3res* /*res*/)
{
    _nfsV3Stat.setattrProcsAmount++;
}

void JsonAnalyzer::lookup3(const RPCProcedure* /*proc*/,
                           const struct NFS3::LOOKUP3args* /*args*/,
                           const struct NFS3::LOOKUP3res* /*res*/)
{
    _nfsV3Stat.lookupProcsAmount++;
}

void JsonAnalyzer::access3(const RPCProcedure* /*proc*/,
                           const struct NFS3::ACCESS3args* /*args*/,
                           const struct NFS3::ACCESS3res* /*res*/)
{
    _nfsV3Stat.accessProcsAmount++;
}

void JsonAnalyzer::readlink3(const RPCProcedure* /*proc*/,
                             const struct NFS3::READLINK3args* /*args*/,
                             const struct NFS3::READLINK3res* /*res*/)
{
    _nfsV3Stat.readlinkProcsAmount++;
}

void JsonAnalyzer::read3(const RPCProcedure* /*proc*/,
                         const struct NFS3::READ3args* /*args*/,
                         const struct NFS3::READ3res* /*res*/)
{
    _nfsV3Stat.readProcsAmount++;
}

void JsonAnalyzer::write3(const RPCProcedure* /*proc*/,
                          const struct NFS3::WRITE3args* /*args*/,
                          const struct NFS3::WRITE3res* /*res*/)
{
    _nfsV3Stat.writeProcsAmount++;
}

void JsonAnalyzer::create3(const RPCProcedure* /*proc*/,
                           const struct NFS3::CREATE3args* /*args*/,
                           const struct NFS3::CREATE3res* /*res*/)
{
    _nfsV3Stat.createProcsAmount++;
}

void JsonAnalyzer::mkdir3(const RPCProcedure* /*proc*/,
                          const struct NFS3::MKDIR3args* /*args*/,
                          const struct NFS3::MKDIR3res* /*res*/)
{
    _nfsV3Stat.mkdirProcsAmount++;
}

void JsonAnalyzer::symlink3(const RPCProcedure* /*proc*/,
                            const struct NFS3::SYMLINK3args* /*args*/,
                            const struct NFS3::SYMLINK3res* /*res*/)
{
    _nfsV3Stat.symlinkProcsAmount++;
}

void JsonAnalyzer::mknod3(const RPCProcedure* /*proc*/,
                          const struct NFS3::MKNOD3args* /*args*/,
                          const struct NFS3::MKNOD3res* /*res*/)
{
    _nfsV3Stat.mknodProcsAmount++;
}

void JsonAnalyzer::remove3(const RPCProcedure* /*proc*/,
                           const struct NFS3::REMOVE3args* /*args*/,
                           const struct NFS3::REMOVE3res* /*res*/)
{
    _nfsV3Stat.removeProcsAmount++;
}

void JsonAnalyzer::rmdir3(const RPCProcedure* /*proc*/,
                          const struct NFS3::RMDIR3args* /*args*/,
                          const struct NFS3::RMDIR3res* /*res*/)
{
    _nfsV3Stat.rmdirProcsAmount++;
}

void JsonAnalyzer::rename3(const RPCProcedure* /*proc*/,
                           const struct NFS3::RENAME3args* /*args*/,
                           const struct NFS3::RENAME3res* /*res*/)
{
    _nfsV3Stat.renameProcsAmount++;
}

void JsonAnalyzer::link3(const RPCProcedure* /*proc*/,
                         const struct NFS3::LINK3args* /*args*/,
                         const struct NFS3::LINK3res* /*res*/)
{
    _nfsV3Stat.linkProcsAmount++;
}

void JsonAnalyzer::readdir3(const RPCProcedure* /*proc*/,
                            const struct NFS3::READDIR3args* /*args*/,
                            const struct NFS3::READDIR3res* /*res*/)
{
    _nfsV3Stat.readdirProcsAmount++;
}

void JsonAnalyzer::readdirplus3(const RPCProcedure* /*proc*/,
                                const struct NFS3::READDIRPLUS3args* /*args*/,
                                const struct NFS3::READDIRPLUS3res* /*res*/)
{
    _nfsV3Stat.readdirplusProcsAmount++;
}

void JsonAnalyzer::fsstat3(const RPCProcedure* /*proc*/,
                           const struct NFS3::FSSTAT3args* /*args*/,
                           const struct NFS3::FSSTAT3res* /*res*/)
{
    _nfsV3Stat.fsstatProcsAmount++;
}

void JsonAnalyzer::fsinfo3(const RPCProcedure* /*proc*/,
                           const struct NFS3::FSINFO3args* /*args*/,
                           const struct NFS3::FSINFO3res* /*res*/)
{
    _nfsV3Stat.fsinfoProcsAmount++;
}

void JsonAnalyzer::pathconf3(const RPCProcedure* /*proc*/,
                             const struct NFS3::PATHCONF3args* /*args*/,
                             const struct NFS3::PATHCONF3res* /*res*/)
{
    _nfsV3Stat.pathconfProcsAmount++;
}

void JsonAnalyzer::commit3(const RPCProcedure* /*proc*/,
                           const struct NFS3::COMMIT3args* /*args*/,
                           const struct NFS3::COMMIT3res* /*res*/)
{
    _nfsV3Stat.commitProcsAmount++;
}

// NFS4.0
// Procedures: 

void JsonAnalyzer::null(const RPCProcedure* /*proc*/,
                        const struct NFS4::NULL4args* /*args*/,
                        const struct NFS4::NULL4res* /*res*/)
{
    _nfsV40Stat.nullProcsAmount++;
}
void JsonAnalyzer::compound4(const RPCProcedure* /*proc*/,
                             const struct NFS4::COMPOUND4args* /*args*/,
                             const struct NFS4::COMPOUND4res* /*res*/)
{
    _nfsV40Stat.compoundProcsAmount++;
}

// Operations:

void JsonAnalyzer::access40(const RPCProcedure* /* proc */,
                            const struct NFS4::ACCESS4args* /* args */,
                            const struct NFS4::ACCESS4res* res)
{
    if(res) _nfsV40Stat.accessOpsAmount++;
}

void JsonAnalyzer::close40(const RPCProcedure* /* proc */,
                           const struct NFS4::CLOSE4args* /* args */,
                           const struct NFS4::CLOSE4res* res)
{
    if(res) _nfsV40Stat.closeOpsAmount++;
}

void JsonAnalyzer::commit40(const RPCProcedure* /* proc */,
                            const struct NFS4::COMMIT4args* /* args */,
                            const struct NFS4::COMMIT4res* res)
{
    if(res) _nfsV40Stat.commitOpsAmount++;
}

void JsonAnalyzer::create40(const RPCProcedure* /* proc */,
                            const struct NFS4::CREATE4args* /* args */,
                            const struct NFS4::CREATE4res* res)
{
    if(res) _nfsV40Stat.createOpsAmount++;
}

void JsonAnalyzer::delegpurge40(const RPCProcedure* /* proc */,
                                const struct NFS4::DELEGPURGE4args* /* args */,
                                const struct NFS4::DELEGPURGE4res* res)
{
    if(res) _nfsV40Stat.delegpurgeOpsAmount++;
}

void JsonAnalyzer::delegreturn40(const RPCProcedure* /* proc */,
                                 const struct NFS4::DELEGRETURN4args* /* args */,
                                 const struct NFS4::DELEGRETURN4res* res)
{
    if(res) _nfsV40Stat.delegreturnOpsAmount++;
}

void JsonAnalyzer::getattr40(const RPCProcedure* /* proc */,
                             const struct NFS4::GETATTR4args* /* args */,
                             const struct NFS4::GETATTR4res* res)
{
    if(res) _nfsV40Stat.getattrOpsAmount++;
}

void JsonAnalyzer::getfh40(const RPCProcedure* /* proc */,
                           const struct NFS4::GETFH4res* res)
{
    if(res) _nfsV40Stat.getfhOpsAmount++;
}

void JsonAnalyzer::link40(const RPCProcedure* /* proc */,
                          const struct NFS4::LINK4args* /* args */,
                          const struct NFS4::LINK4res* res)
{
    if(res) _nfsV40Stat.linkOpsAmount++;
}

void JsonAnalyzer::lock40(const RPCProcedure* /* proc */,
                          const struct NFS4::LOCK4args* /* args */,
                          const struct NFS4::LOCK4res* res)
{
    if(res) _nfsV40Stat.lockOpsAmount++;
}

void JsonAnalyzer::lockt40(const RPCProcedure* /* proc */,
                           const struct NFS4::LOCKT4args* /* args */,
                           const struct NFS4::LOCKT4res* res)
{
    if(res) _nfsV40Stat.locktOpsAmount++;
}

void JsonAnalyzer::locku40(const RPCProcedure* /* proc */,
                           const struct NFS4::LOCKU4args* /* args */,
                           const struct NFS4::LOCKU4res* res)
{
    if(res) _nfsV40Stat.lockuOpsAmount++;
}

void JsonAnalyzer::lookup40(const RPCProcedure* /* proc */,
                            const struct NFS4::LOOKUP4args* /* args */,
                            const struct NFS4::LOOKUP4res* res)
{
    if(res) _nfsV40Stat.lookupOpsAmount++;
}

void JsonAnalyzer::lookupp40(const RPCProcedure* /* proc */,
                             const struct NFS4::LOOKUPP4res* res)
{
    if(res) _nfsV40Stat.lookuppOpsAmount++;
}

void JsonAnalyzer::nverify40(const RPCProcedure* /* proc */,
                             const struct NFS4::NVERIFY4args* /* args */,
                             const struct NFS4::NVERIFY4res* res)
{
    if(res) _nfsV40Stat.nverifyOpsAmount++;
}

void JsonAnalyzer::open40(const RPCProcedure* /* proc */,
                          const struct NFS4::OPEN4args* /* args */,
                          const struct NFS4::OPEN4res* res)
{
    if(res) _nfsV40Stat.openOpsAmount++;
}

void JsonAnalyzer::openattr40(const RPCProcedure* /* proc */,
                              const struct NFS4::OPENATTR4args* /* args */,
                              const struct NFS4::OPENATTR4res* res)
{
    if(res) _nfsV40Stat.openattrOpsAmount++;
}

void JsonAnalyzer::open_confirm40(const RPCProcedure* /* proc */,
                                  const struct NFS4::OPEN_CONFIRM4args* /* args */,
                                  const struct NFS4::OPEN_CONFIRM4res* res)
{
    if(res) _nfsV40Stat.open_confirmOpsAmount++;
}

void JsonAnalyzer::open_downgrade40(const RPCProcedure* /* proc */,
                                    const struct NFS4::OPEN_DOWNGRADE4args* /* args */,
                                    const struct NFS4::OPEN_DOWNGRADE4res* res)
{
    if(res) _nfsV40Stat.open_downgradeOpsAmount++;
}

void JsonAnalyzer::putfh40(const RPCProcedure* /* proc */,
                           const struct NFS4::PUTFH4args* /* args */,
                           const struct NFS4::PUTFH4res* res)
{
    if(res) _nfsV40Stat.putfhOpsAmount++;
}

void JsonAnalyzer::putpubfh40(const RPCProcedure* /* proc */,
                              const struct NFS4::PUTPUBFH4res* res)
{
    if(res) _nfsV40Stat.putpubfhOpsAmount++;
}

void JsonAnalyzer::putrootfh40(const RPCProcedure* /* proc */,
                               const struct NFS4::PUTROOTFH4res* res)
{
    if(res) _nfsV40Stat.putrootfhOpsAmount++;
}

void JsonAnalyzer::read40(const RPCProcedure* /* proc */,
                          const struct NFS4::READ4args* /* args */,
                          const struct NFS4::READ4res* res)
{
    if(res) _nfsV40Stat.readOpsAmount++;
}

void JsonAnalyzer::readdir40(const RPCProcedure* /* proc */,
                             const struct NFS4::READDIR4args* /* args */,
                             const struct NFS4::READDIR4res* res)
{
    if(res) _nfsV40Stat.readdirOpsAmount++;
}

void JsonAnalyzer::readlink40(const RPCProcedure* /* proc */,
                              const struct NFS4::READLINK4res* res)
{
    if(res) _nfsV40Stat.readlinkOpsAmount++;
}

void JsonAnalyzer::remove40(const RPCProcedure* /* proc */,
                            const struct NFS4::REMOVE4args* /* args */,
                            const struct NFS4::REMOVE4res* res)
{
    if(res) _nfsV40Stat.removeOpsAmount++;
}

void JsonAnalyzer::rename40(const RPCProcedure* /* proc */,
                            const struct NFS4::RENAME4args* /* args */,
                            const struct NFS4::RENAME4res* res)
{
    if(res) _nfsV40Stat.renameOpsAmount++;
}

void JsonAnalyzer::renew40(const RPCProcedure* /* proc */,
                           const struct NFS4::RENEW4args* /* args */,
                           const struct NFS4::RENEW4res* res)
{
    if(res) _nfsV40Stat.renewOpsAmount++;
}

void JsonAnalyzer::restorefh40(const RPCProcedure* /* proc */,
                               const struct NFS4::RESTOREFH4res* res)
{
    if(res) _nfsV40Stat.restorefhOpsAmount++;
}

void JsonAnalyzer::savefh40(const RPCProcedure* /* proc */,
                            const struct NFS4::SAVEFH4res* res)
{
    if(res) _nfsV40Stat.savefhOpsAmount++;
}

void JsonAnalyzer::secinfo40(const RPCProcedure* /* proc */,
                             const struct NFS4::SECINFO4args* /* args */,
                             const struct NFS4::SECINFO4res* res)
{
    if(res) _nfsV40Stat.secinfoOpsAmount++;
}

void JsonAnalyzer::setattr40(const RPCProcedure* /* proc */,
                             const struct NFS4::SETATTR4args* /* args */,
                             const struct NFS4::SETATTR4res* res)
{
    if(res) _nfsV40Stat.setattrOpsAmount++;
}

void JsonAnalyzer::setclientid40(const RPCProcedure* /* proc */,
                                 const struct NFS4::SETCLIENTID4args* /* args */,
                                 const struct NFS4::SETCLIENTID4res* res)
{
    if(res) _nfsV40Stat.setclientidOpsAmount++;
}

void JsonAnalyzer::setclientid_confirm40(const RPCProcedure* /* proc */,
                                         const struct NFS4::SETCLIENTID_CONFIRM4args* /* args */,
                                         const struct NFS4::SETCLIENTID_CONFIRM4res* res)
{
    if(res) _nfsV40Stat.setclientid_confirmOpsAmount++;
}

void JsonAnalyzer::verify40(const RPCProcedure* /* proc */,
                            const struct NFS4::VERIFY4args* /* args */,
                            const struct NFS4::VERIFY4res* res)
{
    if(res) _nfsV40Stat.verifyOpsAmount++;
}

void JsonAnalyzer::write40(const RPCProcedure* /* proc */,
                           const struct NFS4::WRITE4args* /* args */,
                           const struct NFS4::WRITE4res* res)
{
    if(res) _nfsV40Stat.writeOpsAmount++;
}

void JsonAnalyzer::release_lockowner40(const RPCProcedure* /* proc */,
                                       const struct NFS4::RELEASE_LOCKOWNER4args* /* args */,
                                       const struct NFS4::RELEASE_LOCKOWNER4res* res)
{
    if(res) _nfsV40Stat.release_lockownerOpsAmount++;
}

void JsonAnalyzer::get_dir_delegation40(const RPCProcedure* /* proc */,
                                        const struct NFS4::GET_DIR_DELEGATION4args* /* args */,
                                        const struct NFS4::GET_DIR_DELEGATION4res* res)
{
    if(res) _nfsV40Stat.get_dir_delegationOpsAmount++;
}

void JsonAnalyzer::illegal40(const RPCProcedure* /* proc */,
                             const struct NFS4::ILLEGAL4res* res)
{
    if(res) _nfsV40Stat.illegalOpsAmount++;
}

// NFS4.1
// Procedures: 
 
void JsonAnalyzer::compound41(const RPCProcedure* /*proc*/,
                              const struct NFS41::COMPOUND4args* /*args*/,
                              const struct NFS41::COMPOUND4res* /*res*/)
{
    _nfsV41Stat.compoundProcsAmount++;
}

// Operations:

void JsonAnalyzer::access41(const RPCProcedure* /* proc */,
                            const struct NFS41::ACCESS4args* /* args */,
                            const struct NFS41::ACCESS4res* res)
{
    if(res) _nfsV41Stat.accessOpsAmount++;
}

void JsonAnalyzer::close41(const RPCProcedure* /* proc */,
                           const struct NFS41::CLOSE4args* /* args */,
                           const struct NFS41::CLOSE4res* res)
{
    if(res) _nfsV41Stat.closeOpsAmount++;
}

void JsonAnalyzer::commit41(const RPCProcedure* /* proc */,
                            const struct NFS41::COMMIT4args* /* args */,
                            const struct NFS41::COMMIT4res* res)
{
    if(res) _nfsV41Stat.commitOpsAmount++;
}

void JsonAnalyzer::create41(const RPCProcedure* /* proc */,
                            const struct NFS41::CREATE4args* /* args */,
                            const struct NFS41::CREATE4res* res)
{
    if(res) _nfsV41Stat.createOpsAmount++;
}

void JsonAnalyzer::delegpurge41(const RPCProcedure* /* proc */,
                                const struct NFS41::DELEGPURGE4args* /* args */,
                                const struct NFS41::DELEGPURGE4res* res)
{
    if(res) _nfsV41Stat.delegpurgeOpsAmount++;
}

void JsonAnalyzer::delegreturn41(const RPCProcedure* /* proc */,
                                 const struct NFS41::DELEGRETURN4args* /* args */,
                                 const struct NFS41::DELEGRETURN4res* res)
{
    if(res) _nfsV41Stat.delegreturnOpsAmount++;
}

void JsonAnalyzer::getattr41(const RPCProcedure* /* proc */,
                             const struct NFS41::GETATTR4args* /* args */,
                             const struct NFS41::GETATTR4res* res)
{
    if(res) _nfsV41Stat.getattrOpsAmount++;
}

void JsonAnalyzer::getfh41(const RPCProcedure* /* proc */,
                           const struct NFS41::GETFH4res* res)
{
    if(res) _nfsV41Stat.getfhOpsAmount++;
}

void JsonAnalyzer::link41(const RPCProcedure* /* proc */,
                          const struct NFS41::LINK4args* /* args */,
                          const struct NFS41::LINK4res* res)
{
    if(res) _nfsV41Stat.linkOpsAmount++;
}

void JsonAnalyzer::lock41(const RPCProcedure* /* proc */,
                          const struct NFS41::LOCK4args* /* args */,
                          const struct NFS41::LOCK4res* res)
{
    if(res) _nfsV41Stat.lockOpsAmount++;
}

void JsonAnalyzer::lockt41(const RPCProcedure* /* proc */,
                           const struct NFS41::LOCKT4args* /* args */,
                           const struct NFS41::LOCKT4res* res)
{
    if(res) _nfsV41Stat.locktOpsAmount++;
}

void JsonAnalyzer::locku41(const RPCProcedure* /* proc */,
                           const struct NFS41::LOCKU4args* /* args */,
                           const struct NFS41::LOCKU4res* res)
{
    if(res) _nfsV41Stat.lockuOpsAmount++;
}

void JsonAnalyzer::lookup41(const RPCProcedure* /* proc */,
                            const struct NFS41::LOOKUP4args* /* args */,
                            const struct NFS41::LOOKUP4res* res)
{
    if(res) _nfsV41Stat.lookupOpsAmount++;
}

void JsonAnalyzer::lookupp41(const RPCProcedure* /* proc */,
                             const struct NFS41::LOOKUPP4res* res)
{
    if(res) _nfsV41Stat.lookuppOpsAmount++;
}

void JsonAnalyzer::nverify41(const RPCProcedure* /* proc */,
                             const struct NFS41::NVERIFY4args* /* args */,
                             const struct NFS41::NVERIFY4res* res)
{
    if(res) _nfsV41Stat.nverifyOpsAmount++;
}

void JsonAnalyzer::open41(const RPCProcedure* /* proc */,
                          const struct NFS41::OPEN4args* /* args */,
                          const struct NFS41::OPEN4res* res)
{
    if(res) _nfsV41Stat.openOpsAmount++;
}

void JsonAnalyzer::openattr41(const RPCProcedure* /* proc */,
                              const struct NFS41::OPENATTR4args* /* args */,
                              const struct NFS41::OPENATTR4res* res)
{
    if(res) _nfsV41Stat.openattrOpsAmount++;
}

void JsonAnalyzer::open_confirm41(const RPCProcedure* /* proc */,
                                  const struct NFS41::OPEN_CONFIRM4args* /* args */,
                                  const struct NFS41::OPEN_CONFIRM4res* res)
{
    if(res) _nfsV41Stat.open_confirmOpsAmount++;
}

void JsonAnalyzer::open_downgrade41(const RPCProcedure* /* proc */,
                                    const struct NFS41::OPEN_DOWNGRADE4args* /* args */,
                                    const struct NFS41::OPEN_DOWNGRADE4res* res)
{
    if(res) _nfsV41Stat.open_downgradeOpsAmount++;
}

void JsonAnalyzer::putfh41(const RPCProcedure* /* proc */,
                           const struct NFS41::PUTFH4args* /* args */,
                           const struct NFS41::PUTFH4res* res)
{
    if(res) _nfsV41Stat.putfhOpsAmount++;
}

void JsonAnalyzer::putpubfh41(const RPCProcedure* /* proc */,
                              const struct NFS41::PUTPUBFH4res* res)
{
    if(res) _nfsV41Stat.putpubfhOpsAmount++;
}

void JsonAnalyzer::putrootfh41(const RPCProcedure* /* proc */,
                               const struct NFS41::PUTROOTFH4res* res)
{
    if(res) _nfsV41Stat.putrootfhOpsAmount++;
}

void JsonAnalyzer::read41(const RPCProcedure* /* proc */,
                          const struct NFS41::READ4args* /* args */,
                          const struct NFS41::READ4res* res)
{
    if(res) _nfsV41Stat.readOpsAmount++;
}

void JsonAnalyzer::readdir41(const RPCProcedure* /* proc */,
                             const struct NFS41::READDIR4args* /* args */,
                             const struct NFS41::READDIR4res* res)
{
    if(res) _nfsV41Stat.readdirOpsAmount++;
}

void JsonAnalyzer::readlink41(const RPCProcedure* /* proc */,
                              const struct NFS41::READLINK4res* res)
{
    if(res) _nfsV41Stat.readlinkOpsAmount++;
}

void JsonAnalyzer::remove41(const RPCProcedure* /* proc */,
                            const struct NFS41::REMOVE4args* /* args */,
                            const struct NFS41::REMOVE4res* res)
{
    if(res) _nfsV41Stat.removeOpsAmount++;
}

void JsonAnalyzer::rename41(const RPCProcedure* /* proc */,
                            const struct NFS41::RENAME4args* /* args */,
                            const struct NFS41::RENAME4res* res)
{
    if(res) _nfsV41Stat.renameOpsAmount++;
}

void JsonAnalyzer::renew41(const RPCProcedure* /* proc */,
                           const struct NFS41::RENEW4args* /* args */,
                           const struct NFS41::RENEW4res* res)
{
    if(res) _nfsV41Stat.renewOpsAmount++;
}

void JsonAnalyzer::restorefh41(const RPCProcedure* /* proc */,
                               const struct NFS41::RESTOREFH4res* res)
{
    if(res) _nfsV41Stat.restorefhOpsAmount++;
}

void JsonAnalyzer::savefh41(const RPCProcedure* /* proc */,
                            const struct NFS41::SAVEFH4res* res)
{
    if(res) _nfsV41Stat.savefhOpsAmount++;
}

void JsonAnalyzer::secinfo41(const RPCProcedure* /* proc */,
                             const struct NFS41::SECINFO4args* /* args */,
                             const struct NFS41::SECINFO4res* res)
{
    if(res) _nfsV41Stat.secinfoOpsAmount++;
}

void JsonAnalyzer::setattr41(const RPCProcedure* /* proc */,
                             const struct NFS41::SETATTR4args* /* args */,
                             const struct NFS41::SETATTR4res* res)
{
    if(res) _nfsV41Stat.setattrOpsAmount++;
}

void JsonAnalyzer::setclientid41(const RPCProcedure* /* proc */,
                                 const struct NFS41::SETCLIENTID4args* /* args */,
                                 const struct NFS41::SETCLIENTID4res* res)
{
    if(res) _nfsV41Stat.setclientidOpsAmount++;
}

void JsonAnalyzer::setclientid_confirm41(const RPCProcedure* /* proc */,
                                         const struct NFS41::SETCLIENTID_CONFIRM4args* /* args */,
                                         const struct NFS41::SETCLIENTID_CONFIRM4res* res)
{
    if(res) _nfsV41Stat.setclientid_confirmOpsAmount++;
}

void JsonAnalyzer::verify41(const RPCProcedure* /* proc */,
                            const struct NFS41::VERIFY4args* /* args */,
                            const struct NFS41::VERIFY4res* res)
{
    if(res) _nfsV41Stat.verifyOpsAmount++;
}

void JsonAnalyzer::write41(const RPCProcedure* /* proc */,
                           const struct NFS41::WRITE4args* /* args */,
                           const struct NFS41::WRITE4res* res)
{
    if(res) _nfsV41Stat.writeOpsAmount++;
}

void JsonAnalyzer::release_lockowner41(const RPCProcedure* /* proc */,
                                       const struct NFS41::RELEASE_LOCKOWNER4args* /* args */,
                                       const struct NFS41::RELEASE_LOCKOWNER4res* res)
{
    if(res) _nfsV41Stat.release_lockownerOpsAmount++;
}

void JsonAnalyzer::backchannel_ctl41(const RPCProcedure* /* proc */,
                                     const struct NFS41::BACKCHANNEL_CTL4args* /* args */,
                                     const struct NFS41::BACKCHANNEL_CTL4res* res)
{
    if(res) _nfsV41Stat.backchannel_ctlOpsAmount++;
}

void JsonAnalyzer::bind_conn_to_session41(const RPCProcedure* /* proc */,
                                          const struct NFS41::BIND_CONN_TO_SESSION4args* /* args */, 
                                          const struct NFS41::BIND_CONN_TO_SESSION4res* res)
{
    if(res) _nfsV41Stat.bind_conn_to_sessionOpsAmount++;
}

void JsonAnalyzer::exchange_id41(const RPCProcedure* /* proc */,
                                 const struct NFS41::EXCHANGE_ID4args* /* args */,
                                 const struct NFS41::EXCHANGE_ID4res* res)
{
    if(res) _nfsV41Stat.exchange_idOpsAmount++;
}

void JsonAnalyzer::create_session41(const RPCProcedure* /* proc */,
                                    const struct NFS41::CREATE_SESSION4args* /* args */,
                                    const struct NFS41::CREATE_SESSION4res* res)
{
    if(res) _nfsV41Stat.create_sessionOpsAmount++;
}

void JsonAnalyzer::destroy_session41(const RPCProcedure* /* proc */,
                                     const struct NFS41::DESTROY_SESSION4args* /* args */,
                                     const struct NFS41::DESTROY_SESSION4res* res)
{
    if(res) _nfsV41Stat.destroy_sessionOpsAmount++;
}

void JsonAnalyzer::free_stateid41(const RPCProcedure* /* proc */,
                                  const struct NFS41::FREE_STATEID4args* /* args */,
                                  const struct NFS41::FREE_STATEID4res* res)
{
    if(res) _nfsV41Stat.free_stateidOpsAmount++;
}

void JsonAnalyzer::get_dir_delegation41(const RPCProcedure* /* proc */,
                                        const struct NFS41::GET_DIR_DELEGATION4args* /* args */,
                                        const struct NFS41::GET_DIR_DELEGATION4res* res)
{
    if(res) _nfsV41Stat.get_dir_delegationOpsAmount++;
}

void JsonAnalyzer::getdeviceinfo41(const RPCProcedure* /* proc */,
                                   const struct NFS41::GETDEVICEINFO4args* /* args */,
                                   const struct NFS41::GETDEVICEINFO4res* res)
{
    if(res) _nfsV41Stat.getdeviceinfoOpsAmount++;
}

void JsonAnalyzer::getdevicelist41(const RPCProcedure* /* proc */,
                                   const struct NFS41::GETDEVICELIST4args* /* args */,
                                   const struct NFS41::GETDEVICELIST4res* res)
{
    if(res) _nfsV41Stat.getdevicelistOpsAmount++;
}

void JsonAnalyzer::layoutcommit41(const RPCProcedure* /* proc */,
                                  const struct NFS41::LAYOUTCOMMIT4args* /* args */,
                                  const struct NFS41::LAYOUTCOMMIT4res* res)
{
    if(res) _nfsV41Stat.layoutcommitOpsAmount++;
}

void JsonAnalyzer::layoutget41(const RPCProcedure* /* proc */,
                               const struct NFS41::LAYOUTGET4args* /* args */,
                               const struct NFS41::LAYOUTGET4res* res)
{
    if(res) _nfsV41Stat.layoutgetOpsAmount++;
}

void JsonAnalyzer::layoutreturn41(const RPCProcedure* /* proc */,
                                  const struct NFS41::LAYOUTRETURN4args* /* args */,
                                  const struct NFS41::LAYOUTRETURN4res* res)
{
    if(res) _nfsV41Stat.layoutreturnOpsAmount++;
}

void JsonAnalyzer::secinfo_no_name41(const RPCProcedure* /* proc */,
                                     const NFS41::SECINFO_NO_NAME4args* /* args */,
                                     const NFS41::SECINFO_NO_NAME4res* res)
{
    if(res) _nfsV41Stat.secinfo_no_nameOpsAmount++;
}

void JsonAnalyzer::sequence41(const RPCProcedure* /* proc */,
                              const struct NFS41::SEQUENCE4args* /* args */,
                              const struct NFS41::SEQUENCE4res* res)
{
    if(res) _nfsV41Stat.sequenceOpsAmount++;
}

void JsonAnalyzer::set_ssv41(const RPCProcedure* /* proc */,
                             const struct NFS41::SET_SSV4args* /* args */,
                             const struct NFS41::SET_SSV4res* res)
{
    if(res) _nfsV41Stat.set_ssvOpsAmount++;
}

void JsonAnalyzer::test_stateid41(const RPCProcedure* /* proc */,
                                  const struct NFS41::TEST_STATEID4args* /* args */,
                                  const struct NFS41::TEST_STATEID4res* res)
{
    if(res) _nfsV41Stat.test_stateidOpsAmount++;
}

void JsonAnalyzer::want_delegation41(const RPCProcedure* /* proc */,
                                     const struct NFS41::WANT_DELEGATION4args* /* args */,
                                     const struct NFS41::WANT_DELEGATION4res* res)
{
    if(res) _nfsV41Stat.want_delegationOpsAmount++;
}

void JsonAnalyzer::destroy_clientid41(const RPCProcedure* /* proc */,
                                      const struct NFS41::DESTROY_CLIENTID4args* /* args */,
                                      const struct NFS41::DESTROY_CLIENTID4res* res)
{
    if(res) _nfsV41Stat.destroy_clientidOpsAmount++;
}

void JsonAnalyzer::reclaim_complete41(const RPCProcedure* /* proc */,
                                      const struct NFS41::RECLAIM_COMPLETE4args* /* args */,
                                      const struct NFS41::RECLAIM_COMPLETE4res* res)
{
    if(res) _nfsV41Stat.reclaim_completeOpsAmount++;
}

void JsonAnalyzer::illegal41(const RPCProcedure* /* proc */,
                             const struct NFS41::ILLEGAL4res* res)
{
    if(res) _nfsV41Stat.illegalOpsAmount++;
}

void JsonAnalyzer::flush_statistics()
{
}
//------------------------------------------------------------------------------
