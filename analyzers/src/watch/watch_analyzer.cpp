//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source file for WatchAnalyzer based on TestAnalyzer.cpp
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
#include <algorithm>
#include <iostream>
#include <string>
#include <unordered_map>

#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>

#include "watch_analyzer.h"
//------------------------------------------------------------------------------
WatchAnalyzer::WatchAnalyzer(const char* opts)
: _cifsv2 {}
, _nfsv41 {}
, _nfsv4 {}
, _nfsv3 {}
, protocols {&_cifsv2, &_nfsv41, &_nfsv4, &_nfsv3}
, gui {opts, protocols}
{
}

WatchAnalyzer::~WatchAnalyzer()
{
}

void WatchAnalyzer::null(const RPCProcedure* proc,
                         const struct NFS3::NULL3args*,
                         const struct NFS3::NULL3res*) { nfs_account(proc); }
void WatchAnalyzer::getattr3(const RPCProcedure* proc,
                             const struct NFS3::GETATTR3args*,
                             const struct NFS3::GETATTR3res*) { nfs_account(proc); }
void WatchAnalyzer::setattr3(const RPCProcedure* proc,
                             const struct NFS3::SETATTR3args*,
                             const struct NFS3::SETATTR3res*) { nfs_account(proc); }
void WatchAnalyzer::lookup3(const RPCProcedure* proc,
                            const struct NFS3::LOOKUP3args*,
                            const struct NFS3::LOOKUP3res*) { nfs_account(proc); }
void WatchAnalyzer::access3(const RPCProcedure* proc,
                            const struct NFS3::ACCESS3args*,
                            const struct NFS3::ACCESS3res*) { nfs_account(proc); }
void WatchAnalyzer::readlink3(const RPCProcedure* proc,
                              const struct NFS3::READLINK3args*,
                              const struct NFS3::READLINK3res*) { nfs_account(proc); }
void WatchAnalyzer::read3(const RPCProcedure* proc,
                          const struct NFS3::READ3args*,
                          const struct NFS3::READ3res*) { nfs_account(proc); }
void WatchAnalyzer::write3(const RPCProcedure* proc,
                           const struct NFS3::WRITE3args*,
                           const struct NFS3::WRITE3res*) { nfs_account(proc); }
void WatchAnalyzer::create3(const RPCProcedure* proc,
                            const struct NFS3::CREATE3args*,
                            const struct NFS3::CREATE3res*) { nfs_account(proc); }
void WatchAnalyzer::mkdir3(const RPCProcedure* proc,
                           const struct NFS3::MKDIR3args*,
                           const struct NFS3::MKDIR3res*) { nfs_account(proc); }
void WatchAnalyzer::symlink3(const RPCProcedure* proc,
                             const struct NFS3::SYMLINK3args*,
                             const struct NFS3::SYMLINK3res*) { nfs_account(proc); }
void WatchAnalyzer::mknod3(const RPCProcedure* proc,
                           const struct NFS3::MKNOD3args*,
                           const struct NFS3::MKNOD3res*) { nfs_account(proc); }
void WatchAnalyzer::remove3(const RPCProcedure* proc,
                            const struct NFS3::REMOVE3args*,
                            const struct NFS3::REMOVE3res*) { nfs_account(proc); }
void WatchAnalyzer::rmdir3(const RPCProcedure* proc,
                           const struct NFS3::RMDIR3args*,
                           const struct NFS3::RMDIR3res*) { nfs_account(proc); }
void WatchAnalyzer::rename3(const RPCProcedure* proc,
                            const struct NFS3::RENAME3args*,
                            const struct NFS3::RENAME3res*) { nfs_account(proc); }
void WatchAnalyzer::link3(const RPCProcedure* proc,
                          const struct NFS3::LINK3args*,
                          const struct NFS3::LINK3res*) { nfs_account(proc); }
void WatchAnalyzer::readdir3(const RPCProcedure* proc,
                             const struct NFS3::READDIR3args*,
                             const struct NFS3::READDIR3res*) { nfs_account(proc); }
void WatchAnalyzer::readdirplus3(const RPCProcedure* proc,
                                 const struct NFS3::READDIRPLUS3args*,
                                 const struct NFS3::READDIRPLUS3res*) { nfs_account(proc); }
void WatchAnalyzer::fsstat3(const RPCProcedure* proc,
                            const struct NFS3::FSSTAT3args*,
                            const struct NFS3::FSSTAT3res*) { nfs_account(proc); }
void WatchAnalyzer::fsinfo3(const RPCProcedure* proc,
                            const struct NFS3::FSINFO3args*,
                            const struct NFS3::FSINFO3res*) { nfs_account(proc); }
void WatchAnalyzer::pathconf3(const RPCProcedure* proc,
                              const struct NFS3::PATHCONF3args*,
                              const struct NFS3::PATHCONF3res*) { nfs_account(proc); }
void WatchAnalyzer::commit3(const RPCProcedure* proc,
                            const struct NFS3::COMMIT3args*,
                            const struct NFS3::COMMIT3res*) { nfs_account(proc); }

// NFS4.0 procedures

void WatchAnalyzer::null(const RPCProcedure* proc,
                         const struct NFS4::NULL4args*,
                         const struct NFS4::NULL4res*) { nfs_account(proc, NFS_V40); }
void WatchAnalyzer::compound4(const RPCProcedure*  proc,
                              const struct NFS4::COMPOUND4args*,
                              const struct NFS4::COMPOUND4res*) { nfs_account(proc, NFS_V40); }

// NFS4.0 operations

void WatchAnalyzer::access40(const RPCProcedure* proc,
                             const struct NFS4::ACCESS4args*,
                             const struct NFS4::ACCESS4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::ACCESS); } }

void WatchAnalyzer::close40(const RPCProcedure* proc,
                            const struct NFS4::CLOSE4args*,
                            const struct NFS4::CLOSE4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::CLOSE); } }
void WatchAnalyzer::commit40(const RPCProcedure* proc,
                             const struct NFS4::COMMIT4args*,
                             const struct NFS4::COMMIT4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::COMMIT); } }
void WatchAnalyzer::create40(const RPCProcedure* proc,
                             const struct NFS4::CREATE4args*,
                             const struct NFS4::CREATE4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::CREATE); } }
void WatchAnalyzer::delegpurge40(const RPCProcedure* proc,
                                 const struct NFS4::DELEGPURGE4args*,
                                 const struct NFS4::DELEGPURGE4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::DELEGPURGE); } }
void WatchAnalyzer::delegreturn40(const RPCProcedure* proc,
                                  const struct NFS4::DELEGRETURN4args*,
                                  const struct NFS4::DELEGRETURN4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::DELEGRETURN); } }
void WatchAnalyzer::getattr40(const RPCProcedure* proc,
                              const struct NFS4::GETATTR4args*,
                              const struct NFS4::GETATTR4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::GETATTR); } }
void WatchAnalyzer::getfh40(const RPCProcedure* proc,
                            const struct NFS4::GETFH4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::GETFH); } }
void WatchAnalyzer::link40(const RPCProcedure* proc,
                           const struct NFS4::LINK4args*,
                           const struct NFS4::LINK4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LINK); } }
void WatchAnalyzer::lock40(const RPCProcedure* proc,
                           const struct NFS4::LOCK4args*,
                           const struct NFS4::LOCK4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOCK); } }
void WatchAnalyzer::lockt40(const RPCProcedure* proc,
                            const struct NFS4::LOCKT4args*,
                            const struct NFS4::LOCKT4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOCKT); } }
void WatchAnalyzer::locku40(const RPCProcedure* proc,
                            const struct NFS4::LOCKU4args*,
                            const struct NFS4::LOCKU4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOCKU); } }
void WatchAnalyzer::lookup40(const RPCProcedure* proc,
                             const struct NFS4::LOOKUP4args*,
                             const struct NFS4::LOOKUP4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOOKUP); } }
void WatchAnalyzer::lookupp40(const RPCProcedure* proc,
                              const struct NFS4::LOOKUPP4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOOKUPP); } }
void WatchAnalyzer::nverify40(const RPCProcedure* proc,
                              const struct NFS4::NVERIFY4args*,
                              const struct NFS4::NVERIFY4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::NVERIFY); } }
void WatchAnalyzer::open40(const RPCProcedure* proc,
                           const struct NFS4::OPEN4args*,
                           const struct NFS4::OPEN4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::OPEN); } }
void WatchAnalyzer::openattr40(const RPCProcedure* proc,
                               const struct NFS4::OPENATTR4args*,
                               const struct NFS4::OPENATTR4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::OPENATTR); } }
void WatchAnalyzer::open_confirm40(const RPCProcedure* proc,
                                   const struct NFS4::OPEN_CONFIRM4args*,
                                   const struct NFS4::OPEN_CONFIRM4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::OPEN_CONFIRM); } }
void WatchAnalyzer::open_downgrade40(const RPCProcedure* proc,
                                     const struct NFS4::OPEN_DOWNGRADE4args*,
                                     const struct NFS4::OPEN_DOWNGRADE4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::OPEN_DOWNGRADE); } }
void WatchAnalyzer::putfh40(const RPCProcedure* proc,
                            const struct NFS4::PUTFH4args*,
                            const struct NFS4::PUTFH4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::PUTFH); } }
void WatchAnalyzer::putpubfh40(const RPCProcedure* proc,
                               const struct NFS4::PUTPUBFH4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::PUTPUBFH); } }
void WatchAnalyzer::putrootfh40(const RPCProcedure* proc,
                                const struct NFS4::PUTROOTFH4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::PUTROOTFH); } }
void WatchAnalyzer::read40(const RPCProcedure* proc,
                           const struct NFS4::READ4args*,
                           const struct NFS4::READ4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::READ); } }
void WatchAnalyzer::readdir40(const RPCProcedure* proc,
                              const struct NFS4::READDIR4args*,
                              const struct NFS4::READDIR4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::READDIR); } }
void WatchAnalyzer::readlink40(const RPCProcedure* proc,
                               const struct NFS4::READLINK4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::READLINK); } }
void WatchAnalyzer::remove40(const RPCProcedure* proc,
                             const struct NFS4::REMOVE4args*,
                             const struct NFS4::REMOVE4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::REMOVE); } }
void WatchAnalyzer::rename40(const RPCProcedure* proc,
                             const struct NFS4::RENAME4args*,
                             const struct NFS4::RENAME4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::RENAME); } }
void WatchAnalyzer::renew40(const RPCProcedure* proc,
                            const struct NFS4::RENEW4args*,
                            const struct NFS4::RENEW4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::RENEW); } }
void WatchAnalyzer::restorefh40(const RPCProcedure* proc,
                                const struct NFS4::RESTOREFH4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::RESTOREFH); } }
void WatchAnalyzer::savefh40(const RPCProcedure* proc,
                             const struct NFS4::SAVEFH4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SAVEFH); } }
void WatchAnalyzer::secinfo40(const RPCProcedure* proc,
                              const struct NFS4::SECINFO4args*,
                              const struct NFS4::SECINFO4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SECINFO); } }
void WatchAnalyzer::setattr40(const RPCProcedure* proc,
                              const struct NFS4::SETATTR4args*,
                              const struct NFS4::SETATTR4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SETATTR); } }
void WatchAnalyzer::setclientid40(const RPCProcedure* proc,
                                  const struct NFS4::SETCLIENTID4args*,
                                  const struct NFS4::SETCLIENTID4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SETCLIENTID); } }
void WatchAnalyzer::setclientid_confirm40(const RPCProcedure* proc,
                                          const struct NFS4::SETCLIENTID_CONFIRM4args*,
                                          const struct NFS4::SETCLIENTID_CONFIRM4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SETCLIENTID_CONFIRM); } }
void WatchAnalyzer::verify40(const RPCProcedure* proc,
                             const struct NFS4::VERIFY4args*,
                             const struct NFS4::VERIFY4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::VERIFY); } }
void WatchAnalyzer::write40(const RPCProcedure* proc,
                            const struct NFS4::WRITE4args*,
                            const struct NFS4::WRITE4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::WRITE); } }
void WatchAnalyzer::release_lockowner40(const RPCProcedure* proc,
                                        const struct NFS4::RELEASE_LOCKOWNER4args*,
                                        const struct NFS4::RELEASE_LOCKOWNER4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::RELEASE_LOCKOWNER); } }
void WatchAnalyzer::get_dir_delegation40(const RPCProcedure* proc,
                                         const struct NFS4::GET_DIR_DELEGATION4args*,
                                         const struct NFS4::GET_DIR_DELEGATION4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::GET_DIR_DELEGATION); } }
void WatchAnalyzer::illegal40(const RPCProcedure* proc,
                              const struct NFS4::ILLEGAL4res* res) { if (res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::ILLEGAL); } }

// NFSv4.1 procedures

void WatchAnalyzer::compound41(const RPCProcedure*  proc,
                               const struct NFS41::COMPOUND4args*,
                               const struct NFS41::COMPOUND4res*) { nfs_account(proc, NFS_V41); }

// NFSv4.1 operations
void WatchAnalyzer::access41(const RPCProcedure* proc,
                             const struct NFS41::ACCESS4args*,
                             const struct NFS41::ACCESS4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::ACCESS); } }

void WatchAnalyzer::close41(const RPCProcedure* proc,
                            const struct NFS41::CLOSE4args*,
                            const struct NFS41::CLOSE4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::CLOSE); } }
void WatchAnalyzer::commit41(const RPCProcedure* proc,
                             const struct NFS41::COMMIT4args*,
                             const struct NFS41::COMMIT4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::COMMIT); } }
void WatchAnalyzer::create41(const RPCProcedure* proc,
                             const struct NFS41::CREATE4args*,
                             const struct NFS41::CREATE4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::CREATE); } }
void WatchAnalyzer::delegpurge41(const RPCProcedure* proc,
                                 const struct NFS41::DELEGPURGE4args*,
                                 const struct NFS41::DELEGPURGE4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::DELEGPURGE); } }
void WatchAnalyzer::delegreturn41(const RPCProcedure* proc,
                                  const struct NFS41::DELEGRETURN4args*,
                                  const struct NFS41::DELEGRETURN4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::DELEGRETURN); } }
void WatchAnalyzer::getattr41(const RPCProcedure* proc,
                              const struct NFS41::GETATTR4args*,
                              const struct NFS41::GETATTR4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GETATTR); } }
void WatchAnalyzer::getfh41(const RPCProcedure* proc,
                            const struct NFS41::GETFH4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GETFH); } }
void WatchAnalyzer::link41(const RPCProcedure* proc,
                           const struct NFS41::LINK4args*,
                           const struct NFS41::LINK4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LINK); } }
void WatchAnalyzer::lock41(const RPCProcedure* proc,
                           const struct NFS41::LOCK4args*,
                           const struct NFS41::LOCK4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOCK); } }
void WatchAnalyzer::lockt41(const RPCProcedure* proc,
                            const struct NFS41::LOCKT4args*,
                            const struct NFS41::LOCKT4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOCKT); } }
void WatchAnalyzer::locku41(const RPCProcedure* proc,
                            const struct NFS41::LOCKU4args*,
                            const struct NFS41::LOCKU4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOCKU); } }
void WatchAnalyzer::lookup41(const RPCProcedure* proc,
                             const struct NFS41::LOOKUP4args*,
                             const struct NFS41::LOOKUP4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOOKUP); } }
void WatchAnalyzer::lookupp41(const RPCProcedure* proc,
                              const struct NFS41::LOOKUPP4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOOKUPP); } }
void WatchAnalyzer::nverify41(const RPCProcedure* proc,
                              const struct NFS41::NVERIFY4args*,
                              const struct NFS41::NVERIFY4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::NVERIFY); } }
void WatchAnalyzer::open41(const RPCProcedure* proc,
                           const struct NFS41::OPEN4args*,
                           const struct NFS41::OPEN4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::OPEN); } }
void WatchAnalyzer::openattr41(const RPCProcedure* proc,
                               const struct NFS41::OPENATTR4args*,
                               const struct NFS41::OPENATTR4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::OPENATTR); } }
void WatchAnalyzer::open_confirm41(const RPCProcedure* proc,
                                   const struct NFS41::OPEN_CONFIRM4args*,
                                   const struct NFS41::OPEN_CONFIRM4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::OPEN_CONFIRM); } }
void WatchAnalyzer::open_downgrade41(const RPCProcedure* proc,
                                     const struct NFS41::OPEN_DOWNGRADE4args*,
                                     const struct NFS41::OPEN_DOWNGRADE4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::OPEN_DOWNGRADE); } }
void WatchAnalyzer::putfh41(const RPCProcedure* proc,
                            const struct NFS41::PUTFH4args*,
                            const struct NFS41::PUTFH4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::PUTFH); } }
void WatchAnalyzer::putpubfh41(const RPCProcedure* proc,
                               const struct NFS41::PUTPUBFH4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::PUTPUBFH); } }
void WatchAnalyzer::putrootfh41(const RPCProcedure* proc,
                                const struct NFS41::PUTROOTFH4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::PUTROOTFH); } }
void WatchAnalyzer::read41(const RPCProcedure* proc,
                           const struct NFS41::READ4args*,
                           const struct NFS41::READ4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::READ); } }
void WatchAnalyzer::readdir41(const RPCProcedure* proc,
                              const struct NFS41::READDIR4args*,
                              const struct NFS41::READDIR4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::READDIR); } }
void WatchAnalyzer::readlink41(const RPCProcedure* proc,
                               const struct NFS41::READLINK4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::READLINK); } }
void WatchAnalyzer::remove41(const RPCProcedure* proc,
                             const struct NFS41::REMOVE4args*,
                             const struct NFS41::REMOVE4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::REMOVE); } }
void WatchAnalyzer::rename41(const RPCProcedure* proc,
                             const struct NFS41::RENAME4args*,
                             const struct NFS41::RENAME4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RENAME); } }
void WatchAnalyzer::renew41(const RPCProcedure* proc,
                            const struct NFS41::RENEW4args*,
                            const struct NFS41::RENEW4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RENEW); } }
void WatchAnalyzer::restorefh41(const RPCProcedure* proc,
                                const struct NFS41::RESTOREFH4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RESTOREFH); } }
void WatchAnalyzer::savefh41(const RPCProcedure* proc,
                             const struct NFS41::SAVEFH4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SAVEFH); } }
void WatchAnalyzer::secinfo41(const RPCProcedure* proc,
                              const struct NFS41::SECINFO4args*,
                              const struct NFS41::SECINFO4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SECINFO); } }
void WatchAnalyzer::setattr41(const RPCProcedure* proc,
                              const struct NFS41::SETATTR4args*,
                              const struct NFS41::SETATTR4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SETATTR); } }
void WatchAnalyzer::setclientid41(const RPCProcedure* proc,
                                  const struct NFS41::SETCLIENTID4args*,
                                  const struct NFS41::SETCLIENTID4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SETCLIENTID); } }
void WatchAnalyzer::setclientid_confirm41(const RPCProcedure* proc,
                                          const struct NFS41::SETCLIENTID_CONFIRM4args*,
                                          const struct NFS41::SETCLIENTID_CONFIRM4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SETCLIENTID_CONFIRM); } }
void WatchAnalyzer::verify41(const RPCProcedure* proc,
                             const struct NFS41::VERIFY4args*,
                             const struct NFS41::VERIFY4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::VERIFY); } }
void WatchAnalyzer::write41(const RPCProcedure* proc,
                            const struct NFS41::WRITE4args*,
                            const struct NFS41::WRITE4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::WRITE); } }
void WatchAnalyzer::release_lockowner41(const RPCProcedure* proc,
                                        const struct NFS41::RELEASE_LOCKOWNER4args*,
                                        const struct NFS41::RELEASE_LOCKOWNER4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RELEASE_LOCKOWNER); } }
void WatchAnalyzer::backchannel_ctl41(const RPCProcedure* proc,
                                      const struct NFS41::BACKCHANNEL_CTL4args*,
                                      const struct NFS41::BACKCHANNEL_CTL4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::BACKCHANNEL_CTL); } }
void WatchAnalyzer::bind_conn_to_session41(const RPCProcedure* proc,
                                           const struct NFS41::BIND_CONN_TO_SESSION4args*,
                                           const struct NFS41::BIND_CONN_TO_SESSION4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::BIND_CONN_TO_SESSION); } }
void WatchAnalyzer::exchange_id41(const RPCProcedure* proc,
                                  const struct NFS41::EXCHANGE_ID4args*,
                                  const struct NFS41::EXCHANGE_ID4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::EXCHANGE_ID); } }
void WatchAnalyzer::create_session41(const RPCProcedure* proc,
                                     const struct NFS41::CREATE_SESSION4args*,
                                     const struct NFS41::CREATE_SESSION4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::CREATE_SESSION); } }
void WatchAnalyzer::destroy_session41(const RPCProcedure* proc,
                                      const struct NFS41::DESTROY_SESSION4args*,
                                      const struct NFS41::DESTROY_SESSION4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::DESTROY_SESSION); } }
void WatchAnalyzer::free_stateid41(const RPCProcedure* proc,
                                   const struct NFS41::FREE_STATEID4args*,
                                   const struct NFS41::FREE_STATEID4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::FREE_STATEID); } }
void WatchAnalyzer::get_dir_delegation41(const RPCProcedure* proc,
                                         const struct NFS41::GET_DIR_DELEGATION4args*,
                                         const struct NFS41::GET_DIR_DELEGATION4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GET_DIR_DELEGATION); } }
void WatchAnalyzer::getdeviceinfo41(const RPCProcedure* proc,
                                    const struct NFS41::GETDEVICEINFO4args*,
                                    const struct NFS41::GETDEVICEINFO4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GETDEVICEINFO); } }
void WatchAnalyzer::getdevicelist41(const RPCProcedure* proc,
                                    const struct NFS41::GETDEVICELIST4args*,
                                    const struct NFS41::GETDEVICELIST4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GETDEVICELIST); } }
void WatchAnalyzer::layoutcommit41(const RPCProcedure* proc,
                                   const struct NFS41::LAYOUTCOMMIT4args*,
                                   const struct NFS41::LAYOUTCOMMIT4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LAYOUTCOMMIT); } }
void WatchAnalyzer::layoutget41(const RPCProcedure* proc,
                                const struct NFS41::LAYOUTGET4args*,
                                const struct NFS41::LAYOUTGET4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LAYOUTGET); } }
void WatchAnalyzer::layoutreturn41(const RPCProcedure* proc,
                                   const struct NFS41::LAYOUTRETURN4args*,
                                   const struct NFS41::LAYOUTRETURN4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LAYOUTRETURN); } }
void WatchAnalyzer::secinfo_no_name41(const RPCProcedure* proc,
                                      const NFS41::SECINFO_NO_NAME4args*,
                                      const NFS41::SECINFO_NO_NAME4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SECINFO_NO_NAME); } }
void WatchAnalyzer::sequence41(const RPCProcedure* proc,
                               const struct NFS41::SEQUENCE4args*,
                               const struct NFS41::SEQUENCE4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SEQUENCE); } }
void WatchAnalyzer::set_ssv41(const RPCProcedure* proc,
                              const struct NFS41::SET_SSV4args*,
                              const struct NFS41::SET_SSV4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SET_SSV); } }
void WatchAnalyzer::test_stateid41(const RPCProcedure* proc,
                                   const struct NFS41::TEST_STATEID4args*,
                                   const struct NFS41::TEST_STATEID4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::TEST_STATEID); } }
void WatchAnalyzer::want_delegation41(const RPCProcedure* proc,
                                      const struct NFS41::WANT_DELEGATION4args*,
                                      const struct NFS41::WANT_DELEGATION4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::WANT_DELEGATION); } }
void WatchAnalyzer::destroy_clientid41(const RPCProcedure* proc,
                                       const struct NFS41::DESTROY_CLIENTID4args*,
                                       const struct NFS41::DESTROY_CLIENTID4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::DESTROY_CLIENTID); } }
void WatchAnalyzer::reclaim_complete41(const RPCProcedure* proc,
                                       const struct NFS41::RECLAIM_COMPLETE4args*,
                                       const struct NFS41::RECLAIM_COMPLETE4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RECLAIM_COMPLETE); } }
void WatchAnalyzer::illegal41(const RPCProcedure* proc,
                              const struct NFS41::ILLEGAL4res* res) { if (res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::ILLEGAL); } }
// CIFS v2

void WatchAnalyzer::closeFileSMBv2(const SMBv2::CloseFileCommand* cmd, const SMBv2::CloseRequest*, const SMBv2::CloseResponse*)
{
    cifs_account(cmd, SMBv2Commands::CLOSE);
}

void WatchAnalyzer::negotiateSMBv2(const SMBv2::NegotiateCommand* cmd, const SMBv2::NegotiateRequest*, const SMBv2::NegotiateResponse*)
{
    cifs_account(cmd, SMBv2Commands::NEGOTIATE);
}

void WatchAnalyzer::sessionSetupSMBv2(const SMBv2::SessionSetupCommand* cmd, const SMBv2::SessionSetupRequest*, const SMBv2::SessionSetupResponse*)
{
    cifs_account(cmd, SMBv2Commands::SESSION_SETUP);
}

void WatchAnalyzer::logOffSMBv2(const SMBv2::LogOffCommand* cmd, const SMBv2::LogOffRequest*, const SMBv2::LogOffResponse*)
{
    cifs_account(cmd, SMBv2Commands::LOGOFF);
}

void WatchAnalyzer::treeConnectSMBv2(const SMBv2::TreeConnectCommand* cmd, const SMBv2::TreeConnectRequest*, const SMBv2::TreeConnectResponse*)
{
    cifs_account(cmd, SMBv2Commands::TREE_CONNECT);
}

void WatchAnalyzer::treeDisconnectSMBv2(const SMBv2::TreeDisconnectCommand* cmd, const SMBv2::TreeDisconnectRequest*, const SMBv2::TreeDisconnectResponse*)
{
    cifs_account(cmd, SMBv2Commands::TREE_DISCONNECT);
}

void WatchAnalyzer::createSMBv2(const SMBv2::CreateCommand* cmd, const SMBv2::CreateRequest*, const SMBv2::CreateResponse*)
{
    cifs_account(cmd, SMBv2Commands::CREATE);
}

void WatchAnalyzer::flushSMBv2(const SMBv2::FlushCommand* cmd, const SMBv2::FlushRequest*, const SMBv2::FlushResponse*)
{
    cifs_account(cmd, SMBv2Commands::FLUSH);
}

void WatchAnalyzer::readSMBv2(const SMBv2::ReadCommand* cmd, const SMBv2::ReadRequest*, const SMBv2::ReadResponse*)
{
    cifs_account(cmd, SMBv2Commands::READ);
}

void WatchAnalyzer::writeSMBv2(const SMBv2::WriteCommand* cmd, const SMBv2::WriteRequest*, const SMBv2::WriteResponse*)
{
    cifs_account(cmd, SMBv2Commands::WRITE);
}

void WatchAnalyzer::lockSMBv2(const SMBv2::LockCommand* cmd, const SMBv2::LockRequest*, const SMBv2::LockResponse*)
{
    cifs_account(cmd, SMBv2Commands::LOCK);
}

void WatchAnalyzer::ioctlSMBv2(const SMBv2::IoctlCommand* cmd, const SMBv2::IoCtlRequest*, const SMBv2::IoCtlResponse*)
{
    cifs_account(cmd, SMBv2Commands::IOCTL);
}

void WatchAnalyzer::cancelSMBv2(const SMBv2::CancelCommand* cmd, const SMBv2::CancelRequest*, const SMBv2::CancelResponce*)
{
    cifs_account(cmd, SMBv2Commands::CANCEL);
}

void WatchAnalyzer::echoSMBv2(const SMBv2::EchoCommand* cmd, const SMBv2::EchoRequest*, const SMBv2::EchoResponse*)
{
    cifs_account(cmd, SMBv2Commands::ECHO);
}

void WatchAnalyzer::queryDirSMBv2(const SMBv2::QueryDirCommand* cmd, const SMBv2::QueryDirRequest*, const SMBv2::QueryDirResponse*)
{
    cifs_account(cmd, SMBv2Commands::QUERY_DIRECTORY);
}

void WatchAnalyzer::changeNotifySMBv2(const SMBv2::ChangeNotifyCommand* cmd, const SMBv2::ChangeNotifyRequest*, const SMBv2::ChangeNotifyResponse*)
{
    cifs_account(cmd, SMBv2Commands::CHANGE_NOTIFY);
}

void WatchAnalyzer::queryInfoSMBv2(const SMBv2::QueryInfoCommand* cmd, const SMBv2::QueryInfoRequest*, const SMBv2::QueryInfoResponse*)
{
    cifs_account(cmd, SMBv2Commands::QUERY_INFO);
}

void WatchAnalyzer::setInfoSMBv2(const SMBv2::SetInfoCommand* cmd, const SMBv2::SetInfoRequest*, const SMBv2::SetInfoResponse*)
{
    cifs_account(cmd, SMBv2Commands::SET_INFO);
}

void WatchAnalyzer::breakOplockSMBv2(const SMBv2::BreakOpLockCommand* cmd, const SMBv2::OplockAcknowledgment*, const SMBv2::OplockResponse*)
{
    cifs_account(cmd, SMBv2Commands::OPLOCK_BREAK);
}

void WatchAnalyzer::flush_statistics()
{
}

void WatchAnalyzer::on_unix_signal(int signo)
{
    if (signo == SIGWINCH)
    {
        gui.enableUpdate();
    }
}

void WatchAnalyzer::nfs_account(const RPCProcedure* proc, const unsigned int nfs_minor_vers)
{
    const u_int nfs_proc = proc->call.ru.RM_cmb.cb_proc;
    const u_int nfs_vers = proc->call.ru.RM_cmb.cb_vers;

    if (nfs_vers == NFS_V4)
    {
        if (nfs_minor_vers == NFS_V40)
        {
            std::vector<std::size_t> nfs4_proc_count (ProcEnumNFS4::count, 0);
            ++nfs4_proc_count[nfs_proc];
            gui.update(&_nfsv4, nfs4_proc_count);
        }

        if (nfs_minor_vers == NFS_V41 || nfs_proc == ProcEnumNFS4::NFS_NULL)
        {
            std::vector<std::size_t> nfs41_proc_count (ProcEnumNFS41::count, 0);
            ++nfs41_proc_count[nfs_proc];
            gui.update(&_nfsv41, nfs41_proc_count);
        }
    }
    else if (nfs_vers == NFS_V3)
    {
        std::vector<std::size_t> nfs3_proc_count (ProcEnumNFS3::count, 0);
        ++nfs3_proc_count[nfs_proc];
        gui.update(&_nfsv3, nfs3_proc_count);
    }
}

void WatchAnalyzer::account40_op(const RPCProcedure* /*proc*/, const ProcEnumNFS4::NFSProcedure operation)
{
    std::vector<std::size_t> nfs4_proc_count (ProcEnumNFS4::count, 0);
    ++nfs4_proc_count[operation];
    gui.update(&_nfsv4, nfs4_proc_count);
}

void WatchAnalyzer::account41_op(const RPCProcedure* /*proc*/, const ProcEnumNFS41::NFSProcedure operation)
{
    std::vector<std::size_t> nfs41_proc_count (ProcEnumNFS41::count, 0);
    ++nfs41_proc_count[operation];
    gui.update(&_nfsv41, nfs41_proc_count);
}
//------------------------------------------------------------------------------
extern "C"
{

    const char* usage()
    {
        return "User can set chrono output timeout in msec.\n"
               "You have to run nfstrace with verbosity level set to 0 (nfstrace -v 0 ...)";
    }

    IAnalyzer* create(const char* opts)
    {
        try
        {
            return new WatchAnalyzer(opts);
        }
        catch (std::exception& e)
        {
            std::cerr << "Can't initalize plugin: " << e.what() << std::endl;
            return nullptr;
        }
    }

    void destroy(IAnalyzer* instance)
    {
        delete instance;
    }

    NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)
}
//------------------------------------------------------------------------------
