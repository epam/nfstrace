//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: IAnalyzer describe interface of analysiss expected by application.
// The interface define set of NFS Procedure handlers with empty dummy implementation
// and pure virtual function for flushing analysis statistics.
// Copyright (c) 2013 EPAM Systems
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
#ifndef IANALYZER_TYPE_H
#define IANALYZER_TYPE_H
//------------------------------------------------------------------------------

#include <iostream>

#include "nfs_types.h"
#include "nfs3_types_rpcgen.h"
#include "nfs4_types_rpcgen.h"
#include "nfs41_types_rpcgen.h"
#include "rpc_procedure.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

class INFSv3rpcgen
{
public:
    virtual void null(const struct RPCProcedure*,
            const struct NFS3::NULL3args*,
            const struct NFS3::NULL3res*) {}
    virtual void getattr3(const struct RPCProcedure*,
            const struct NFS3::GETATTR3args*,
            const struct NFS3::GETATTR3res*) {}
    virtual void setattr3(const struct RPCProcedure*,
            const struct NFS3::SETATTR3args*,
            const struct NFS3::SETATTR3res*) {}
    virtual void lookup3(const struct RPCProcedure*,
            const struct NFS3::LOOKUP3args*,
            const struct NFS3::LOOKUP3res*) {}
    virtual void access3(const struct RPCProcedure*,
            const struct NFS3::ACCESS3args*,
            const struct NFS3::ACCESS3res*) {}
    virtual void readlink3(const struct RPCProcedure*,
            const struct NFS3::READLINK3args*,
            const struct NFS3::READLINK3res*) {}
    virtual void read3(const struct RPCProcedure*,
            const struct NFS3::READ3args*,
            const struct NFS3::READ3res*) {}
    virtual void write3(const struct RPCProcedure*,
            const struct NFS3::WRITE3args*,
            const struct NFS3::WRITE3res*) {}
    virtual void create3(const struct RPCProcedure*,
            const struct NFS3::CREATE3args*,
            const struct NFS3::CREATE3res*) {}
    virtual void mkdir3(const struct RPCProcedure*,
            const struct NFS3::MKDIR3args*,
            const struct NFS3::MKDIR3res*) {}
    virtual void symlink3(const struct RPCProcedure*,
            const struct NFS3::SYMLINK3args*,
            const struct NFS3::SYMLINK3res*) {}
    virtual void mknod3(const struct RPCProcedure*,
            const struct NFS3::MKNOD3args*,
            const struct NFS3::MKNOD3res*) {}
    virtual void remove3(const struct RPCProcedure*,
            const struct NFS3::REMOVE3args*,
            const struct NFS3::REMOVE3res*) {}
    virtual void rmdir3(const struct RPCProcedure*,
            const struct NFS3::RMDIR3args*,
            const struct NFS3::RMDIR3res*) {}
    virtual void rename3(const struct RPCProcedure*,
            const struct NFS3::RENAME3args*,
            const struct NFS3::RENAME3res*) {}
    virtual void link3(const struct RPCProcedure*,
            const struct NFS3::LINK3args*,
            const struct NFS3::LINK3res*) {}
    virtual void readdir3(const struct RPCProcedure*,
            const struct NFS3::READDIR3args*,
            const struct NFS3::READDIR3res*) {}
    virtual void readdirplus3(const struct RPCProcedure*,
            const struct NFS3::READDIRPLUS3args*,
            const struct NFS3::READDIRPLUS3res*) {}
    virtual void fsstat3(const struct RPCProcedure*,
            const struct NFS3::FSSTAT3args*,
            const struct NFS3::FSSTAT3res*) {}
    virtual void fsinfo3(const struct RPCProcedure*,
            const struct NFS3::FSINFO3args*,
            const struct NFS3::FSINFO3res*) {}
    virtual void pathconf3(const struct RPCProcedure*,
            const struct NFS3::PATHCONF3args*,
            const struct NFS3::PATHCONF3res*) {}
    virtual void commit3(const struct RPCProcedure*,
            const struct NFS3::COMMIT3args*,
            const struct NFS3::COMMIT3res*) {}
};

class INFSv4rpcgen
{
public:
    virtual void null(const struct RPCProcedure*,
            const struct NFS4::NULL4args*,
            const struct NFS4::NULL4res*) {}
    virtual void compound4(const struct RPCProcedure*,
            const struct NFS4::COMPOUND4args*,
            const struct NFS4::COMPOUND4res*) {}

    virtual void access40(const struct RPCProcedure*,
            const struct NFS4::ACCESS4args*,
            const struct NFS4::ACCESS4res*) {std::cout << "\n\n\n111111111111\n\n\n";}
    virtual void close40(const struct RPCProcedure*,
            const struct NFS4::CLOSE4args*,
            const struct NFS4::CLOSE4res*) {}
    virtual void commit40(const struct RPCProcedure*,
            const struct NFS4::COMMIT4args*,
            const struct NFS4::COMMIT4res*) {}
    virtual void create40(const struct RPCProcedure*,
            const struct NFS4::CREATE4args*,
            const struct NFS4::CREATE4res*) {}
    virtual void delegpurge40(const struct RPCProcedure*,
            const struct NFS4::DELEGPURGE4args*,
            const struct NFS4::DELEGPURGE4res*) {}
    virtual void delegreturn40(const struct RPCProcedure*,
            const struct NFS4::DELEGRETURN4args*,
            const struct NFS4::DELEGRETURN4res*) {}
    virtual void getattr40(const struct RPCProcedure*,
            const struct NFS4::GETATTR4args*,
            const struct NFS4::GETATTR4res*) {}
    virtual void getfh40(const struct RPCProcedure*,
            const struct NFS4::GETFH4res*) {}
    virtual void link40(const struct RPCProcedure*,
            const struct NFS4::LINK4args*,
            const struct NFS4::LINK4res*) {}
    virtual void lock40(const struct RPCProcedure*,
            const struct NFS4::LOCK4args*,
            const struct NFS4::LOCK4res*) {}
    virtual void lockt40(const struct RPCProcedure*,
            const struct NFS4::LOCKT4args*,
            const struct NFS4::LOCKT4res*) {}
    virtual void locku40(const struct RPCProcedure*,
            const struct NFS4::LOCKU4args*,
            const struct NFS4::LOCKU4res*) {}
    virtual void lookup40(const struct RPCProcedure*,
            const struct NFS4::LOOKUP4args*,
            const struct NFS4::LOOKUP4res*) {}
    virtual void lookupp40(const struct RPCProcedure*,
            const struct NFS4::LOOKUPP4res*) {}
    virtual void nverify40(const struct RPCProcedure*,
            const struct NFS4::NVERIFY4args*,
            const struct NFS4::NVERIFY4res*) {}
    virtual void open40(const struct RPCProcedure*,
            const struct NFS4::OPEN4args*,
            const struct NFS4::OPEN4res*) {}
    virtual void openattr40(const struct RPCProcedure*,
            const struct NFS4::OPENATTR4args*,
            const struct NFS4::OPENATTR4res*) {}
    virtual void open_confirm40(const struct RPCProcedure*,
            const struct NFS4::OPEN_CONFIRM4args*,
            const struct NFS4::OPEN_CONFIRM4res*) {}
    virtual void open_downgrade40(const struct RPCProcedure*,
            const struct NFS4::OPEN_DOWNGRADE4args*,
            const struct NFS4::OPEN_DOWNGRADE4res*) {}
    virtual void putfh40(const struct RPCProcedure*,
            const struct NFS4::PUTFH4args*,
            const struct NFS4::PUTFH4res*) {}
    virtual void putpubfh40(const struct RPCProcedure*,
            const struct NFS4::PUTPUBFH4res*) {}
    virtual void putrootfh40(const struct RPCProcedure*,
            const struct NFS4::PUTROOTFH4res*) {}
    virtual void read40(const struct RPCProcedure*,
            const struct NFS4::READ4args*,
            const struct NFS4::READ4res*) {}
    virtual void readdir40(const struct RPCProcedure*,
            const struct NFS4::READDIR4args*,
            const struct NFS4::READDIR4res*) {}
    virtual void readlink40(const struct RPCProcedure*,
            const struct NFS4::READLINK4res*) {}
    virtual void remove40(const struct RPCProcedure*,
            const struct NFS4::REMOVE4args*,
            const struct NFS4::REMOVE4res*) {}
    virtual void rename40(const struct RPCProcedure*,
            const struct NFS4::RENAME4args*,
            const struct NFS4::RENAME4res*) {}
    virtual void renew40(const struct RPCProcedure*,
            const struct NFS4::RENEW4args*,
            const struct NFS4::RENEW4res*) {}
    virtual void restorefh40(const struct RPCProcedure*,
            const struct NFS4::RESTOREFH4res*) {}
    virtual void savefh40(const struct RPCProcedure*,
            const struct NFS4::SAVEFH4res*) {}
    virtual void secinfo40(const struct RPCProcedure*,
            const struct NFS4::SECINFO4args*,
            const struct NFS4::SECINFO4res*) {}
    virtual void setattr40(const struct RPCProcedure*,
            const struct NFS4::SETATTR4args*,
            const struct NFS4::SETATTR4res*) {}
    virtual void setclientid40(const struct RPCProcedure*,
            const struct NFS4::SETCLIENTID4args*,
            const struct NFS4::SETCLIENTID4res*) {}
    virtual void setclientid_confirm40(const struct RPCProcedure*,
            const struct NFS4::SETCLIENTID_CONFIRM4args*,
            const struct NFS4::SETCLIENTID_CONFIRM4res*) {}
    virtual void verify40(const struct RPCProcedure*,
            const struct NFS4::VERIFY4args*,
            const struct NFS4::VERIFY4res*) {}
    virtual void write40(const struct RPCProcedure*,
            const struct NFS4::WRITE4args*,
            const struct NFS4::WRITE4res*) {}
    virtual void release_lockowner40(const struct RPCProcedure*,
            const struct NFS4::RELEASE_LOCKOWNER4args*,
            const struct NFS4::RELEASE_LOCKOWNER4res*) {}
    virtual void get_dir_delegation40(const struct RPCProcedure*,
            const struct NFS4::GET_DIR_DELEGATION4args*,
            const struct NFS4::GET_DIR_DELEGATION4res*) {}
    virtual void illegal40(const struct RPCProcedure*,
            const struct NFS4::ILLEGAL4res*) {}
};

class INFSv41rpcgen
{
public:
    virtual void null41(const struct RPCProcedure*,
            const struct NFS41::NULL4args*,
            const struct NFS41::NULL4res*) {}
    virtual void compound41(const struct RPCProcedure*,
            const struct NFS41::COMPOUND4args*,
            const struct NFS41::COMPOUND4res*) {}

    virtual void access41(const struct RPCProcedure*,
            const struct NFS41::ACCESS4args*,
            const struct NFS41::ACCESS4res*) {}
    virtual void close41(const struct RPCProcedure*,
            const struct NFS41::CLOSE4args*,
            const struct NFS41::CLOSE4res*) {}
    virtual void commit41(const struct RPCProcedure*,
            const struct NFS41::COMMIT4args*,
            const struct NFS41::COMMIT4res*) {}
    virtual void create41(const struct RPCProcedure*,
            const struct NFS41::CREATE4args*,
            const struct NFS41::CREATE4res*) {}
    virtual void delegpurge41(const struct RPCProcedure*,
            const struct NFS41::DELEGPURGE4args*,
            const struct NFS41::DELEGPURGE4res*) {}
    virtual void delegreturn41(const struct RPCProcedure*,
            const struct NFS41::DELEGRETURN4args*,
            const struct NFS41::DELEGRETURN4res*) {}
    virtual void getattr41(const struct RPCProcedure*,
            const struct NFS41::GETATTR4args*,
            const struct NFS41::GETATTR4res*) {}
    virtual void getfh41(const struct RPCProcedure*,
            const struct NFS41::GETFH4res*) {}
    virtual void link41(const struct RPCProcedure*,
            const struct NFS41::LINK4args*,
            const struct NFS41::LINK4res*) {}
    virtual void lock41(const struct RPCProcedure*,
            const struct NFS41::LOCK4args*,
            const struct NFS41::LOCK4res*) {}
    virtual void lockt41(const struct RPCProcedure*,
            const struct NFS41::LOCKT4args*,
            const struct NFS41::LOCKT4res*) {}
    virtual void locku41(const struct RPCProcedure*,
            const struct NFS41::LOCKU4args*,
            const struct NFS41::LOCKU4res*) {}
    virtual void lookup41(const struct RPCProcedure*,
            const struct NFS41::LOOKUP4args*,
            const struct NFS41::LOOKUP4res*) {}
    virtual void lookupp41(const struct RPCProcedure*,
            const struct NFS41::LOOKUPP4res*) {}
    virtual void nverify41(const struct RPCProcedure*,
            const struct NFS41::NVERIFY4args*,
            const struct NFS41::NVERIFY4res*) {}
    virtual void open41(const struct RPCProcedure*,
            const struct NFS41::OPEN4args*,
            const struct NFS41::OPEN4res*) {}
    virtual void openattr41(const struct RPCProcedure*,
            const struct NFS41::OPENATTR4args*,
            const struct NFS41::OPENATTR4res*) {}
    virtual void open_confirm41(const struct RPCProcedure*,
            const struct NFS41::OPEN_CONFIRM4args*,
            const struct NFS41::OPEN_CONFIRM4res*) {}
    virtual void open_downgrade41(const struct RPCProcedure*,
            const struct NFS41::OPEN_DOWNGRADE4args*,
            const struct NFS41::OPEN_DOWNGRADE4res*) {}
    virtual void putfh41(const struct RPCProcedure*,
            const struct NFS41::PUTFH4args*,
            const struct NFS41::PUTFH4res*) {}
    virtual void putpubfh41(const struct RPCProcedure*,
            const struct NFS41::PUTPUBFH4res*) {}
    virtual void putrootfh41(const struct RPCProcedure*,
            const struct NFS41::PUTROOTFH4res*) {}
    virtual void read41(const struct RPCProcedure*,
            const struct NFS41::READ4args*,
            const struct NFS41::READ4res*) {}
    virtual void readdir41(const struct RPCProcedure*,
            const struct NFS41::READDIR4args*,
            const struct NFS41::READDIR4res*) {}
    virtual void readlink41(const struct RPCProcedure*,
            const struct NFS41::READLINK4res*) {}
    virtual void remove41(const struct RPCProcedure*,
            const struct NFS41::REMOVE4args*,
            const struct NFS41::REMOVE4res*) {}
    virtual void rename41(const struct RPCProcedure*,
            const struct NFS41::RENAME4args*,
            const struct NFS41::RENAME4res*) {}
    virtual void renew41(const struct RPCProcedure*,
            const struct NFS41::RENEW4args*,
            const struct NFS41::RENEW4res*) {}
    virtual void restorefh41(const struct RPCProcedure*,
            const struct NFS41::RESTOREFH4res*) {}
    virtual void savefh41(const struct RPCProcedure*,
            const struct NFS41::SAVEFH4res*) {}
    virtual void secinfo41(const struct RPCProcedure*,
            const struct NFS41::SECINFO4args*,
            const struct NFS41::SECINFO4res*) {}
    virtual void setattr41(const struct RPCProcedure*,
            const struct NFS41::SETATTR4args*,
            const struct NFS41::SETATTR4res*) {}
    virtual void setclientid41(const struct RPCProcedure*,
            const struct NFS41::SETCLIENTID4args*,
            const struct NFS41::SETCLIENTID4res*) {}
    virtual void setclientid_confirm41(const struct RPCProcedure*,
            const struct NFS41::SETCLIENTID_CONFIRM4args*,
            const struct NFS41::SETCLIENTID_CONFIRM4res*) {}
    virtual void verify41(const struct RPCProcedure*,
            const struct NFS41::VERIFY4args*,
            const struct NFS41::VERIFY4res*) {}
    virtual void write41(const struct RPCProcedure*,
            const struct NFS41::WRITE4args*,
            const struct NFS41::WRITE4res*) {}
    virtual void release_lockowner41(const struct RPCProcedure*,
            const struct NFS41::RELEASE_LOCKOWNER4args*,
            const struct NFS41::RELEASE_LOCKOWNER4res*) {}
    virtual void backchannel_ctl41(const struct RPCProcedure*,
            const struct NFS41::BACKCHANNEL_CTL4args*,
            const struct NFS41::BACKCHANNEL_CTL4res*) {}
    virtual void bind_conn_to_session41(const struct RPCProcedure*,
            const struct NFS41::BIND_CONN_TO_SESSION4args*,
            const struct NFS41::BIND_CONN_TO_SESSION4res*) {}
    virtual void exchange_id41(const struct RPCProcedure*,
            const struct NFS41::EXCHANGE_ID4args*,
            const struct NFS41::EXCHANGE_ID4res*) {}
    virtual void create_session41(const struct RPCProcedure*,
            const struct NFS41::CREATE_SESSION4args*,
            const struct NFS41::CREATE_SESSION4res*) {}
    virtual void destroy_session41(const struct RPCProcedure*,
            const struct NFS41::DESTROY_SESSION4args*,
            const struct NFS41::DESTROY_SESSION4res*) {}
    virtual void free_stateid41(const struct RPCProcedure*,
            const struct NFS41::FREE_STATEID4args*,
            const struct NFS41::FREE_STATEID4res*) {}
    virtual void get_dir_delegation41(const struct RPCProcedure*,
            const struct NFS41::GET_DIR_DELEGATION4args*,
            const struct NFS41::GET_DIR_DELEGATION4res*) {}
    virtual void getdeviceinfo41(const struct RPCProcedure*,
            const struct NFS41::GETDEVICEINFO4args*,
            const struct NFS41::GETDEVICEINFO4res*) {}
    virtual void getdevicelist41(const struct RPCProcedure*,
            const struct NFS41::GETDEVICELIST4args*,
            const struct NFS41::GETDEVICELIST4res*) {}
    virtual void layoutcommit41(const struct RPCProcedure*,
            const struct NFS41::LAYOUTCOMMIT4args*,
            const struct NFS41::LAYOUTCOMMIT4res*) {}
    virtual void layoutget41(const struct RPCProcedure*,
            const struct NFS41::LAYOUTGET4args*,
            const struct NFS41::LAYOUTGET4res*) {}
    virtual void layoutreturn41(const struct RPCProcedure*,
            const struct NFS41::LAYOUTRETURN4args*,
            const struct NFS41::LAYOUTRETURN4res*) {}
    virtual void secinfo_no_name41(const struct RPCProcedure*,
            const NFS41::SECINFO_NO_NAME4args*,
            const NFS41::SECINFO_NO_NAME4res*) {}
    virtual void sequence41(const struct RPCProcedure*,
            const struct NFS41::SEQUENCE4args*,
            const struct NFS41::SEQUENCE4res*) {}
    virtual void set_ssv41(const struct RPCProcedure*,
            const struct NFS41::SET_SSV4args*,
            const struct NFS41::SET_SSV4res*) {}
    virtual void test_stateid41(const struct RPCProcedure*,
            const struct NFS41::TEST_STATEID4args*,
            const struct NFS41::TEST_STATEID4res*) {}
    virtual void want_delegation41(const struct RPCProcedure*,
            const struct NFS41::WANT_DELEGATION4args*,
            const struct NFS41::WANT_DELEGATION4res*) {}
    virtual void destroy_clientid41(const struct RPCProcedure*,
            const struct NFS41::DESTROY_CLIENTID4args*,
            const struct NFS41::DESTROY_CLIENTID4res*) {}
    virtual void reclaim_complete41(const struct RPCProcedure*,
            const struct NFS41::RECLAIM_COMPLETE4args*,
            const struct NFS41::RECLAIM_COMPLETE4res*) {}
    virtual void illegal41(const struct RPCProcedure*,
            const struct NFS41::ILLEGAL4res*) {}
};


class IAnalyzer : public INFSv3rpcgen, public INFSv4rpcgen, public INFSv41rpcgen
{
public:
    virtual ~IAnalyzer() {};
    virtual void flush_statistics() = 0;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//IANALYZER_TYPE_H
//------------------------------------------------------------------------------
