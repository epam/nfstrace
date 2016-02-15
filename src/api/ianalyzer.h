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
#include "cifs_types.h"
#include "nfs3_types_rpcgen.h"
#include "nfs41_types_rpcgen.h"
#include "nfs4_types_rpcgen.h"
#include "nfs_types.h"
#include "rpc_types.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{
/*! Abstract interface for plugins that collect NFS3 statistics
 */
class INFSv3rpcgen
{
public:
    virtual ~INFSv3rpcgen() {}
    // clang-format off
    /*! NFSv3 "NULL" procedure
     * \param RPCProcedure  - Specified procedure
     * \param NULL3args     - procedure arguments
     * \param NULL3res      - procedure results
     */ 
    virtual void null(const RPCProcedure*,
            const struct NFS3::NULL3args*,
            const struct NFS3::NULL3res*) {}

    /*! NFSv3 "GETATTR" procedure (Get file attributes)
     * \param RPCProcedure     - Specified procedure
     * \param GETATTR3args     - procedure arguments
     * \param GETATTR3res      - procedure results
     */
    virtual void getattr3(const RPCProcedure*,
            const struct NFS3::GETATTR3args*,
            const struct NFS3::GETATTR3res*) {}

    /*! NFSv3 "SETATTR" procedure (Set file attributes)
     * \param RPCProcedure     - Specified procedure
     * \param SETATTR3args     - procedure arguments
     * \param SETATTR3res      - procedure results
     */
    virtual void setattr3(const RPCProcedure*,
            const struct NFS3::SETATTR3args*,
            const struct NFS3::SETATTR3res*) {}

    /*! NFSv3 "LOOKUP" procedure (Lookup filename)
     * \param RPCProcedure    - Specified procedure
     * \param LOOKUP3args     - procedure arguments
     * \param LOOKUP3res      - procedure results
     */
    virtual void lookup3(const RPCProcedure*,
            const struct NFS3::LOOKUP3args*,
            const struct NFS3::LOOKUP3res*) {}

    /*! NFSv3 "ACCESS" procedure (Check Access Permission)
     * \param RPCProcedure    - Specified procedure
     * \param ACCESS3args     - procedure arguments
     * \param ACCESS3res      - procedure results
     */
    virtual void access3(const RPCProcedure*,
            const struct NFS3::ACCESS3args*,
            const struct NFS3::ACCESS3res*) {}

    /*! NFSv3 "READLINK" procedure (Read from symbolic link)
     * \param RPCProcedure      - Specified procedure
     * \param READLINK3args     - procedure arguments
     * \param READLINK3res      - procedure results
     */
    virtual void readlink3(const RPCProcedure*,
            const struct NFS3::READLINK3args*,
            const struct NFS3::READLINK3res*) {}

    /*! NFSv3 "READ" procedure (Read from file)
     * \param RPCProcedure  - Specified procedure
     * \param READ3args     - procedure arguments
     * \param READ3res      - procedure results
     */
    virtual void read3(const RPCProcedure*,
            const struct NFS3::READ3args*,
            const struct NFS3::READ3res*) {}

    /*! NFSv3 "WRITE" procedure (Write to file)
     * \param RPCProcedure   - Specified procedure
     * \param WRITE3args     - procedure arguments
     * \param WRITE3res      - procedure results
     */
    virtual void write3(const RPCProcedure*,
            const struct NFS3::WRITE3args*,
            const struct NFS3::WRITE3res*) {}

    /*! NFSv3 "CREATE" procedure (Create a file)
     * \param RPCProcedure    - Specified procedure
     * \param CREATE3args     - procedure arguments
     * \param CREATE3res      - procedure results
     */
    virtual void create3(const RPCProcedure*,
            const struct NFS3::CREATE3args*,
            const struct NFS3::CREATE3res*) {}

    /*! NFSv3 "MKDIR" procedure (Create a directory)
     * \param RPCProcedure   - Specified procedure
     * \param MKDIR3args     - procedure arguments
     * \param MKDIR3res      - procedure results
     */
    virtual void mkdir3(const RPCProcedure*,
            const struct NFS3::MKDIR3args*,
            const struct NFS3::MKDIR3res*) {}

    /*! NFSv3 "SYMLINK" procedure (Create a symbolic link)
     * \param RPCProcedure     - Specified procedure
     * \param SYMLINK3args     - procedure arguments
     * \param SYMLINK3res      - procedure results
     */
    virtual void symlink3(const RPCProcedure*,
            const struct NFS3::SYMLINK3args*,
            const struct NFS3::SYMLINK3res*) {}

    /*! NFSv3 "MKNOD" procedure (Create a special device)
     * \param RPCProcedure   - Specified procedure
     * \param MKNOD3args     - procedure arguments
     * \param MKNOD3res      - procedure results
     */
    virtual void mknod3(const RPCProcedure*,
            const struct NFS3::MKNOD3args*,
            const struct NFS3::MKNOD3res*) {}

    /*! NFSv3 "REMOVE" procedure (Remove a file)
     * \param RPCProcedure    - Specified procedure
     * \param REMOVE3args     - procedure arguments
     * \param REMOVE3res      - procedure results
     */
    virtual void remove3(const RPCProcedure*,
            const struct NFS3::REMOVE3args*,
            const struct NFS3::REMOVE3res*) {}

    /*! NFSv3 "RMDIR" procedure (Remove a directory)
     * \param RPCProcedure   - Specified procedure
     * \param RMDIR3args     - procedure arguments
     * \param RMDIR3res      - procedure results
     */
    virtual void rmdir3(const RPCProcedure*,
            const struct NFS3::RMDIR3args*,
            const struct NFS3::RMDIR3res*) {}

    /*! NFSv3 "RENAME" procedure (Rename a file or directory)
     * \param RPCProcedure    - Specified procedure
     * \param RENAME3args     - procedure arguments
     * \param RENAME3res      - procedure results
     */
    virtual void rename3(const RPCProcedure*,
            const struct NFS3::RENAME3args*,
            const struct NFS3::RENAME3res*) {}

    /*! NFSv3 "LINK" procedure (Create link to an object)
     * \param RPCProcedure  - Specified procedure
     * \param LINK3args     - procedure arguments
     * \param LINK3res      - procedure results
     */
    virtual void link3(const RPCProcedure*,
            const struct NFS3::LINK3args*,
            const struct NFS3::LINK3res*) {}

    /*! NFSv3 "READDIR" procedure (Read From directory)
     * \param RPCProcedure     - Specified procedure
     * \param READDIR3args     - procedure arguments
     * \param READDIR3res      - procedure results
     */
    virtual void readdir3(const RPCProcedure*,
            const struct NFS3::READDIR3args*,
            const struct NFS3::READDIR3res*) {}

    /*! NFSv3 "READDIRPLUS" procedure (Extended read from directory)
     * \param RPCProcedure         - Specified procedure
     * \param READDIRPLUS3args     - procedure arguments
     * \param READDIRPLUS3res      - procedure results
     */
    virtual void readdirplus3(const RPCProcedure*,
            const struct NFS3::READDIRPLUS3args*,
            const struct NFS3::READDIRPLUS3res*) {}

    /*! NFSv3 "FSSTAT" procedure (Get dynamic file system information)
     * \param RPCProcedure    - Specified procedure
     * \param FSSTAT3args     - procedure arguments
     * \param FSSTAT3res      - procedure results
     */
    virtual void fsstat3(const RPCProcedure*,
            const struct NFS3::FSSTAT3args*,
            const struct NFS3::FSSTAT3res*) {}

    /*! NFSv3 "FSINFO" procedure (Get static file system information)
     * \param RPCProcedure    - Specified procedure
     * \param FSINFO3args     - procedure arguments
     * \param FSINFO3res      - procedure results
     */
    virtual void fsinfo3(const RPCProcedure*,
            const struct NFS3::FSINFO3args*,
            const struct NFS3::FSINFO3res*) {}

    /*! NFSv3 "PATHINFO" procedure (Retrieve POSIX information)
     * \param RPCProcedure      - Specified procedure
     * \param PATHINFO3args     - procedure arguments
     * \param PATHINFO3res      - procedure results
     */
    virtual void pathconf3(const RPCProcedure*,
            const struct NFS3::PATHCONF3args*,
            const struct NFS3::PATHCONF3res*) {}

    /*! NFSv3 "COMMIT" procedure (Commit cached data on a server to stable storage)
     * \param RPCProcedure    - Specified procedure
     * \param COMMIT3args     - procedure arguments
     * \param COMMIT3res      - procedure results
     */
    virtual void commit3(const RPCProcedure*,
            const struct NFS3::COMMIT3args*,
            const struct NFS3::COMMIT3res*) {}
};

/*! Abstract interface for plugins that collect NFS4 statistics
 */
class INFSv4rpcgen
{
public:
    virtual ~INFSv4rpcgen() {}
    /*! NFSv4 "NULL" procedure (No Operation)
     * \param RPCProcedure  - Specified procedure
     * \param NULL4args     - procedure arguments
     * \param NULL4res      - procedure results
     */
    virtual void null4(const RPCProcedure*,
            const struct NFS4::NULL4args*,
            const struct NFS4::NULL4res*) {}

    /*! NFSv4 "COMPOUND" procedure (Compound Operations)
     * \param RPCProcedure  - Specified procedure
     * \param COMPOUND4args - procedure arguments
     * \param COMPOUND4res  - procedure results
     */
    virtual void compound4(const RPCProcedure*,
            const struct NFS4::COMPOUND4args*,
            const struct NFS4::COMPOUND4res*) {}

    /*! NFSv4 "ACCESS" operation (Check Access Rights)
     * \param RPCProcedure    - Specified operation
     * \param ACCESS4args     - operation arguments
     * \param ACCESS4res      - operation results
     */
    virtual void access40(const RPCProcedure*,
            const struct NFS4::ACCESS4args*,
            const struct NFS4::ACCESS4res*) {}

    /*! NFSv4 "CLOSE" operation (Close File)
     * \param RPCProcedure   - Specified operation
     * \param CLOSE4args     - operation arguments
     * \param CLOSE4res      - operation results
     */
    virtual void close40(const RPCProcedure*,
            const struct NFS4::CLOSE4args*,
            const struct NFS4::CLOSE4res*) {}

    /*! NFSv4 "COMMIT" operation (Commit Cached Data)
     * \param RPCProcedure    - Specified operation
     * \param COMMIT4args     - operation arguments
     * \param COMMIT4res      - operation results
     */
    virtual void commit40(const RPCProcedure*,
            const struct NFS4::COMMIT4args*,
            const struct NFS4::COMMIT4res*) {}

    /*! NFSv4 "CREATE" operation (Create a Non-Regular File Object)
     * \param RPCProcedure    - Specified operation
     * \param CREATE4args     - operation arguments
     * \param CREATE4res      - operation results
     */
    virtual void create40(const RPCProcedure*,
            const struct NFS4::CREATE4args*,
            const struct NFS4::CREATE4res*) {}

    /*! NFSv4 "DELEGPURGE" operation (Purge Delegations Awaiting Recovery)
     * \param RPCProcedure        - Specified operation
     * \param DELEGPURGE4args     - operation arguments
     * \param DELEGPURGE4res      - operation results
     */
    virtual void delegpurge40(const RPCProcedure*,
            const struct NFS4::DELEGPURGE4args*,
            const struct NFS4::DELEGPURGE4res*) {}

    /*! NFSv4 "DELEGRETURN" operation (Return Delegation)
     * \param RPCProcedure        - Specified operation
     * \param DELEGRETURN4args    - operation arguments
     * \param DELEGRETUR4res      - operation results
     */
    virtual void delegreturn40(const RPCProcedure*,
            const struct NFS4::DELEGRETURN4args*,
            const struct NFS4::DELEGRETURN4res*) {}

    /*! NFSv4 "GETATTR" operation (Get Attributes)
     * \param RPCProcedure     - Specified operation
     * \param GETATTR4args     - operation arguments
     * \param GETATTR4res      - operation results
     */
    virtual void getattr40(const RPCProcedure*,
            const struct NFS4::GETATTR4args*,
            const struct NFS4::GETATTR4res*) {}

    /*! NFSv4 "GETFH" operation (Get Current Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param GETFH4res     - operation results
     */
    virtual void getfh40(const RPCProcedure*,
            const struct NFS4::GETFH4res*) {}

    /*! NFSv4 "LINK" operation (Create Link to a File)
     * \param RPCProcedure  - Specified operation
     * \param LINK4args     - operation arguments
     * \param LINK4res      - operation results
     */
    virtual void link40(const RPCProcedure*,
            const struct NFS4::LINK4args*,
            const struct NFS4::LINK4res*) {}

    /*! NFSv4 "LOCK" operation (Create Lock)
     * \param RPCProcedure  - Specified operation
     * \param LOCK4args     - operation arguments
     * \param LOCK4res      - operation results
     */
    virtual void lock40(const RPCProcedure*,
            const struct NFS4::LOCK4args*,
            const struct NFS4::LOCK4res*) {}

    /*! NFSv4 "LOCKT" operation (Test For Lock)
     * \param RPCProcedure   - Specified operation
     * \param LOCKT4args     - operation arguments
     * \param LOCKT4res      - operation results
     */
    virtual void lockt40(const RPCProcedure*,
            const struct NFS4::LOCKT4args*,
            const struct NFS4::LOCKT4res*) {}

    /*! NFSv4 "LOCKU" operation (Unlock File)
     * \param RPCProcedure  - Specified operation
     * \param LOCKUargs     - operation arguments
     * \param LOCKUres      - operation results
     */
    virtual void locku40(const RPCProcedure*,
            const struct NFS4::LOCKU4args*,
            const struct NFS4::LOCKU4res*) {}

    /*! NFSv4 "LOCKUP" operation (Lookup Filename)
     * \param RPCProcedure  - Specified operation
     * \param LOCKUP4args   - operation arguments
     * \param LOCKUP4res    - operation results
     */
    virtual void lookup40(const RPCProcedure*,
            const struct NFS4::LOOKUP4args*,
            const struct NFS4::LOOKUP4res*) {}

    /*! NFSv4 "LOCKUPP" operation (Lookup Parent Directory)
     * \param RPCProcedure  - Specified operation
     * \param LOCKUPP4res   - operation results
     */ 
    virtual void lookupp40(const RPCProcedure*,
            const struct NFS4::LOOKUPP4res*) {}

    /*! NFSv4 "NVERIFY" operation (Verify Difference in Attributes)
     * \param RPCProcedure  - Specified operation
     * \param NVERIFY4args  - operation arguments
     * \param NVERIFY4res   - operation results
     */
    virtual void nverify40(const RPCProcedure*,
            const struct NFS4::NVERIFY4args*,
            const struct NFS4::NVERIFY4res*) {}

    /*! NFSv4 "OPEN" operation (Open a Regular File)
     * \param RPCProcedure  - Specified operation
     * \param OPEN4args     - operation arguments
     * \param OPEN4res      - operation results
     */
    virtual void open40(const RPCProcedure*,
            const struct NFS4::OPEN4args*,
            const struct NFS4::OPEN4res*) {}

    /*! NFSv4 "OPENATTR" operation (Open Named Attribute Directory)
     * \param RPCProcedure  - Specified operation
     * \param OPENATTR4args - operation arguments
     * \param OPENATTR4res  - operation results
     */
    virtual void openattr40(const RPCProcedure*,
            const struct NFS4::OPENATTR4args*,
            const struct NFS4::OPENATTR4res*) {}

    /*! NFSv4 "OPEN_CONFIRM" operation (Confirm Open)
     * \param RPCProcedure          - Specified operation
     * \param OPEN_CONFIRM4args     - operation arguments
     * \param OPEN_CONFIRM4NULL3res - operation results
     */
    virtual void open_confirm40(const RPCProcedure*,
            const struct NFS4::OPEN_CONFIRM4args*,
            const struct NFS4::OPEN_CONFIRM4res*) {}

    /*! NFSv4 "OPEN_DOWNGRADE" operation (Reduce Open File Access)
     * \param RPCProcedure           - Specified operation
     * \param OPEN_DOWNGRADE4args    - operation arguments
     * \param OPEN_DOWNGRADE4res     - operation results
     */
    virtual void open_downgrade40(const RPCProcedure*,
            const struct NFS4::OPEN_DOWNGRADE4args*,
            const struct NFS4::OPEN_DOWNGRADE4res*) {}

    /*! NFSv4 "PUTFH" operation (Set Current Filehandle)
     * \param RPCProcedure   - Specified operation
     * \param PUTFH4args     - operation arguments
     * \param PUTFH4res      - operation results
     */
    virtual void putfh40(const RPCProcedure*,
            const struct NFS4::PUTFH4args*,
            const struct NFS4::PUTFH4res*) {}

    /*! NFSv4 "PUTPUBFH" operation (Set Public Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param PUTPUBFH4res  - operation results
     */
    virtual void putpubfh40(const RPCProcedure*,
            const struct NFS4::PUTPUBFH4res*) {}

    /*! NFSv4 "PUTROOTFH" operation (Set Root Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param PUTROOTFHargs - operation arguments
     * \param PUTROOTFHres  - operation results
     */
    virtual void putrootfh40(const RPCProcedure*,
            const struct NFS4::PUTROOTFH4res*) {}

    /*! NFSv4 "READ" operation (Read from File)
     * \param RPCProcedure  - Specified operation
     * \param READ4args     - operation arguments
     * \param READ4res      - operation results
     */
    virtual void read40(const RPCProcedure*,
            const struct NFS4::READ4args*,
            const struct NFS4::READ4res*) {}

    /*! NFSv4 "READDIR" operation (Read Directory)
     * \param RPCProcedure  - Specified operation
     * \param READDIR4args  - operation arguments
     * \param READDIR4res   - operation results
     */
    virtual void readdir40(const RPCProcedure*,
            const struct NFS4::READDIR4args*,
            const struct NFS4::READDIR4res*) {}

    /*! NFSv4 "READLINK" operation (Read Symbolic Link)
     * \param RPCProcedure  - Specified operation
     * \param READLINK4res  - operation results
     */
    virtual void readlink40(const RPCProcedure*,
            const struct NFS4::READLINK4res*) {}

    /*! NFSv4 "REMOVE" operation (Remove Filesystem Object)
     * \param RPCProcedure  - Specified operation
     * \param REMOVE4args   - operation arguments
     * \param REMOVE4res    - operation results
     */
    virtual void remove40(const RPCProcedure*,
            const struct NFS4::REMOVE4args*,
            const struct NFS4::REMOVE4res*) {}

    /*! NFSv4 "RENAME" operation (Rename Directory Entry)
     * \param RPCProcedure  - Specified operation
     * \param RENAME4args   - operation arguments
     * \param RENAME4res    - operation results
     */
    virtual void rename40(const RPCProcedure*,
            const struct NFS4::RENAME4args*,
            const struct NFS4::RENAME4res*) {}

    /*! NFSv4 "RENEW" operation (Renew a Lease)
     * \param RPCProcedure - Specified operation
     * \param RENEW4args   - operation arguments
     * \param RENEW4res    - operation results
     */
    virtual void renew40(const RPCProcedure*,
            const struct NFS4::RENEW4args*,
            const struct NFS4::RENEW4res*) {}

    /*! NFSv4 "RESTOREFH" operation (Restore Saved Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param RESTOREFH4res - operation results
     */
    virtual void restorefh40(const RPCProcedure*,
            const struct NFS4::RESTOREFH4res*) {}

    /*! NFSv4 "SAVEFH" operation (Save Current Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param SAVEFH4res    - operation results
     */
    virtual void savefh40(const RPCProcedure*,
            const struct NFS4::SAVEFH4res*) {}

    /*! NFSv4 "SECINFO" operation (Obtain Available Security)
     * \param RPCProcedure  - Specified operation
     * \param SECINFO4args  - operation arguments
     * \param SECINFO4res   - operation results
     */
    virtual void secinfo40(const RPCProcedure*,
            const struct NFS4::SECINFO4args*,
            const struct NFS4::SECINFO4res*) {}

    /*! NFSv4 "SETATTR" operation (Set Attributes)
     * \param RPCProcedure  - Specified operation
     * \param SETATTR4args  - operation arguments
     * \param SETATTR4res   - operation results
     */
    virtual void setattr40(const RPCProcedure*,
            const struct NFS4::SETATTR4args*,
            const struct NFS4::SETATTR4res*) {}

    /*! NFSv4 "SETCLIENTID" operation (Negotiate Clientid)
     * \param RPCProcedure         - Specified operation
     * \param SETCLIENTID4args     - operation arguments
     * \param SETCLIENTID4res      - operation results
     */
    virtual void setclientid40(const RPCProcedure*,
            const struct NFS4::SETCLIENTID4args*,
            const struct NFS4::SETCLIENTID4res*) {}

    /*! NFSv4 "SETCLIENTID_CONFIRM" operation
     * \param RPCProcedure                 - Specified operation
     * \param SETCLIENTID_CONFIRM4args     - operation arguments
     * \param SETCLIENTID_CONFIRM4res      - operation results
     */
    virtual void setclientid_confirm40(const RPCProcedure*,
            const struct NFS4::SETCLIENTID_CONFIRM4args*,
            const struct NFS4::SETCLIENTID_CONFIRM4res*) {}

    /*! NFSv4 "VERIFY" operation (Verify Same Attributes)
     * \param RPCProcedure    - Specified operation
     * \param VERIFY4args     - operation arguments
     * \param VERIFY4res      - operation results
     */
    virtual void verify40(const RPCProcedure*,
            const struct NFS4::VERIFY4args*,
            const struct NFS4::VERIFY4res*) {}

    /*! NFSv4 "WRITE" operation (Write to File)
     * \param RPCProcedure   - Specified operation
     * \param WRITE4args     - operation arguments
     * \param WRITE4res      - operation results
     */
    virtual void write40(const RPCProcedure*,
            const struct NFS4::WRITE4args*,
            const struct NFS4::WRITE4res*) {}

    /*! NFSv4 "RELEASE_LOCKOWNER" operation (Release Lockowner State)
     * \param RPCProcedure              - Specified operation
     * \param RELEASE_LOCKOWNER4args    - operation arguments
     * \param RELEASE_LOCKOWNER4res     - operation results
     */
    virtual void release_lockowner40(const RPCProcedure*,
            const struct NFS4::RELEASE_LOCKOWNER4args*,
            const struct NFS4::RELEASE_LOCKOWNER4res*) {}

    /*! NFSv4 "GET_DIR_DELEGATION" operation (No Operation)
     * \param RPCProcedure                - Specified operation
     * \param GET_DIR_DELEGATION4args     - operation arguments
     * \param GET_DIR_DELEGATION4res      - operation results
     */
    virtual void get_dir_delegation40(const RPCProcedure*,
            const struct NFS4::GET_DIR_DELEGATION4args*,
            const struct NFS4::GET_DIR_DELEGATION4res*) {}

    /*! NFSv4 "ILLEGAL" operation (Illegal operation)
     * \param RPCProcedure  - Specified operation
     * \param ILLEGAL4res   - operation results
     */
    virtual void illegal40(const RPCProcedure*,
            const struct NFS4::ILLEGAL4res*) {}
};

/*! Abstract interface for plugins that collect NFS41 statistics
 */
class INFSv41rpcgen
{
public:
    virtual ~INFSv41rpcgen() {}
    //there is no null41 procedure, use null if needed: IAnalyzer::INFSv4rpcgen::null
    
    /*! NFSv41 "COMPOUND" procedure (Compound Operations)
     * \param RPCProcedure  - Specified procedure
     * \param COMPOUND4args - procedure arguments
     * \param COMPOUND4res  - procedure results
     */
    virtual void compound41(const RPCProcedure*,
            const struct NFS41::COMPOUND4args*,
            const struct NFS41::COMPOUND4res*) {}

    /*! NFSv41 "ACCESS" operation (Check Access Rights)
     * \param RPCProcedure    - Specified operation
     * \param ACCESS4args     - operation arguments
     * \param ACCESS4res      - operation results
     */
    virtual void access41(const RPCProcedure*,
            const struct NFS41::ACCESS4args*,
            const struct NFS41::ACCESS4res*) {}

    /*! NFSv41 "CLOSE" operation (Close File)
     * \param RPCProcedure   - Specified operation
     * \param CLOSE4args     - operation arguments
     * \param CLOSE4res      - operation results
     */
    virtual void close41(const RPCProcedure*,
            const struct NFS41::CLOSE4args*,
            const struct NFS41::CLOSE4res*) {}

    /*! NFSv41 "COMMIT" operation (Commit Cached Data)
     * \param RPCProcedure    - Specified operation
     * \param COMMIT4args     - operation arguments
     * \param COMMIT4res      - operation results
     */
    virtual void commit41(const RPCProcedure*,
            const struct NFS41::COMMIT4args*,
            const struct NFS41::COMMIT4res*) {}

    /*! NFSv41 "CREATE" operation (Create a Non-Regular File Object)
     * \param RPCProcedure    - Specified operation
     * \param CREATE4args     - operation arguments
     * \param CREATE4res      - operation results
     */
    virtual void create41(const RPCProcedure*,
            const struct NFS41::CREATE4args*,
            const struct NFS41::CREATE4res*) {}

    /*! NFSv41 "DELEGPURGE" operation (Purge Delegations Awaiting Recovery)
     * \param RPCProcedure        - Specified operation
     * \param DELEGPURGE4args     - operation arguments
     * \param DELEGPURGE4res      - operation results
     */
    virtual void delegpurge41(const RPCProcedure*,
            const struct NFS41::DELEGPURGE4args*,
            const struct NFS41::DELEGPURGE4res*) {}

    /*! NFSv41 "DELEGRETURN" operation (Return Delegation)
     * \param RPCProcedure        - Specified operation
     * \param DELEGRETURN4args    - operation arguments
     * \param DELEGRETUR4res      - operation results
     */
    virtual void delegreturn41(const RPCProcedure*,
            const struct NFS41::DELEGRETURN4args*,
            const struct NFS41::DELEGRETURN4res*) {}

    /*! NFSv41 "GETATTR" operation (Get Attributes)
     * \param RPCProcedure     - Specified operation
     * \param GETATTR4args     - operation arguments
     * \param GETATTR4res      - operation results
     */
    virtual void getattr41(const RPCProcedure*,
            const struct NFS41::GETATTR4args*,
            const struct NFS41::GETATTR4res*) {}

    /*! NFSv41 "GETFH" operation (Get Current Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param GETFH4res     - operation results
     */
    virtual void getfh41(const RPCProcedure*,
            const struct NFS41::GETFH4res*) {}

    /*! NFSv41 "LINK" operation (Create Link to a File)
     * \param RPCProcedure  - Specified operation
     * \param LINK4args     - operation arguments
     * \param LINK4res      - operation results
     */
    virtual void link41(const RPCProcedure*,
            const struct NFS41::LINK4args*,
            const struct NFS41::LINK4res*) {}

    /*! NFSv41 "LOCK" operation (Create Lock)
     * \param RPCProcedure  - Specified operation
     * \param LOCK4args     - operation arguments
     * \param LOCK4res      - operation results
     */
    virtual void lock41(const RPCProcedure*,
            const struct NFS41::LOCK4args*,
            const struct NFS41::LOCK4res*) {}

    /*! NFSv41 "LOCKT" operation (Test For Lock)
     * \param RPCProcedure   - Specified operation
     * \param LOCKT4args     - operation arguments
     * \param LOCKT4res      - operation results
     */
    virtual void lockt41(const RPCProcedure*,
            const struct NFS41::LOCKT4args*,
            const struct NFS41::LOCKT4res*) {}

    /*! NFSv41 "LOCKU" operation (Unlock File)
     * \param RPCProcedure  - Specified operation
     * \param LOCKUargs     - operation arguments
     * \param LOCKUres      - operation results
     */
    virtual void locku41(const RPCProcedure*,
            const struct NFS41::LOCKU4args*,
            const struct NFS41::LOCKU4res*) {}

    /*! NFSv41 "LOCKUP" operation (Lookup Filename)
     * \param RPCProcedure  - Specified operation
     * \param LOCKUP4args   - operation arguments
     * \param LOCKUP4res    - operation results
     */
    virtual void lookup41(const RPCProcedure*,
            const struct NFS41::LOOKUP4args*,
            const struct NFS41::LOOKUP4res*) {}

    /*! NFSv41 "LOCKUPP" operation (Lookup Parent Directory)
     * \param RPCProcedure  - Specified operation
     * \param LOCKUPP4res   - operation results
     */ 
    virtual void lookupp41(const RPCProcedure*,
            const struct NFS41::LOOKUPP4res*) {}

    /*! NFSv41 "NVERIFY" operation (Verify Difference in Attributes)
     * \param RPCProcedure  - Specified operation
     * \param NVERIFY4args  - operation arguments
     * \param NVERIFY4res   - operation results
     */
    virtual void nverify41(const RPCProcedure*,
            const struct NFS41::NVERIFY4args*,
            const struct NFS41::NVERIFY4res*) {}

    /*! NFSv41 "OPEN" operation (Open a Regular File)
     * \param RPCProcedure  - Specified operation
     * \param OPEN4args     - operation arguments
     * \param OPEN4res      - operation results
     */
    virtual void open41(const RPCProcedure*,
            const struct NFS41::OPEN4args*,
            const struct NFS41::OPEN4res*) {}

    /*! NFSv41 "OPENATTR" operation (Open Named Attribute Directory)
     * \param RPCProcedure  - Specified operation
     * \param OPENATTR4args - operation arguments
     * \param OPENATTR4res  - operation results
     */
    virtual void openattr41(const RPCProcedure*,
            const struct NFS41::OPENATTR4args*,
            const struct NFS41::OPENATTR4res*) {}

    /*! NFSv41 "OPEN_CONFIRM" operation (Confirm Open)
     * \param RPCProcedure          - Specified operation
     * \param OPEN_CONFIRM4args     - operation arguments
     * \param OPEN_CONFIRM4NULL3res - operation results
     */
    virtual void open_confirm41(const RPCProcedure*,
            const struct NFS41::OPEN_CONFIRM4args*,
            const struct NFS41::OPEN_CONFIRM4res*) {}

    /*! NFSv41 "OPEN_DOWNGRADE" operation (Reduce Open File Access)
     * \param RPCProcedure           - Specified operation
     * \param OPEN_DOWNGRADE4args    - operation arguments
     * \param OPEN_DOWNGRADE4res     - operation results
     */
    virtual void open_downgrade41(const RPCProcedure*,
            const struct NFS41::OPEN_DOWNGRADE4args*,
            const struct NFS41::OPEN_DOWNGRADE4res*) {}

    /*! NFSv41 "PUTFH" operation (Set Current Filehandle)
     * \param RPCProcedure   - Specified operation
     * \param PUTFH4args     - operation arguments
     * \param PUTFH4res      - operation results
     */
    virtual void putfh41(const RPCProcedure*,
            const struct NFS41::PUTFH4args*,
            const struct NFS41::PUTFH4res*) {}

    /*! NFSv41 "PUTPUBFH" operation (Set Public Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param PUTPUBFH4res  - operation results
     */
    virtual void putpubfh41(const RPCProcedure*,
            const struct NFS41::PUTPUBFH4res*) {}

    /*! NFSv41 "PUTROOTFH" operation (Set Root Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param PUTROOTFHargs - operation arguments
     * \param PUTROOTFHres  - operation results
     */
    virtual void putrootfh41(const RPCProcedure*,
            const struct NFS41::PUTROOTFH4res*) {}

    /*! NFSv41 "READ" operation (Read from File)
     * \param RPCProcedure  - Specified operation
     * \param READ4args     - operation arguments
     * \param READ4res      - operation results
     */
    virtual void read41(const RPCProcedure*,
            const struct NFS41::READ4args*,
            const struct NFS41::READ4res*) {}

    /*! NFSv41 "READDIR" operation (Read Directory)
     * \param RPCProcedure  - Specified operation
     * \param READDIR4args  - operation arguments
     * \param READDIR4res   - operation results
     */
    virtual void readdir41(const RPCProcedure*,
            const struct NFS41::READDIR4args*,
            const struct NFS41::READDIR4res*) {}

    /*! NFSv41 "READLINK" operation (Read Symbolic Link)
     * \param RPCProcedure  - Specified operation
     * \param READLINK4res  - operation results
     */
    virtual void readlink41(const RPCProcedure*,
            const struct NFS41::READLINK4res*) {}

    /*! NFSv41 "REMOVE" operation (Remove Filesystem Object)
     * \param RPCProcedure  - Specified operation
     * \param REMOVE4args   - operation arguments
     * \param REMOVE4res    - operation results
     */
    virtual void remove41(const RPCProcedure*,
            const struct NFS41::REMOVE4args*,
            const struct NFS41::REMOVE4res*) {}

    /*! NFSv41 "RENAME" operation (Rename Directory Entry)
     * \param RPCProcedure  - Specified operation
     * \param RENAME4args   - operation arguments
     * \param RENAME4res    - operation results
     */
    virtual void rename41(const RPCProcedure*,
            const struct NFS41::RENAME4args*,
            const struct NFS41::RENAME4res*) {}

    /*! NFSv41 "RENEW" operation (Renew a Lease)
     * \param RPCProcedure - Specified operation
     * \param RENEW4args   - operation arguments
     * \param RENEW4res    - operation results
     */
    virtual void renew41(const RPCProcedure*,
            const struct NFS41::RENEW4args*,
            const struct NFS41::RENEW4res*) {}

    /*! NFSv41 "RESTOREFH" operation (Restore Saved Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param RESTOREFH4res      - operation results
     */
    virtual void restorefh41(const RPCProcedure*,
            const struct NFS41::RESTOREFH4res*) {}

    /*! NFSv41 "SAVEFH" operation (Save Current Filehandle)
     * \param RPCProcedure  - Specified operation
     * \param SAVEFH4res    - operation results
     */
    virtual void savefh41(const RPCProcedure*,
            const struct NFS41::SAVEFH4res*) {}

    /*! NFSv41 "SECINFO" operation (Obtain Available Security)
     * \param RPCProcedure  - Specified operation
     * \param SECINFO4args  - operation arguments
     * \param SECINFO4res   - operation results
     */
    virtual void secinfo41(const RPCProcedure*,
            const struct NFS41::SECINFO4args*,
            const struct NFS41::SECINFO4res*) {}

    /*! NFSv41 "SETATTR" operation (Set Attributes)
     * \param RPCProcedure  - Specified operation
     * \param SETATTR4args  - operation arguments
     * \param SETATTR4res   - operation results
     */
    virtual void setattr41(const RPCProcedure*,
            const struct NFS41::SETATTR4args*,
            const struct NFS41::SETATTR4res*) {}

    /*! NFSv41 "SETCLIENTID" operation (Negotiate Clientid)
     * \param RPCProcedure         - Specified operation
     * \param SETCLIENTID4args     - operation arguments
     * \param SETCLIENTID4res      - operation results
     */
    virtual void setclientid41(const RPCProcedure*,
            const struct NFS41::SETCLIENTID4args*,
            const struct NFS41::SETCLIENTID4res*) {}

    /*! NFSv41 "SETCLIENTID_CONFIRM" operation
     * \param RPCProcedure                 - Specified operation
     * \param SETCLIENTID_CONFIRM4args     - operation arguments
     * \param SETCLIENTID_CONFIRM4res      - operation results
     */
    virtual void setclientid_confirm41(const RPCProcedure*,
            const struct NFS41::SETCLIENTID_CONFIRM4args*,
            const struct NFS41::SETCLIENTID_CONFIRM4res*) {}

    /*! NFSv41 "VERIFY" operation (Verify Same Attributes)
     * \param RPCProcedure    - Specified operation
     * \param VERIFY4args     - operation arguments
     * \param VERIFY4res      - operation results
     */
    virtual void verify41(const RPCProcedure*,
            const struct NFS41::VERIFY4args*,
            const struct NFS41::VERIFY4res*) {}

    /*! NFSv41 "WRITE" operation (Write to File)
     * \param RPCProcedure  - Specified operation
     * \param WRITE4args    - operation arguments
     * \param WRITE4res     - operation results
     */
    virtual void write41(const RPCProcedure*,
            const struct NFS41::WRITE4args*,
            const struct NFS41::WRITE4res*) {}

    /*! NFSv41 "RELEASE_LOCKOWNER" operation
     * \param RPCProcedure           - Specified operation
     * \param RELEASE_LOCKOWNER4args - operation arguments
     * \param RELEASE_LOCKOWNER4res  - operation results
     */
    virtual void release_lockowner41(const RPCProcedure*,
            const struct NFS41::RELEASE_LOCKOWNER4args*,
            const struct NFS41::RELEASE_LOCKOWNER4res*) {}

    /*! NFSv41 "BACKCHANNEL_CTL" operation (Backchannel Control)
     * \param RPCProcedure         - Specified operation
     * \param BACKCHANNEL_CTL4args - operation arguments
     * \param BACKCHANNEL_CTL4res  - operation results
     */
    virtual void backchannel_ctl41(const RPCProcedure*,
            const struct NFS41::BACKCHANNEL_CTL4args*,
            const struct NFS41::BACKCHANNEL_CTL4res*) {}

    /*! NFSv41 "BIND_CONN_TO_SESSION" operation (Associate Connection with Session)
     * \param RPCProcedure              - Specified operation
     * \param BIND_CONN_TO_SESSION4args - operation arguments
     * \param BIND_CONN_TO_SESSION4res  - operation results
     */
    virtual void bind_conn_to_session41(const RPCProcedure*,
            const struct NFS41::BIND_CONN_TO_SESSION4args*,
            const struct NFS41::BIND_CONN_TO_SESSION4res*) {}

    /*! NFSv41 "EXCHANGE_ID" operation (Instantiate Client ID)
     * \param RPCProcedure     - Specified operation
     * \param EXCHANGE_ID4args - operation arguments
     * \param EXCHANGE_ID4res  - operation results
     */
    virtual void exchange_id41(const RPCProcedure*,
            const struct NFS41::EXCHANGE_ID4args*,
            const struct NFS41::EXCHANGE_ID4res*) {}

    /*! NFSv41 "CREATE_SESSION" operation (Create New Session and Confirm Client ID)
     * \param RPCProcedure        - Specified operation
     * \param CREATE_SESSION4args - operation arguments
     * \param CREATE_SESSION4res  - operation results
     */
    virtual void create_session41(const RPCProcedure*,
            const struct NFS41::CREATE_SESSION4args*,
            const struct NFS41::CREATE_SESSION4res*) {}

    /*! NFSv41 "DESTROY_SESSION" operation (Destroy a Session)
     * \param RPCProcedure         - Specified operation
     * \param DESTROY_SESSION4args - operation arguments
     * \param DESTROY_SESSION4res  - operation results
     */
    virtual void destroy_session41(const RPCProcedure*,
            const struct NFS41::DESTROY_SESSION4args*,
            const struct NFS41::DESTROY_SESSION4res*) {}

    /*! NFSv41 "FREE_STATEID" operation (Free Stateid with No Locks)
     * \param RPCProcedure  - Specified operation
     * \param FREE_STATEID4args - operation arguments
     * \param FREE_STATEID4res  - operation results
     */
    virtual void free_stateid41(const RPCProcedure*,
            const struct NFS41::FREE_STATEID4args*,
            const struct NFS41::FREE_STATEID4res*) {}

    /*! NFSv41 "GET_DIR_DELEGATION" operation (Get a Directory Delegation)
     * \param RPCProcedure  - Specified operation
     * \param GET_DIR_DELEGATION4args - operation arguments
     * \param GET_DIR_DELEGATION4res  - operation results
     */
    virtual void get_dir_delegation41(const RPCProcedure*,
            const struct NFS41::GET_DIR_DELEGATION4args*,
            const struct NFS41::GET_DIR_DELEGATION4res*) {}

    /*! NFSv41 "GETDEVICEINFO" operation (Get Device Information)
     * \param RPCProcedure       - Specified operation
     * \param GETDEVICEINFO4args - operation arguments
     * \param GETDEVICEINFO4res  - operation results
     */
    virtual void getdeviceinfo41(const RPCProcedure*,
            const struct NFS41::GETDEVICEINFO4args*,
            const struct NFS41::GETDEVICEINFO4res*) {}

    /*! NFSv41 "GETDEVICELIST" operation (Get All Device Mappings for a File System)
     * \param RPCProcedure       - Specified operation
     * \param GETDEVICELIST4args - operation arguments
     * \param GETDEVICELIST4res  - operation results
     */
    virtual void getdevicelist41(const RPCProcedure*,
            const struct NFS41::GETDEVICELIST4args*,
            const struct NFS41::GETDEVICELIST4res*) {}

    /*! NFSv41 "LAYOUTCOMMIT" operation (Commit Writes Made Using a Layout)
     * \param RPCProcedure      - Specified operation
     * \param LAYOUTCOMMIT4args - operation arguments
     * \param LAYOUTCOMMIT4res  - operation results
     */
    virtual void layoutcommit41(const RPCProcedure*,
            const struct NFS41::LAYOUTCOMMIT4args*,
            const struct NFS41::LAYOUTCOMMIT4res*) {}

    /*! NFSv41 "LAYOUTGET" operation (Get Layout Information)
     * \param RPCProcedure   - Specified operation
     * \param LAYOUTGET4args - operation arguments
     * \param LAYOUTGET4res  - operation results
     */
    virtual void layoutget41(const RPCProcedure*,
            const struct NFS41::LAYOUTGET4args*,
            const struct NFS41::LAYOUTGET4res*) {}

    /*! NFSv41 "LAYOUTRETURN" operation (Release Layout Information)
     * \param RPCProcedure      - Specified operation
     * \param LAYOUTRETURN4args - operation arguments
     * \param LAYOUTRETURN4res  - operation results
     */
    virtual void layoutreturn41(const RPCProcedure*,
            const struct NFS41::LAYOUTRETURN4args*,
            const struct NFS41::LAYOUTRETURN4res*) {}

    /*! NFSv41 "SECINFO_NO_NAME" operation (Get Security on Unnamed Object)
     * \param RPCProcedure         - Specified operation
     * \param SECINFO_NO_NAME4args - operation arguments
     * \param SECINFO_NO_NAME4res  - operation results
     */
    virtual void secinfo_no_name41(const RPCProcedure*,
            const NFS41::SECINFO_NO_NAME4args*,
            const NFS41::SECINFO_NO_NAME4res*) {}

    /*! NFSv41 "SEQUENCE" operation (Supply Per-Procedure Sequencing and Control)
     * \param RPCProcedure  - Specified operation
     * \param SEQUENCE4args - operation arguments
     * \param SEQUENCE4res  - operation results
     */
    virtual void sequence41(const RPCProcedure*,
            const struct NFS41::SEQUENCE4args*,
            const struct NFS41::SEQUENCE4res*) {}

    /*! NFSv41 "SET_SSV" operation (Update SSV for a Client ID)
     * \param RPCProcedure - Specified operation
     * \param SET_SSV4args - operation arguments
     * \param SET_SSV4res  - operation results
     */
    virtual void set_ssv41(const RPCProcedure*,
            const struct NFS41::SET_SSV4args*,
            const struct NFS41::SET_SSV4res*) {}

    /*! NFSv41 "TEST_STATEID" operation (Test Stateids for Validity)
     * \param RPCProcedure      - Specified operation
     * \param TEST_STATEID4args - operation arguments
     * \param TEST_STATEID4res  - operation results
     */
    virtual void test_stateid41(const RPCProcedure*,
            const struct NFS41::TEST_STATEID4args*,
            const struct NFS41::TEST_STATEID4res*) {}

    /*! NFSv41 "WANT_DELEGATION" operation (Request Delegation)
     * \param RPCProcedure         - Specified operation
     * \param WANT_DELEGATION4args - operation arguments
     * \param WANT_DELEGATION4res  - operation results
     */
    virtual void want_delegation41(const RPCProcedure*,
            const struct NFS41::WANT_DELEGATION4args*,
            const struct NFS41::WANT_DELEGATION4res*) {}

    /*! NFSv41 "DESTROY_CLIENTID" operation
     * \param RPCProcedure          - Specified operation
     * \param DESTROY_CLIENTID4args - operation arguments
     * \param DESTROY_CLIENTID4res  - operation results
     */
    virtual void destroy_clientid41(const RPCProcedure*,
            const struct NFS41::DESTROY_CLIENTID4args*,
            const struct NFS41::DESTROY_CLIENTID4res*) {}

    /*! NFSv41 "RECLAIM_COMPLETE" operation (Indicates Reclaims Finished)
     * \param RPCProcedure          - Specified operation
     * \param RECLAIM_COMPLETE4args - operation arguments
     * \param RECLAIM_COMPLETE4res  - operation results
     */
    virtual void reclaim_complete41(const RPCProcedure*,
            const struct NFS41::RECLAIM_COMPLETE4args*,
            const struct NFS41::RECLAIM_COMPLETE4res*) {}

    /*! NFSv41 "ILLEGAL" operation (Illegal operation)
     * \param RPCProcedure  - Specified operation
     * \param ILLEGAL4res   - operation results
     */
    virtual void illegal41(const RPCProcedure*,
            const struct NFS41::ILLEGAL4res*) {}
};

/*! Abstract interface of plugin which collects SMBv1 statistics
 */
class ISMBv1
{
public:
    virtual ~ISMBv1() {}

    /*! SMBv1 "CreateDirectory" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createDirectorySMBv1(const SMBv1::CreateDirectoryCommand*, const SMBv1::CreateDirectoryArgumentType*, const SMBv1::CreateDirectoryResultType*) {}

    /*! SMBv1 "DeleteDirectory" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void deleteDirectorySMBv1(const SMBv1::DeleteDirectoryCommand*, const SMBv1::DeleteDirectoryArgumentType*, const SMBv1::DeleteDirectoryResultType*) {}

    /*! SMBv1 "Open" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void openSMBv1(const SMBv1::OpenCommand*, const SMBv1::OpenArgumentType*, const SMBv1::OpenResultType*) {}

    /*! SMBv1 "Create" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createSMBv1(const SMBv1::CreateCommand*, const SMBv1::CreateArgumentType*, const SMBv1::CreateResultType*) {}

    /*! SMBv1 "Close" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void closeSMBv1(const SMBv1::CloseCommand*, const SMBv1::CloseArgumentType*, const SMBv1::CloseResultType*) {}

    /*! SMBv1 "Flush" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void flushSMBv1(const SMBv1::FlushCommand*, const SMBv1::FlushArgumentType*, const SMBv1::FlushResultType*) {}

    /*! SMBv1 "Delete" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void deleteSMBv1(const SMBv1::DeleteCommand*, const SMBv1::DeleteArgumentType*, const SMBv1::DeleteResultType*) {}

    /*! SMBv1 "Rename" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void renameSMBv1(const SMBv1::RenameCommand*, const SMBv1::RenameArgumentType*, const SMBv1::RenameResultType*) {}

    /*! SMBv1 "QueryInformation" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryInfoSMBv1(const SMBv1::QueryInformationCommand*, const SMBv1::QueryInformationArgumentType*, const SMBv1::QueryInformationResultType*) {}

    /*! SMBv1 "SetInformation" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void setInfoSMBv1(const SMBv1::SetInformationCommand*, const SMBv1::SetInformationArgumentType*, const SMBv1::SetInformationResultType*) {}

    /*! SMBv1 "Read" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readSMBv1(const SMBv1::ReadCommand*, const SMBv1::ReadArgumentType*, const SMBv1::ReadResultType*) {}

    /*! SMBv1 "Write" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeSMBv1(const SMBv1::WriteCommand*, const SMBv1::WriteArgumentType*, const SMBv1::WriteResultType*) {}

    /*! SMBv1 "LockByteRange" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void lockByteRangeSMBv1(const SMBv1::LockByteRangeCommand*, const SMBv1::LockByteRangeArgumentType*, const SMBv1::LockByteRangeResultType*) {}

    /*! SMBv1 "UnlockByteRange" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void unlockByteRangeSMBv1(const SMBv1::UnlockByteRangeCommand*, const SMBv1::UnlockByteRangeArgumentType*, const SMBv1::UnlockByteRangeResultType*) {}

    /*! SMBv1 "CreateTemporary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createTmpSMBv1(const SMBv1::CreateTemporaryCommand*, const SMBv1::CreateTemporaryArgumentType*, const SMBv1::CreateTemporaryResultType*) {}

    /*! SMBv1 "CreateNew" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createNewSMBv1(const SMBv1::CreateNewCommand*, const SMBv1::CreateNewArgumentType*, const SMBv1::CreateNewResultType*) {}

    /*! SMBv1 "CheckDirectory" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void checkDirectorySMBv1(const SMBv1::CheckDirectoryCommand*, const SMBv1::CheckDirectoryArgumentType*, const SMBv1::CheckDirectoryResultType*) {}

    /*! SMBv1 "ProcessExit" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void processExitSMBv1(const SMBv1::ProcessExitCommand*, const SMBv1::ProcessExitArgumentType*, const SMBv1::ProcessExitResultType*) {}

    /*! SMBv1 "Seek" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void seekSMBv1(const SMBv1::SeekCommand*, const SMBv1::SeekArgumentType*, const SMBv1::SeekResultType*) {}

    /*! SMBv1 "LockAndRead" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void lockAndReadSMBv1(const SMBv1::LockAndReadCommand*, const SMBv1::LockAndReadArgumentType*, const SMBv1::LockAndReadResultType*) {}

    /*! SMBv1 "WriteAndUnlock" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeAndUnlockSMBv1(const SMBv1::WriteAndUnlockCommand*, const SMBv1::WriteAndUnlockArgumentType*, const SMBv1::WriteAndUnlockResultType*) {}

    /*! SMBv1 "ReadRaw" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readRawSMBv1(const SMBv1::ReadRawCommand*, const SMBv1::ReadRawArgumentType*, const SMBv1::ReadRawResultType*) {}

    /*! SMBv1 "ReadMpx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readMpxSMBv1(const SMBv1::ReadMpxCommand*, const SMBv1::ReadMpxArgumentType*, const SMBv1::ReadMpxResultType*) {}

    /*! SMBv1 "ReadMpxSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readMpxSecondarySMBv1(const SMBv1::ReadMpxSecondaryCommand*, const SMBv1::ReadMpxSecondaryArgumentType*, const SMBv1::ReadMpxSecondaryResultType*) {}

    /*! SMBv1 "WriteRaw" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeRawSMBv1(const SMBv1::WriteRawCommand*, const SMBv1::WriteRawArgumentType*, const SMBv1::WriteRawResultType*) {}

    /*! SMBv1 "WriteMpx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeMpxSMBv1(const SMBv1::WriteMpxCommand*, const SMBv1::WriteMpxArgumentType*, const SMBv1::WriteMpxResultType*) {}

    /*! SMBv1 "WriteMpxSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeMpxSecondarySMBv1(const SMBv1::WriteMpxSecondaryCommand*, const SMBv1::WriteMpxSecondaryArgumentType*, const SMBv1::WriteMpxSecondaryResultType*) {}

    /*! SMBv1 "WriteComplete" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeCompleteSMBv1(const SMBv1::WriteCompleteCommand*, const SMBv1::WriteCompleteArgumentType*, const SMBv1::WriteCompleteResultType*) {}

    /*! SMBv1 "QueryServer" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryServerSMBv1(const SMBv1::QueryServerCommand*, const SMBv1::QueryServerArgumentType*, const SMBv1::QueryServerResultType*) {}

    /*! SMBv1 "SetInformation2" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void setInfo2SMBv1(const SMBv1::SetInformation2Command*, const SMBv1::SetInformation2ArgumentType*, const SMBv1::SetInformation2ResultType*) {}

    /*! SMBv1 "QueryInformation2" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryInfo2SMBv1(const SMBv1::QueryInformation2Command*, const SMBv1::QueryInformation2ArgumentType*, const SMBv1::QueryInformation2ResultType*) {}

    /*! SMBv1 "LockingAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void lockingAndxSMBv1(const SMBv1::LockingAndxCommand*, const SMBv1::LockingAndxArgumentType*, const SMBv1::LockingAndxResultType*) {}

    /*! SMBv1 "Transaction" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void transactionSMBv1(const SMBv1::TransactionCommand*, const SMBv1::TransactionArgumentType*, const SMBv1::TransactionResultType*) {}

    /*! SMBv1 "TransactionSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void transactionSecondarySMBv1(const SMBv1::TransactionSecondaryCommand*, const SMBv1::TransactionSecondaryArgumentType*, const SMBv1::TransactionSecondaryResultType*) {}

    /*! SMBv1 "Ioctl" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ioctlSMBv1(const SMBv1::IoctlCommand*, const SMBv1::IoctlArgumentType*, const SMBv1::IoctlResultType*) {}

    /*! SMBv1 "IoctlSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ioctlSecondarySMBv1(const SMBv1::IoctlSecondaryCommand*, const SMBv1::IoctlSecondaryArgumentType*, const SMBv1::IoctlSecondaryResultType*) {}

    /*! SMBv1 "Copy" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void copySMBv1(const SMBv1::CopyCommand*, const SMBv1::CopyArgumentType*, const SMBv1::CopyResultType*) {}

    /*! SMBv1 "Move" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void moveSMBv1(const SMBv1::MoveCommand*, const SMBv1::MoveArgumentType*, const SMBv1::MoveResultType*) {}

    /*! SMBv1 "Echo" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void echoSMBv1(const SMBv1::EchoCommand*, const SMBv1::EchoArgumentType*, const SMBv1::EchoResultType*) {}

    /*! SMBv1 "WriteAndClose" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeAndCloseSMBv1(const SMBv1::WriteAndCloseCommand*, const SMBv1::WriteAndCloseArgumentType*, const SMBv1::WriteAndCloseResultType*) {}

    /*! SMBv1 "OpenAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void openAndxSMBv1(const SMBv1::OpenAndxCommand*, const SMBv1::OpenAndxArgumentType*, const SMBv1::OpenAndxResultType*) {}

    /*! SMBv1 "ReadAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readAndxSMBv1(const SMBv1::ReadAndxCommand*, const SMBv1::ReadAndxArgumentType*, const SMBv1::ReadAndxResultType*) {}

    /*! SMBv1 "WriteAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeAndxSMBv1(const SMBv1::WriteAndxCommand*, const SMBv1::WriteAndxArgumentType*, const SMBv1::WriteAndxResultType*) {}

    /*! SMBv1 "NewFileSize" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void newFileSizeSMBv1(const SMBv1::NewFileSizeCommand*, const SMBv1::NewFileSizeArgumentType*, const SMBv1::NewFileSizeResultType*) {}

    /*! SMBv1 "CloseAndTreeDisc" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void closeAndTreeDiscSMBv1(const SMBv1::CloseAndTreeDiscCommand*, const SMBv1::CloseAndTreeDiscArgumentType*, const SMBv1::CloseAndTreeDiscResultType*) {}

    /*! SMBv1 "Transaction2" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void transaction2SMBv1(const SMBv1::Transaction2Command*, const SMBv1::Transaction2ArgumentType*, const SMBv1::Transaction2ResultType*) {}

    /*! SMBv1 "Transaction2Secondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void transaction2SecondarySMBv1(const SMBv1::Transaction2SecondaryCommand*, const SMBv1::Transaction2SecondaryArgumentType*, const SMBv1::Transaction2SecondaryResultType*) {}

    /*! SMBv1 "FindClose2" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findClose2SMBv1(const SMBv1::FindClose2Command*, const SMBv1::FindClose2ArgumentType*, const SMBv1::FindClose2ResultType*) {}

    /*! SMBv1 "FindNotifyClose" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findNotifyCloseSMBv1(const SMBv1::FindNotifyCloseCommand*, const SMBv1::FindNotifyCloseArgumentType*, const SMBv1::FindNotifyCloseResultType*) {}

    /*! SMBv1 "TreeConnect" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeConnectSMBv1(const SMBv1::TreeConnectCommand*, const SMBv1::TreeConnectArgumentType*, const SMBv1::TreeConnectResultType*) {}

    /*! SMBv1 "TreeDisconnect" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeDisconnectSMBv1(const SMBv1::TreeDisconnectCommand*, const SMBv1::TreeDisconnectArgumentType*, const SMBv1::TreeDisconnectResultType*) {}

    /*! SMBv1 "Negotiate" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void negotiateSMBv1(const SMBv1::NegotiateCommand*, const SMBv1::NegotiateArgumentType*, const SMBv1::NegotiateResultType*) {}

    /*! SMBv1 "SessionSetupAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void sessionSetupAndxSMBv1(const SMBv1::SessionSetupAndxCommand*, const SMBv1::SessionSetupAndxArgumentType*, const SMBv1::SessionSetupAndxResultType*) {}

    /*! SMBv1 "LogoffAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void logoffAndxSMBv1(const SMBv1::LogoffAndxCommand*, const SMBv1::LogoffAndxArgumentType*, const SMBv1::LogoffAndxResultType*) {}

    /*! SMBv1 "TreeConnectAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeConnectAndxSMBv1(const SMBv1::TreeConnectAndxCommand*, const SMBv1::TreeConnectAndxArgumentType*, const SMBv1::TreeConnectAndxResultType*) {}

    /*! SMBv1 "SecurityPackageAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void securityPackageAndxSMBv1(const SMBv1::SecurityPackageAndxCommand*, const SMBv1::SecurityPackageAndxArgumentType*, const SMBv1::SecurityPackageAndxResultType*) {}

    /*! SMBv1 "QueryInformationDisk" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryInformationDiskSMBv1(const SMBv1::QueryInformationDiskCommand*, const SMBv1::QueryInformationDiskArgumentType*, const SMBv1::QueryInformationDiskResultType*) {}

    /*! SMBv1 "Search" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void searchSMBv1(const SMBv1::SearchCommand*, const SMBv1::SearchArgumentType*, const SMBv1::SearchResultType*) {}

    /*! SMBv1 "Find" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findSMBv1(const SMBv1::FindCommand*, const SMBv1::FindArgumentType*, const SMBv1::FindResultType*) {}

    /*! SMBv1 "FindUnique" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findUniqueSMBv1(const SMBv1::FindUniqueCommand*, const SMBv1::FindUniqueArgumentType*, const SMBv1::FindUniqueResultType*) {}

    /*! SMBv1 "FindClose" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void findCloseSMBv1(const SMBv1::FindCloseCommand*, const SMBv1::FindCloseArgumentType*, const SMBv1::FindCloseResultType*) {}

    /*! SMBv1 "NtTransact" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntTransactSMBv1(const SMBv1::NtTransactCommand*, const SMBv1::NtTransactArgumentType*, const SMBv1::NtTransactResultType*) {}

    /*! SMBv1 "NtTransactSecondary" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntTransactSecondarySMBv1(const SMBv1::NtTransactSecondaryCommand*, const SMBv1::NtTransactSecondaryArgumentType*, const SMBv1::NtTransactSecondaryResultType*) {}

    /*! SMBv1 "NtCreateAndx" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntCreateAndxSMBv1(const SMBv1::NtCreateAndxCommand*, const SMBv1::NtCreateAndxArgumentType*, const SMBv1::NtCreateAndxResultType*) {}

    /*! SMBv1 "NtCancel" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntCancelSMBv1(const SMBv1::NtCancelCommand*, const SMBv1::NtCancelArgumentType*, const SMBv1::NtCancelResultType*) {}

    /*! SMBv1 "NtRename" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ntRenameSMBv1(const SMBv1::NtRenameCommand*, const SMBv1::NtRenameArgumentType*, const SMBv1::NtRenameResultType*) {}

    /*! SMBv1 "OpenPrintFile" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void openPrintFileSMBv1(const SMBv1::OpenPrintFileCommand*, const SMBv1::OpenPrintFileArgumentType*, const SMBv1::OpenPrintFileResultType*) {}

    /*! SMBv1 "WritePrintFile" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writePrintFileSMBv1(const SMBv1::WritePrintFileCommand*, const SMBv1::WritePrintFileArgumentType*, const SMBv1::WritePrintFileResultType*) {}

    /*! SMBv1 "ClosePrintFile" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void closePrintFileSMBv1(const SMBv1::ClosePrintFileCommand*, const SMBv1::ClosePrintFileArgumentType*, const SMBv1::ClosePrintFileResultType*) {}

    /*! SMBv1 "GetPrintQueue" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void getPrintQueueSMBv1(const SMBv1::GetPrintQueueCommand*, const SMBv1::GetPrintQueueArgumentType*, const SMBv1::GetPrintQueueResultType*) {}

    /*! SMBv1 "ReadBulk" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readBulkSMBv1(const SMBv1::ReadBulkCommand*, const SMBv1::ReadBulkArgumentType*, const SMBv1::ReadBulkResultType*) {}

    /*! SMBv1 "WriteBulk" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeBulkSMBv1(const SMBv1::WriteBulkCommand*, const SMBv1::WriteBulkArgumentType*, const SMBv1::WriteBulkResultType*) {}

    /*! SMBv1 "WriteBulkData" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeBulkDataSMBv1(const SMBv1::WriteBulkDataCommand*, const SMBv1::WriteBulkDataArgumentType*, const SMBv1::WriteBulkDataResultType*) {}

    /*! SMBv1 "Invalid" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void invalidSMBv1(const SMBv1::InvalidCommand*, const SMBv1::InvalidArgumentType*, const SMBv1::InvalidResultType*) {}

    /*! SMBv1 "NoAndxCommand" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void noAndxCommandSMBv1(const SMBv1::NoAndxCommand*, const SMBv1::NoAndxCmdArgumentType*, const SMBv1::NoAndxCmdResultType*) {}
};

/*! Abstract interface of plugin which collects SMBv2 statistics
 */
class ISMBv2
{
public:
    virtual ~ISMBv2() {}

    /*! "Close file" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void closeFileSMBv2(const SMBv2::CloseFileCommand*, const SMBv2::CloseRequest*, const SMBv2::CloseResponse*) {}

    /*! "Negotiate" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void negotiateSMBv2(const SMBv2::NegotiateCommand*, const SMBv2::NegotiateRequest*, const SMBv2::NegotiateResponse*) {}

    /*! "session setup" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void sessionSetupSMBv2(const SMBv2::SessionSetupCommand*, const SMBv2::SessionSetupRequest*, const SMBv2::SessionSetupResponse*) {}

    /*! "log off" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void logOffSMBv2(const SMBv2::LogOffCommand*, const SMBv2::LogOffRequest*, const SMBv2::LogOffResponse*) {}

    /*! "Tree Connect" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeConnectSMBv2(const SMBv2::TreeConnectCommand*, const SMBv2::TreeConnectRequest*, const SMBv2::TreeConnectResponse*) {}

    /*! "Tree disconnect" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void treeDisconnectSMBv2(const SMBv2::TreeDisconnectCommand*, const SMBv2::TreeDisconnectRequest*, const SMBv2::TreeDisconnectResponse*) {}

    /*! "Create" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void createSMBv2(const SMBv2::CreateCommand*, const SMBv2::CreateRequest*, const SMBv2::CreateResponse*) {}

    /*! "Flush" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void flushSMBv2(const SMBv2::FlushCommand*, const SMBv2::FlushRequest*, const SMBv2::FlushResponse*) {}

    /*! "Read" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void readSMBv2(const SMBv2::ReadCommand*, const SMBv2::ReadRequest*, const SMBv2::ReadResponse*) {}

    /*! "Write" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void writeSMBv2(const SMBv2::WriteCommand*, const SMBv2::WriteRequest*, const SMBv2::WriteResponse*) {}

    /*! "Lock" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void lockSMBv2(const SMBv2::LockCommand*, const SMBv2::LockRequest*, const SMBv2::LockResponse*) {}

    /*! "IO ctl" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void ioctlSMBv2(const SMBv2::IoctlCommand*, const SMBv2::IoCtlRequest*, const SMBv2::IoCtlResponse*) {}

    /*! "Cancel" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void cancelSMBv2(const SMBv2::CancelCommand*, const SMBv2::CancelRequest*, const SMBv2::CancelResponce*) {}

    /*! "Echo" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void echoSMBv2(const SMBv2::EchoCommand*, const SMBv2::EchoRequest*, const SMBv2::EchoResponse*) {}

    /*! "Query directory" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryDirSMBv2(const SMBv2::QueryDirCommand*, const SMBv2::QueryDirRequest*, const SMBv2::QueryDirResponse*) {}

    /*! "Change notify" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void changeNotifySMBv2(const SMBv2::ChangeNotifyCommand*, const SMBv2::ChangeNotifyRequest*, const SMBv2::ChangeNotifyResponse*) {}

    /*! "Query Info" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void queryInfoSMBv2(const SMBv2::QueryInfoCommand*, const SMBv2::QueryInfoRequest*, const SMBv2::QueryInfoResponse*) {}

    /*! "Set Info" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void setInfoSMBv2(const SMBv2::SetInfoCommand*, const SMBv2::SetInfoRequest*, const SMBv2::SetInfoResponse*) {}

    /*! "Break opportunistic lock" command "on receive" event handler
     * \param cmd - Specified command
     * \param arg - arguments for the command
     * \param res - result of the command
     */
    virtual void breakOplockSMBv2(const SMBv2::BreakOpLockCommand*, const SMBv2::OplockAcknowledgment*, const SMBv2::OplockResponse*) {}
    // clang-format on
};

/*! Base interface for all nfstrace plugins.
 * Extends protocol interfaces: NFS3, NFS4, NFS41, SMBv1, SMBv2
 */
class IAnalyzer : public INFSv3rpcgen, public INFSv4rpcgen, public INFSv41rpcgen, public ISMBv1, public ISMBv2
{
public:
    virtual ~IAnalyzer() {}
    virtual void flush_statistics() = 0;
    virtual void on_unix_signal(int /*signo*/) {}
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif // IANALYZER_TYPE_H
//------------------------------------------------------------------------------
