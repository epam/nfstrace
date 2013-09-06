//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Data Working Set (OFDWS) analyzer. Provide information about unique data accessed. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef OFDWS_ANALYZER_H
#define OFDWS_ANALYZER_H
//------------------------------------------------------------------------------
#include <tr1/unordered_map>

#include "../nfs3/nfs_operation.h"
#include "../rpc_sessions.h"
#include "base_analyzer.h"
#include "fh.h"                     //hash-table's key
#include "file_rw_op.h"
//------------------------------------------------------------------------------
using namespace NST::analyzer::NFS3;

using NST::analyzer::RPC::RPCOperation;
using NST::analyzer::XDR::Opaque;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

class OFDWSAnalyzer : public BaseAnalyzer
{
    typedef std::tr1::unordered_map<FH, FileRWOp*, FH::FH_Hash, FH::FH_Eq> OFDWS;
    typedef OFDWS::const_iterator ConstIterator;
    typedef OFDWS::iterator Iterator;
    typedef OFDWS::value_type Pair;
    typedef std::pair<Iterator, bool> Inserted;

    struct ConstIterator_Comp
    {
        inline bool operator()(const ConstIterator& a, const ConstIterator& b) const
        {
            return (a->second->get_total() < b->second->get_total());
        }
    } const_iterator_comp;

public:
    OFDWSAnalyzer(uint32_t block_size, uint32_t bucket_size);
    virtual ~OFDWSAnalyzer();

    virtual bool call_null       (const RPCOperation& operation);
    virtual bool call_getattr    (const RPCOperation& operation);
    virtual bool call_setattr    (const RPCOperation& operation);
    virtual bool call_lookup     (const RPCOperation& operation);
    virtual bool call_access     (const RPCOperation& operation);
    virtual bool call_readlink   (const RPCOperation& operation);
    virtual bool call_read       (const RPCOperation& operation);
    virtual bool call_write      (const RPCOperation& operation);
    virtual bool call_create     (const RPCOperation& operation);
    virtual bool call_mkdir      (const RPCOperation& operation);
    virtual bool call_symlink    (const RPCOperation& operation);
    virtual bool call_mknod      (const RPCOperation& operation);
    virtual bool call_remove     (const RPCOperation& operation);
    virtual bool call_rmdir      (const RPCOperation& operation);
    virtual bool call_rename     (const RPCOperation& operation);
    virtual bool call_link       (const RPCOperation& operation);
    virtual bool call_readdir    (const RPCOperation& operation);
    virtual bool call_readdirplus(const RPCOperation& operation);
    virtual bool call_fsstat     (const RPCOperation& operation);
    virtual bool call_fsinfo     (const RPCOperation& operation);
    virtual bool call_pathconf   (const RPCOperation& operation);
    virtual bool call_commit     (const RPCOperation& operation);
    virtual void print(std::ostream& out);

private:
    Iterator get_file_rw_op(const nfs_fh3& key);
    void print_file_ranked(std::ostream& out) const;
    void print_data_usage(std::ostream& out) const;
    void print_rw_records(std::ostream& out, const FileRWOp& file_rw_op) const;
    void store_files_rw_records() const;

    OFDWS ofdws_stat; 
    uint64_t read_total;
    uint64_t write_total;
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//OFDWS_ANALYZER_H
//------------------------------------------------------------------------------
