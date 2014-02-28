//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Data Working Set (OFDWS) analyzer. Provide information about unique data accessed.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef OFDWS_ANALYZER_H
#define OFDWS_ANALYZER_H
//------------------------------------------------------------------------------
#include <unordered_map>

#include <utils/fh.h>   //hash-table's key
#include "file_rw_op.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
static const int32_t g_def_bl_size = 8; // [KB]
static const int32_t g_def_bu_size = 16;

class OFDWSAnalyzer : public IAnalyzer
{
    typedef std::unordered_map<FH, FileRWOp*, FH::FH_Hash, FH::FH_Eq> OFDWS;
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
    OFDWSAnalyzer(int32_t bl_size, int32_t bu_size);
    virtual ~OFDWSAnalyzer();

    virtual void read3(const struct RPCProcedure* proc,
            const struct READ3args* args,
            const struct READ3res* res);
    virtual void write3(const struct RPCProcedure* proc,
            const struct WRITE3args* args,
            const struct WRITE3res* res);

    virtual void flush_statistics();

private:
    Iterator get_file_rw_op(const nfs_fh3& key);
    void print_file_ranked(std::ostream& out) const;
    void print_data_usage(std::ostream& out) const;
    void print_rw_records(std::ostream& out, const FileRWOp& file_rw_op) const;
    void store_files_rw_records() const;

    OFDWS ofdws_stat;
    uint64_t read_total;
    uint64_t write_total;
    std::ostream& out;
};
//------------------------------------------------------------------------------
#endif//OFDWS_ANALYZER_H
//------------------------------------------------------------------------------
