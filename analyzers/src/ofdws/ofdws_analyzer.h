//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Data Working Set (OFDWS) analyzer. Provide information about unique data accessed.
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
#ifndef OFDWS_ANALYZER_H
#define OFDWS_ANALYZER_H
//------------------------------------------------------------------------------
#include <cstring>
#include <unordered_map>

#include "file_rw_op.h"
//------------------------------------------------------------------------------
static const int32_t g_def_bl_size {8}; // [KB]
static const int32_t g_def_bu_size {16};

struct FH
{
    uint32_t len {};
    char data[NFS3::NFS3_FHSIZE];

    struct FH_Eq
    {
        bool operator()(const FH& a, const FH& b) const;
    };
    struct FH_Hash
    {
        int operator()(const FH& fh) const;
    };

    inline FH(const NFS3::nfs_fh3& obj)
    {
        len = obj.data.data_len;
        memcpy(data, obj.data.data_val, len);
    }
    inline FH(const FH& obj)
    {
        len = obj.len;
        memcpy(data, obj.data, len);
    }
    std::string to_string() const;

    friend std::ostream& operator<<(std::ostream& out, const FH& obj);


private:
    static inline char to_char(uint8_t hex)
    {
        if(hex < 0xA)
            return hex + '0';
        else
            return hex + 'a' - 0xA;
    }
};

inline int FH::FH_Hash::operator()(const FH& fh) const
{
    int hash = 0;
    for(uint32_t i = 0; i < fh.len; ++i)
        hash += fh.data[i];
    return hash;
}

inline bool FH::FH_Eq::operator()(const FH& a, const FH& b) const
{
    if(a.len != b.len)
        return false;

    for(uint32_t i = 0; i < a.len; ++i)
        if(a.data[i] != b.data[i])
            return false;
    return true;
}

inline std::string FH::to_string() const
{
    std::string str;
    str.reserve(NFS3::NFS3_FHSIZE * 2 + 1); // One byte holds two symbols.
    for(uint32_t i = 0; i < len; ++i)
    {
        str += to_char((data[i] >> 4) & 0xf);
        str += to_char(data[i] & 0xf);
    }
    return str;
}

inline std::ostream& operator<<(std::ostream& out, const FH& fh)
{
    print_nfs_fh(out, fh.data, fh.len);
    return out;
}

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
    OFDWSAnalyzer(int32_t bl_size,
                  int32_t bu_size);
    virtual ~OFDWSAnalyzer();

    void read3(const RPCProcedure* proc,
            const struct NFS3::READ3args* args,
            const struct NFS3::READ3res* res) override final;
    void write3(const RPCProcedure* proc,
            const struct NFS3::WRITE3args* args,
            const struct NFS3::WRITE3res* res) override final;

    virtual void flush_statistics();

private:
    Iterator get_file_rw_op(const NFS3::nfs_fh3& key);
    void print_file_ranked(std::ostream& out) const;
    void print_data_usage(std::ostream& out) const;
    void print_rw_records(std::ostream& out,
                        const FileRWOp& file_rw_op) const;
    void store_files_rw_records() const;

    OFDWS ofdws_stat;
    uint64_t read_total;
    uint64_t write_total;
    std::ostream& out;
};
//------------------------------------------------------------------------------
#endif//OFDWS_ANALYZER_H
//------------------------------------------------------------------------------
