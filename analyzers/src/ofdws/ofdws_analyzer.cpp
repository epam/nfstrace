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
#include <algorithm>            //std::sort
#include <cstdlib>
#include <fstream>              //std::ofstream
#include <vector>

#include "ofdws_analyzer.h"
//------------------------------------------------------------------------------
OFDWSAnalyzer::OFDWSAnalyzer(int32_t bl_size,
                             int32_t bu_size)
: read_total{0}
, write_total{0}
, out(std::cout)

{
    FileRWOp::set_block_size(bl_size * 1024);
    FileRWOp::set_bucket_size(bu_size);
}

OFDWSAnalyzer::~OFDWSAnalyzer()
{
    Iterator i = ofdws_stat.begin();
    Iterator end = ofdws_stat.end();
    for(; i != end; ++i)
        delete i->second;
}

void OFDWSAnalyzer::read3(const RPCProcedure*,
                          const struct NFS3::READ3args* args,
                          const struct NFS3::READ3res*  res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        read_total += res->READ3res_u.resok.count;

        Iterator i = get_file_rw_op(args->file);
        i->second->calculate(ProcEnumNFS3::READ, args->offset, res->READ3res_u.resok.count);
    }
}

void OFDWSAnalyzer::write3(const RPCProcedure*,
                           const struct NFS3::WRITE3args* args,
                           const struct NFS3::WRITE3res*  res)
{
    if(res && res->status == NFS3::nfsstat3::NFS3_OK)
    {
        write_total += res->WRITE3res_u.resok.count;

        Iterator i = get_file_rw_op(args->file);
        i->second->calculate(ProcEnumNFS3::WRITE, args->offset, res->WRITE3res_u.resok.count);
    }
}

void OFDWSAnalyzer::flush_statistics()
{
    out << "### OFDWS Analyzer ###" << std::endl;
    out << "Read total: " << read_total << " Write total: " << write_total << std::endl;
    if(read_total != 0 || write_total != 0)
    {
        out << "File ranked:\n"; 
        print_file_ranked(out);
        out << "Once accessed: ";
        print_data_usage(out);
        store_files_rw_records();
    }
}

void OFDWSAnalyzer::store_files_rw_records() const
{
    ConstIterator i = ofdws_stat.begin();
    ConstIterator i_end = ofdws_stat.end();
    std::ofstream fout;
    for(; i != i_end; ++i)
    {
        std::string fh = i->first.to_string();
        fout.open(fh.c_str(), std::ios_base::out | std::ios_base::trunc);
        print_rw_records(fout, *i->second);
        fout.close();
    }
}

void OFDWSAnalyzer::print_rw_records(std::ostream& out, const FileRWOp& file_rw_op) const
{
    FileRWOp::ConstIterator j = file_rw_op.begin();
    FileRWOp::ConstIterator j_end = file_rw_op.end();
    for(; j != j_end; ++j)
    {
        uint64_t offset = j->first;
        FileRWOp::RWTime* bucket = j->second;
        for(uint32_t k = 0; k < FileRWOp::get_bucket_size(); ++k)
            out << offset * FileRWOp::get_bucket_size() + k << ' ' << bucket[k].get_total_freq() << '\n';
    }
}

void OFDWSAnalyzer::print_data_usage(std::ostream& out) const
{
    uint64_t once {0};
    uint64_t mult {0}; // mult = multiple
    uint32_t used {0};
    ConstIterator i = ofdws_stat.begin();
    ConstIterator i_end = ofdws_stat.end();
    for(; i != i_end; ++i)
    {
        FileRWOp::ConstIterator j = i->second->begin();
        FileRWOp::ConstIterator j_end = i->second->end();
        for(; j != j_end; ++j)
        {
            FileRWOp::RWTime* bucket = j->second;
            for(uint32_t k = 0; k < FileRWOp::get_bucket_size(); ++k)
            {
                used = bucket[k].get_read_freq() + bucket[k].get_write_freq();
                if(used > 0)
                {
                    if(used == 1)
                        ++once;
                    else
                        ++mult;
                }
            }
        }
    }
    out.precision(2);
    out << std::fixed << float(once)/(once + mult) * 100 << '%' << std::endl;
}

void OFDWSAnalyzer::print_file_ranked(std::ostream& out) const
{
    uint32_t size = ofdws_stat.size();
    std::vector< ConstIterator > v(size);
    ConstIterator i = ofdws_stat.begin();
    ConstIterator end = ofdws_stat.end();
    for(uint32_t j = 0; i != end; ++i, ++j)
        v[j] = i;
    std::sort(v.begin(), v.end(), const_iterator_comp);
    for(uint32_t j = size; j > 0; --j)
        out << v[j-1]->first << ' ' << v[j-1]->second->get_read_total() << ' ' << v[j-1]->second->get_write_total() << '\n';
}

OFDWSAnalyzer::Iterator OFDWSAnalyzer::get_file_rw_op(const NFS3::nfs_fh3& key)
{
    Iterator i = ofdws_stat.find(key);
    if(i == ofdws_stat.end())
    {
        Inserted ins = ofdws_stat.insert(Pair(key, new FileRWOp()));
        if(ins.second == false)
            throw int();
        i = ins.first;
    }
    return i;
}

extern "C"
{

const char* usage()
{
    return "bu_size - for specifying amount of buckets. Range: 1..32767 [16 by default]\n"
           "bl_size - for specifying block size [KB]. Range: 1..31 [8 by default]";
}

IAnalyzer* create(const char* optarg)
{
    enum
    {
        bu_size = 0,
        bl_size 
    };
    const char* token[] = {
        "bu_size",
        "bl_size",
        NULL
    };

    char* value {NULL};
    int32_t bucket_size = g_def_bu_size;
    int32_t block_size = g_def_bl_size;
    while (*optarg != '\0')
    {
        int supopt = getsubopt((char**)&optarg, (char**)token, &value);
        if(value == NULL)
            return nullptr;

        switch(supopt)
        {
            case bu_size:
                bucket_size = atoi(value);
                if(bucket_size < 1 || block_size > 32767)
                    return nullptr;
                break;

            case bl_size:
                block_size = atoi(value);
                if(block_size < 1 || block_size > 31)
                    return nullptr;
                break;

            default:
                return nullptr;
        }
        value = NULL;
    }
    return new OFDWSAnalyzer(bucket_size, block_size);
}

void destroy(IAnalyzer* instance)
{
    delete instance;
}

NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

}
//------------------------------------------------------------------------------
