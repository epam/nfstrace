//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Data Working Set (OFDWS) analyzer. Provide information about unique data accessed. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <algorithm>            //std::sort
#include <fstream>              //std::ofstream
#include <vector>

#include "ofdws_analyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
OFDWSAnalyzer::OFDWSAnalyzer(const char*) : read_total(0), write_total(0), out(std::cout)
{
    FileRWOp::set_block_size(16*1024);
    FileRWOp::set_bucket_size(8);
}

OFDWSAnalyzer::~OFDWSAnalyzer()
{
    Iterator i = ofdws_stat.begin();
    Iterator end = ofdws_stat.end();
    for(; i != end; ++i)
        delete i->second;
}

void OFDWSAnalyzer::read3(const struct RPCProcedure*,
                          const struct READ3args* args,
                          const struct READ3res*  res)
{
    if(res->status == nfsstat3::OK)
    {
        read_total += res->u.resok.count;

        Iterator i = get_file_rw_op(args->file);
        i->second->calculate(ProcEnum::READ, args->offset, res->u.resok.count);
    }
}

void OFDWSAnalyzer::write3(const struct RPCProcedure*,
                           const struct WRITE3args* args,
                           const struct WRITE3res*  res)
{
    if(res->status == nfsstat3::OK)
    {
        write_total += res->u.resok.count;

        Iterator i = get_file_rw_op(args->file);
        i->second->calculate(ProcEnum::WRITE, args->offset, res->u.resok.count);
    }
}

void OFDWSAnalyzer::flush_statistics()
{
    out << "### OFDWS Analyzer ###" << std::endl;
    out << "Read total: " << read_total << " Write total: " << write_total << std::endl;
    out << "File ranked:\n"; 
    print_file_ranked(out);
    out << "Once accessed: ";
    print_data_usage(out);
    store_files_rw_records();
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
    uint64_t once = 0;
    uint64_t mult = 0; // mult = multiple
    uint32_t used = 0;
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
    out << std::fixed << float(once)/(once + mult) * 100 << "%" << std::endl;
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

OFDWSAnalyzer::Iterator OFDWSAnalyzer::get_file_rw_op(const nfs_fh3& key)
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

BaseAnalyzer* create(const char* opts)
{
    return new OFDWSAnalyzer(opts);
}

void destroy(BaseAnalyzer* context)
{
    delete context;
}

const char* usage()
{
    return "Do what you want!";
}

}
//------------------------------------------------------------------------------
