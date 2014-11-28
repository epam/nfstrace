//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Hash-table hold info about read/write operations.
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
#ifndef FILE_RW_OP_H
#define FILE_RW_OP_H
//------------------------------------------------------------------------------
#include <vector>
#include <unordered_map>

#include <api/plugin_api.h>
//------------------------------------------------------------------------------
class FileRWOp
{
public:
    class RWTime
    {
    public:
        RWTime() : read_freq{0}, write_freq{0} {}

        inline void inc_read_freq(uint32_t count = 1)  { read_freq += count; }
        inline void inc_write_freq(uint32_t count = 1) { write_freq += count; }

        inline uint32_t get_read_freq()  const { return read_freq; }
        inline uint32_t get_write_freq() const { return write_freq; }
        inline uint32_t get_total_freq() const { return read_freq + write_freq; }
    private:
        RWTime(const RWTime&);
        void operator=(const RWTime&);

        uint32_t read_freq;
        uint32_t write_freq;
    };

    typedef std::unordered_map<uint64_t, RWTime*> BucketTable;
    typedef BucketTable::const_iterator ConstIterator;
    typedef BucketTable::iterator Iterator;
    typedef BucketTable::value_type Pair;
    typedef std::pair<Iterator, bool> Inserted;

    inline FileRWOp() : read_total{0}, write_total{0} {}
    ~FileRWOp();

    void calculate(ProcEnumNFS3::NFSProcedure op,
                                     uint64_t offset,
                                     uint32_t count,
                                     uint32_t time = 0);

    inline uint64_t get_read_total() const   { return read_total;  }
    inline uint64_t get_write_total() const  { return write_total; }
    inline uint64_t get_total() const        { return read_total + write_total; }

    inline Iterator begin() { return buckets.begin(); }
    inline Iterator end()   { return buckets.end(); }
    inline ConstIterator begin() const { return buckets.begin(); }
    inline ConstIterator end()   const { return buckets.end(); }

    static inline uint32_t get_block_size()  { return block_size; }
    static inline uint32_t get_bucket_size() { return bucket_size; }

    static inline void set_block_size(uint32_t bl_s) { block_size = bl_s; }
    static inline void set_bucket_size(uint32_t b_s) { bucket_size = b_s; }

private:
    FileRWOp(const FileRWOp&);
    void operator=(const FileRWOp&);

    BucketTable buckets;
    uint64_t read_total;
    uint64_t write_total;
    static uint32_t block_size;
    static uint32_t bucket_size;
};
//------------------------------------------------------------------------------
#endif//FILE_RW_OP_H
//------------------------------------------------------------------------------
