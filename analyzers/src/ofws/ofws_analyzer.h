//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Working Set (OFWS) analyzer. Enumerate the overall set of files accessed by clients.
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
#ifndef OFWS_ANALYZER_H
#define OFWS_ANALYZER_H
//------------------------------------------------------------------------------
#include <cstdint>
#include <iomanip>
#include <ostream>
#include <cstring>
#include <unordered_map>

#include <api/plugin_api.h>
//------------------------------------------------------------------------------
struct FH
{
    uint32_t len {};
    char data[NFS3::NFS3_FHSIZE] {};

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

class OFWSAnalyzer : public IAnalyzer
{
    class OpCounter
    {
    public:
        inline OpCounter() : total{0}
        {
            std::memset(counters, 0, sizeof(counters));
        }
        inline ~OpCounter() {}
        inline void inc(ProcEnumNFS3::NFSProcedure op, uint32_t size = 1)
        {
            total += size;
            counters[op] += size;
        }
        inline uint64_t get_total() const { return total; }
        inline uint32_t operator[](uint32_t op) const { return counters[op]; }
    private:
        OpCounter(const OpCounter&);
        void operator=(const OpCounter&);

        uint32_t counters[ProcEnumNFS3::count];
        uint64_t total;
    };

    typedef std::unordered_map<FH, OpCounter*, FH::FH_Hash, FH::FH_Eq> OFWS;
    typedef OFWS::value_type Pair;
    typedef OFWS::iterator Iterator;
    typedef OFWS::const_iterator ConstIterator;
    typedef std::pair<Iterator, bool> Inserted;

    struct Iterator_Comp
    {
        inline bool operator()(const Iterator& a, const Iterator& b) const
        {
            return (a->second->get_total() < b->second->get_total());
        }
    } iterator_comp;

public:
    inline OFWSAnalyzer():out(std::cout) {}
    virtual ~OFWSAnalyzer();

    void getattr3(const RPCProcedure* proc,
            const struct NFS3::GETATTR3args* args,
            const struct NFS3::GETATTR3res* res) override final;
    void setattr3(const RPCProcedure* proc,
            const struct NFS3::SETATTR3args* args,
            const struct NFS3::SETATTR3res* res) override final;
    void lookup3(const RPCProcedure* proc,
            const struct NFS3::LOOKUP3args* args,
            const struct NFS3::LOOKUP3res* res) override final;
    void access3(const RPCProcedure* proc,
            const struct NFS3::ACCESS3args* args,
            const struct NFS3::ACCESS3res* res) override final;
    void readlink3(const RPCProcedure* proc,
            const struct NFS3::READLINK3args* args,
            const struct NFS3::READLINK3res* res) override final;
    void read3(const RPCProcedure* proc,
            const struct NFS3::READ3args* args,
            const struct NFS3::READ3res* res) override final;
    void write3(const RPCProcedure* proc,
            const struct NFS3::WRITE3args* args,
            const struct NFS3::WRITE3res* res) override final;
    void create3(const RPCProcedure* proc,
            const struct NFS3::CREATE3args* args,
            const struct NFS3::CREATE3res* res) override final;
    void mkdir3(const RPCProcedure* proc,
            const struct NFS3::MKDIR3args* args,
            const struct NFS3::MKDIR3res* res) override final;
    void symlink3(const RPCProcedure* proc,
            const struct NFS3::SYMLINK3args* args,
            const struct NFS3::SYMLINK3res* res) override final;
    void mknod3(const RPCProcedure* proc,
            const struct NFS3::MKNOD3args* args,
            const struct NFS3::MKNOD3res* res) override final;
    void remove3(const RPCProcedure* proc,
            const struct NFS3::REMOVE3args* args,
            const struct NFS3::REMOVE3res* res) override final;
    void rmdir3(const RPCProcedure* proc,
            const struct NFS3::RMDIR3args* args,
            const struct NFS3::RMDIR3res* res) override final;
    void rename3(const RPCProcedure* proc,
            const struct NFS3::RENAME3args* args,
            const struct NFS3::RENAME3res* res) override final;
    void link3(const RPCProcedure* proc,
            const struct NFS3::LINK3args* args,
            const struct NFS3::LINK3res* res) override final;
    void readdir3(const RPCProcedure* proc,
            const struct NFS3::READDIR3args* args,
            const struct NFS3::READDIR3res* res) override final;
    void readdirplus3(const RPCProcedure* proc,
            const struct NFS3::READDIRPLUS3args* args,
            const struct NFS3::READDIRPLUS3res* res) override final;
    void fsstat3(const RPCProcedure* proc,
            const struct NFS3::FSSTAT3args* args,
            const struct NFS3::FSSTAT3res* res) override final;
    void fsinfo3(const RPCProcedure* proc,
            const struct NFS3::FSINFO3args* args,
            const struct NFS3::FSINFO3res* res) override final;
    void pathconf3(const RPCProcedure* proc,
            const struct NFS3::PATHCONF3args* args,
            const struct NFS3::PATHCONF3res* res) override final;
    void commit3(const RPCProcedure* proc,
            const struct NFS3::COMMIT3args* args,
            const struct NFS3::COMMIT3res* res) override final;

    virtual void flush_statistics();

private:
    Iterator find_or_create_op_counter(const NFS3::nfs_fh3& key);

    OFWS ofws_stat;
    std::ostream& out;
};
//------------------------------------------------------------------------------
#endif//OFWS_ANALYZER_H
//------------------------------------------------------------------------------
