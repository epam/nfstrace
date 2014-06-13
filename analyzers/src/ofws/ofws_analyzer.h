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
#include <unordered_map>

#include <api/plugin_api.h>
//------------------------------------------------------------------------------
class OFWSAnalyzer : public IAnalyzer
{
    class OpCounter
    {
    public:
        inline OpCounter() : total(0)
        {
            std::memset(counters, 0, sizeof(counters));
        }
        inline ~OpCounter() {}
        inline void inc(ProcEnum::NFSProcedure op, uint32_t size = 1)
        {
            total += size;
            counters[op] += size;
        }
        inline uint64_t get_total() const { return total; }
        inline uint32_t operator[](uint32_t op) const { return counters[op]; }
    private:
        OpCounter(const OpCounter&);
        void operator=(const OpCounter&);

        uint32_t counters[ProcEnum::count];
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

    virtual void null(const struct RPCProcedure* proc,
            const struct NULLargs* args,
            const struct NULLres* res);
    virtual void getattr3(const struct RPCProcedure* proc,
            const struct GETATTR3args* args,
            const struct GETATTR3res* res);
    virtual void setattr3(const struct RPCProcedure* proc,
            const struct SETATTR3args* args,
            const struct SETATTR3res* res);
    virtual void lookup3(const struct RPCProcedure* proc,
            const struct LOOKUP3args* args,
            const struct LOOKUP3res* res);
    virtual void access3(const struct RPCProcedure* proc,
            const struct ACCESS3args* args,
            const struct ACCESS3res* res);
    virtual void readlink3(const struct RPCProcedure* proc,
            const struct READLINK3args* args,
            const struct READLINK3res* res);
    virtual void read3(const struct RPCProcedure* proc,
            const struct READ3args* args,
            const struct READ3res* res);
    virtual void write3(const struct RPCProcedure* proc,
            const struct WRITE3args* args,
            const struct WRITE3res* res);
    virtual void create3(const struct RPCProcedure* proc,
            const struct CREATE3args* args,
            const struct CREATE3res* res);
    virtual void mkdir3(const struct RPCProcedure* proc,
            const struct MKDIR3args* args,
            const struct MKDIR3res* res);
    virtual void symlink3(const struct RPCProcedure* proc,
            const struct SYMLINK3args* args,
            const struct SYMLINK3res* res);
    virtual void mknod3(const struct RPCProcedure* proc,
            const struct MKNOD3args* args,
            const struct MKNOD3res* res);
    virtual void remove3(const struct RPCProcedure* proc,
            const struct REMOVE3args* args,
            const struct REMOVE3res* res);
    virtual void rmdir3(const struct RPCProcedure* proc,
            const struct RMDIR3args* args,
            const struct RMDIR3res* res);
    virtual void rename3(const struct RPCProcedure* proc,
            const struct RENAME3args* args,
            const struct RENAME3res* res);
    virtual void link3(const struct RPCProcedure* proc,
            const struct LINK3args* args,
            const struct LINK3res* res);
    virtual void readdir3(const struct RPCProcedure* proc,
            const struct READDIR3args* args,
            const struct READDIR3res* res);
    virtual void readdirplus3(const struct RPCProcedure* proc,
            const struct READDIRPLUS3args* args,
            const struct READDIRPLUS3res* res);
    virtual void fsstat3(const struct RPCProcedure* proc,
            const struct FSSTAT3args* args,
            const struct FSSTAT3res* res);
    virtual void fsinfo3(const struct RPCProcedure* proc,
            const struct FSINFO3args* args,
            const struct FSINFO3res* res);
    virtual void pathconf3(const struct RPCProcedure* proc,
            const struct PATHCONF3args* args,
            const struct PATHCONF3res* res);
    virtual void commit3(const struct RPCProcedure* proc,
            const struct COMMIT3args* args,
            const struct COMMIT3res* res);

    virtual void flush_statistics();

private:
    Iterator find_or_create_op_counter(const nfs_fh3& key);

    OFWS ofws_stat;
    std::ostream& out;
};
//------------------------------------------------------------------------------
#endif//OFWS_ANALYZER_H
//------------------------------------------------------------------------------
