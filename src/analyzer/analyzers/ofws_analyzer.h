//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Working Set (OFWS) analyzer. Enumerate the overall set of files accessed by clients.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef OFWS_ANALYZER_H
#define OFWS_ANALYZER_H
//------------------------------------------------------------------------------
#include <cstring>  //memset
#include <tr1/unordered_map>
#include <sstream>

#include "../xdr/xdr_struct.h"
#include "../nfs3/nfs_operation.h"
#include "../rpc_sessions.h"
#include "base_analyzer.h"
#include "breakdown.h"
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

class OpCounter
{
public:
    inline OpCounter() : total(0)
    {
        std::memset(counters, 0, sizeof(counters));
    }
    inline ~OpCounter() {}
    inline void inc(Proc::Enum op, uint32_t size = 1)
    {
        total += size;
        counters[op] += size;
    }
    inline uint64_t get_total() const { return total; }
    inline uint32_t operator[](uint32_t op) const { return counters[op]; }
private:
    OpCounter(const OpCounter&);
    void operator=(const OpCounter&);

    uint32_t counters[Proc::num];
    uint64_t total;
};

class OFWSAnalyzer : public BaseAnalyzer
{
    struct FH 
    {
        inline FH(const nfs_fh3& obj)
        {
            len = obj.data.len;
            memcpy(data, obj.data.ptr, len);
        }
        inline FH(const FH& obj)
        {
            len = obj.len;
            memcpy(data, obj.data, len);
        }

        friend std::ostream& operator<<(std::ostream& out, const FH& obj)
        {
            for(uint32_t i = 0; i < obj.len; ++i)
            {
                out << (uint32_t) obj.data[i];
            }
            return out;
        }

        uint32_t len;
        uint8_t data[64];
    };
    struct FH_Eq
    {
        bool operator()(const FH& a, const FH& b) const
        {
            if(a.len != b.len)
            {
                return false;
            }

            for(uint32_t i = 0; i < a.len; ++i)
            {
                if(a.data[i] != b.data[i])
                {
                    return false;
                }
            }
            return true;
        }
    };
    struct FH_Hash
    {
        int operator()(const FH& fh) const
        {
            int hash = 0;
            for(uint32_t i = 0; i < fh.len; ++i)
            {
                hash += fh.data[i];
            }
            return hash;
        }
    };

    typedef std::tr1::unordered_map<FH, OpCounter*, FH_Hash, FH_Eq> OFWS;
    typedef OFWS::value_type Pair;
    typedef OFWS::iterator Iterator;
    typedef OFWS::const_iterator ConstIterator;
    typedef std::pair<Iterator, bool> Inserted;

    struct Iterator_Comp
    {
        bool operator()(const Iterator& a, const Iterator& b) const
        {
            return (a->second->get_total() < b->second->get_total());
        }
    } iterator_comp;

public:
    inline OFWSAnalyzer() {}
    virtual ~OFWSAnalyzer();

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
    Iterator find_or_create_op_counter(const nfs_fh3& key);
    OFWS ofws_stat; 
};

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//OFWS_ANALYZER_H
//------------------------------------------------------------------------------
