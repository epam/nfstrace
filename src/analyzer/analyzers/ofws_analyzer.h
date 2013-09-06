//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Overall File Working Set (OFWS) analyzer. Enumerate the overall set of files accessed by clients.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef OFWS_ANALYZER_H
#define OFWS_ANALYZER_H
//------------------------------------------------------------------------------
#include <tr1/unordered_map>

#include "../nfs3/nfs_operation.h"
#include "../rpc_sessions.h"
#include "base_analyzer.h"
#include "fh.h"                     //hash-table's key
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

class OFWSAnalyzer : public BaseAnalyzer
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

    typedef std::tr1::unordered_map<FH, OpCounter*, FH::FH_Hash, FH::FH_Eq> OFWS;
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
