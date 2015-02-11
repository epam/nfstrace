//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Operation breakdown analyzer. Identify clients that are busier than others.
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
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <list>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <map>
#include <vector>

#include <arpa/inet.h> // for ntohs()/ntohl()
#include <sys/time.h>

#include <api/plugin_api.h>
//------------------------------------------------------------------------------
template <typename T>
T to_sec(const timeval& val)
{
    return (((T)val.tv_sec) + ((T)val.tv_usec) / 1000000.0);
}

template <typename T>
class TwoPassVariance
{
    using ConstIterator = std::list<timeval>::const_iterator;

public:
    TwoPassVariance() : count{0} {}
    ~TwoPassVariance() {}

    void add(const timeval& t)
    {
        ++count;
        latencies.push_back(t);
    }

    uint32_t get_count() const { return count; }

    T get_avg() const
    {
        if(count == 0) return T();

        ConstIterator   i = latencies.begin();
        ConstIterator end = latencies.end();

        timeval res;
        timerclear(&res);
        for(; i != end; ++i)
        {
            timeradd(&res, &(*i), &res);
        }
        return to_sec<T>(res) / count;
    }

    T get_st_dev() const
    {
        if(count < 2) return T();

        const T avg = get_avg();
        T st_dev = T();

        ConstIterator   i = latencies.begin();
        ConstIterator end = latencies.end();
        for(T delta; i != end; ++i)
        {
            delta = to_sec<T>(*i) - avg;
            st_dev += pow(delta, 2.0);
        }
        st_dev /= (count - 1);
        return sqrt(st_dev);
    }

private:
    void operator=(const TwoPassVariance&)  = delete;

    uint32_t count;
    std::list<timeval> latencies;
};

template <typename T>
class OnlineVariance
{
public:
    OnlineVariance() : count{0},
                       st_dev{},
                          avg{},
                           m2{} {}
    ~OnlineVariance() {}

    void add(const timeval& t)
    {
        T x = to_sec<T>(t);
        T delta = x - avg;
        avg += delta / (++count);
        m2 += delta * (x - avg);
    }

    uint32_t get_count() const { return count; }

    T get_avg() const { return avg; }

    T get_st_dev() const
    {
        if(count < 2) return T();
        return sqrt(m2 / (count - 1));
    }

private:
    void operator=(const OnlineVariance&) = delete;

    uint32_t count;
    T st_dev;
    T avg;
    T m2;
};

template
<
typename T, // Data type defines evaluation precision
template <typename> class Algorithm // Evaluation algorithm
>
class Latencies
{
public:
    Latencies()
    {
        timerclear(&min);
        timerclear(&max);
    }

    void add(const timeval& t)        { algorithm.add(t); set_range(t); }
    uint64_t       get_count()  const { return algorithm.get_count();   }
    long double    get_avg()    const { return algorithm.get_avg();     }
    long double    get_st_dev() const { return algorithm.get_st_dev();  }
    const timeval& get_min()    const { return min; }
    const timeval& get_max()    const { return max; }

private:
    void operator=(const Latencies&) = delete;

    void set_range(const timeval& t)
    {
        if(timercmp(&t, &min, <))
            min = t;
        if(min.tv_sec == 0 && min.tv_usec == 0)
            min = t;
        if(timercmp(&t, &max, >))
            max = t;
    }

    Algorithm<T> algorithm;
    timeval min;
    timeval max;
};

template
<
    typename T,
    template <class> class Algorithm
>
class BreakdownCounter
{
public:
     BreakdownCounter() {}
    ~BreakdownCounter() {}
    const Latencies<T, Algorithm>& operator[](uint32_t index) const
    {
        return latencies[index];
    }
    Latencies<T, Algorithm>& operator[](uint32_t index)
    {
        return latencies[index];
    }

private:
    void operator=  (const BreakdownCounter&) = delete;

    Latencies<T, Algorithm> latencies[ProcEnumNFS41::count];
};

template
<
    typename T,
    template <class> class Algorithm
>
class BreakdownAnalyzer : public IAnalyzer
{
    struct Less // defines order for sessions in output
    {
        bool operator() (const Session& a, const Session& b) const
        {
            return ( (std::uint16_t)(a.ip_type) < (std::uint16_t)(b.ip_type) ) || // compare versions of IP address
                   ( ntohs(a.port[0]) < ntohs(b.port[0])                     ) || // compare Source(client) ports
                   ( ntohs(a.port[1]) < ntohs(b.port[1])                     ) || // compare Destination(server) ports

                   ( (a.ip_type == Session::IPType::v4) ? // compare IPv4
                        ((ntohl(a.ip.v4.addr[0]) < ntohl(b.ip.v4.addr[0])) || (ntohl(a.ip.v4.addr[1]) < ntohl(b.ip.v4.addr[1])))
                     :
                        (memcmp(&a.ip.v6, &b.ip.v6, sizeof(a.ip.v6)) < 0 )
                   );
        }
    };

    using Breakdown = BreakdownCounter<T, Algorithm>;
    using PerOpStat = std::map<Session, Breakdown, Less>;
    using Pair = typename PerOpStat::value_type;
public:
    BreakdownAnalyzer(std::ostream& o = std::cout) : nfs3_proc_total{0},
                                                     nfs3_proc_count(ProcEnumNFS3::count, 0),
                                                     nfs4_proc_total{0},
                                                     nfs4_ops_total{0},
                                                     nfs4_proc_count(ProcEnumNFS4::count, 0),
                                                     nfs41_proc_total{0},
                                                     nfs41_ops_total{0},
                                                     nfs41_proc_count(ProcEnumNFS41::count, 0),
                                                     out(o) { }
    virtual ~BreakdownAnalyzer() { }

    // NFSv3 procedures

    void null(const RPCProcedure* proc,
              const struct NFS3::NULL3args*,
              const struct NFS3::NULL3res*) override final { account(proc); }
    void getattr3(const RPCProcedure* proc,
                  const struct NFS3::GETATTR3args*,
                  const struct NFS3::GETATTR3res*) override final { account(proc); }
    void setattr3(const RPCProcedure* proc,
                  const struct NFS3::SETATTR3args*,
                  const struct NFS3::SETATTR3res*) override final { account(proc); }
    void lookup3(const RPCProcedure* proc,
                 const struct NFS3::LOOKUP3args*,
                 const struct NFS3::LOOKUP3res*) override final { account(proc); }
    void access3(const RPCProcedure* proc,
                 const struct NFS3::ACCESS3args*,
                 const struct NFS3::ACCESS3res*) override final { account(proc); }
    void readlink3(const RPCProcedure* proc,
                   const struct NFS3::READLINK3args*,
                   const struct NFS3::READLINK3res*) override final { account(proc); }
    void read3(const RPCProcedure* proc,
               const struct NFS3::READ3args*,
               const struct NFS3::READ3res*) override final { account(proc); }
    void write3(const RPCProcedure* proc,
                const struct NFS3::WRITE3args*,
                const struct NFS3::WRITE3res*) override final { account(proc); }
    void create3(const RPCProcedure* proc,
                 const struct NFS3::CREATE3args*,
                 const struct NFS3::CREATE3res*) override final { account(proc); }
    void mkdir3(const RPCProcedure* proc,
                const struct NFS3::MKDIR3args*,
                const struct NFS3::MKDIR3res*) override final { account(proc); }
    void symlink3(const RPCProcedure* proc,
                 const struct NFS3::SYMLINK3args*,
                 const struct NFS3::SYMLINK3res*) override final { account(proc); }
    void mknod3(const RPCProcedure* proc,
                const struct NFS3::MKNOD3args*,
                const struct NFS3::MKNOD3res*) override final { account(proc); }
    void remove3(const RPCProcedure* proc,
                 const struct NFS3::REMOVE3args*,
                 const struct NFS3::REMOVE3res*) override final { account(proc); }
    void rmdir3(const RPCProcedure* proc,
                const struct NFS3::RMDIR3args*,
                const struct NFS3::RMDIR3res*) override final { account(proc); }
    void rename3(const RPCProcedure* proc,
                 const struct NFS3::RENAME3args*,
                 const struct NFS3::RENAME3res*) override final { account(proc); }
    void link3(const RPCProcedure* proc,
               const struct NFS3::LINK3args*,
               const struct NFS3::LINK3res*) override final { account(proc); }
    void readdir3(const RPCProcedure* proc,
                  const struct NFS3::READDIR3args*,
                  const struct NFS3::READDIR3res*) override final { account(proc); }
    void readdirplus3(const RPCProcedure* proc,
                      const struct NFS3::READDIRPLUS3args*,
                      const struct NFS3::READDIRPLUS3res*) override final { account(proc); }
    void fsstat3(const RPCProcedure* proc,
                 const struct NFS3::FSSTAT3args*,
                 const struct NFS3::FSSTAT3res*) override final { account(proc); }
    void fsinfo3(const RPCProcedure* proc,
                 const struct NFS3::FSINFO3args*,
                 const struct NFS3::FSINFO3res*) override final { account(proc); }
    void pathconf3(const RPCProcedure* proc,
                   const struct NFS3::PATHCONF3args*,
                   const struct NFS3::PATHCONF3res*) override final { account(proc); }
    void commit3(const RPCProcedure* proc,
                 const struct NFS3::COMMIT3args*,
                 const struct NFS3::COMMIT3res*) override final { account(proc); }

    // NFS4.0 procedures

    void null(const RPCProcedure* proc,
              const struct NFS4::NULL4args*,
              const struct NFS4::NULL4res*) override final { account(proc, NFS_V40); }
    void compound4(const RPCProcedure*  proc,
                   const struct NFS4::COMPOUND4args*,
                   const struct NFS4::COMPOUND4res*) override final { account(proc, NFS_V40); }

    // NFS4.0 operations

    void access40(const RPCProcedure* proc,
                  const struct NFS4::ACCESS4args*,
                  const struct NFS4::ACCESS4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::ACCESS); } }

    void close40(const RPCProcedure* proc,
                  const struct NFS4::CLOSE4args*,
                  const struct NFS4::CLOSE4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::CLOSE); } }
    void commit40(const RPCProcedure* proc,
                  const struct NFS4::COMMIT4args*,
                  const struct NFS4::COMMIT4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::COMMIT); } }
    void create40(const RPCProcedure* proc,
                  const struct NFS4::CREATE4args*,
                  const struct NFS4::CREATE4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::CREATE); } }
    void delegpurge40(const RPCProcedure* proc,
                      const struct NFS4::DELEGPURGE4args*,
                      const struct NFS4::DELEGPURGE4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::DELEGPURGE); } }
    void delegreturn40(const RPCProcedure* proc,
                       const struct NFS4::DELEGRETURN4args*,
                       const struct NFS4::DELEGRETURN4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::DELEGRETURN); } }
    void getattr40(const RPCProcedure* proc,
                   const struct NFS4::GETATTR4args*,
                   const struct NFS4::GETATTR4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::GETATTR); } }
    void getfh40(const RPCProcedure* proc,
                 const struct NFS4::GETFH4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::GETFH); } }
    void link40(const RPCProcedure* proc,
                const struct NFS4::LINK4args*,
                const struct NFS4::LINK4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LINK); } }
    void lock40(const RPCProcedure* proc,
                const struct NFS4::LOCK4args*,
                const struct NFS4::LOCK4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOCK); } }
    void lockt40(const RPCProcedure* proc,
                 const struct NFS4::LOCKT4args*,
                 const struct NFS4::LOCKT4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOCKT); } }
    void locku40(const RPCProcedure* proc,
                 const struct NFS4::LOCKU4args*,
                 const struct NFS4::LOCKU4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOCKU); } }
    void lookup40(const RPCProcedure* proc,
                  const struct NFS4::LOOKUP4args*,
                  const struct NFS4::LOOKUP4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOOKUP); } }
    void lookupp40(const RPCProcedure* proc,
                   const struct NFS4::LOOKUPP4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::LOOKUPP); } }
    void nverify40(const RPCProcedure* proc,
                   const struct NFS4::NVERIFY4args*,
                   const struct NFS4::NVERIFY4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::NVERIFY); } }
    void open40(const RPCProcedure* proc,
                const struct NFS4::OPEN4args*,
                const struct NFS4::OPEN4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::OPEN); } }
    void openattr40(const RPCProcedure* proc,
                    const struct NFS4::OPENATTR4args*,
                    const struct NFS4::OPENATTR4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::OPENATTR); } }
    void open_confirm40(const RPCProcedure* proc,
                        const struct NFS4::OPEN_CONFIRM4args*,
                        const struct NFS4::OPEN_CONFIRM4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::OPEN_CONFIRM); } }
    void open_downgrade40(const RPCProcedure* proc,
                          const struct NFS4::OPEN_DOWNGRADE4args*,
                          const struct NFS4::OPEN_DOWNGRADE4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::OPEN_DOWNGRADE); } }
    void putfh40(const RPCProcedure* proc,
                 const struct NFS4::PUTFH4args*,
                 const struct NFS4::PUTFH4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::PUTFH); } }
    void putpubfh40(const RPCProcedure* proc,
                    const struct NFS4::PUTPUBFH4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::PUTPUBFH); } }
    void putrootfh40(const RPCProcedure* proc,
                     const struct NFS4::PUTROOTFH4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::PUTROOTFH); } }
    void read40(const RPCProcedure* proc,
                const struct NFS4::READ4args*,
                const struct NFS4::READ4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::READ); } }
    void readdir40(const RPCProcedure* proc,
                   const struct NFS4::READDIR4args*,
                   const struct NFS4::READDIR4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::READDIR); } }
    void readlink40(const RPCProcedure* proc,
                    const struct NFS4::READLINK4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::READLINK); } }
    void remove40(const RPCProcedure* proc,
                  const struct NFS4::REMOVE4args*,
                  const struct NFS4::REMOVE4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::REMOVE); } }
    void rename40(const RPCProcedure* proc,
                  const struct NFS4::RENAME4args*,
                  const struct NFS4::RENAME4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::RENAME); } }
    void renew40(const RPCProcedure* proc,
                 const struct NFS4::RENEW4args*,
                 const struct NFS4::RENEW4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::RENEW); } }
    void restorefh40(const RPCProcedure* proc,
                     const struct NFS4::RESTOREFH4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::RESTOREFH); } }
    void savefh40(const RPCProcedure* proc,
                  const struct NFS4::SAVEFH4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SAVEFH); } }
    void secinfo40(const RPCProcedure* proc,
                   const struct NFS4::SECINFO4args*,
                   const struct NFS4::SECINFO4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SECINFO); } }
    void setattr40(const RPCProcedure* proc,
                   const struct NFS4::SETATTR4args*,
                   const struct NFS4::SETATTR4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SETATTR); } }
    void setclientid40(const RPCProcedure* proc,
                       const struct NFS4::SETCLIENTID4args*,
                       const struct NFS4::SETCLIENTID4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SETCLIENTID); } }
    void setclientid_confirm40(const RPCProcedure* proc,
                               const struct NFS4::SETCLIENTID_CONFIRM4args*,
                               const struct NFS4::SETCLIENTID_CONFIRM4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::SETCLIENTID_CONFIRM); } }
    void verify40(const RPCProcedure* proc,
                  const struct NFS4::VERIFY4args*,
                  const struct NFS4::VERIFY4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::VERIFY); } }
    void write40(const RPCProcedure* proc,
                 const struct NFS4::WRITE4args*,
                 const struct NFS4::WRITE4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::WRITE); } }
    void release_lockowner40(const RPCProcedure* proc,
                             const struct NFS4::RELEASE_LOCKOWNER4args*,
                             const struct NFS4::RELEASE_LOCKOWNER4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::RELEASE_LOCKOWNER); } }
    void get_dir_delegation40(const RPCProcedure* proc,
                              const struct NFS4::GET_DIR_DELEGATION4args*,
                              const struct NFS4::GET_DIR_DELEGATION4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::GET_DIR_DELEGATION); } }
    void illegal40(const RPCProcedure* proc,
                   const struct NFS4::ILLEGAL4res* res) override final { if(res) { account40_op(proc, ProcEnumNFS4::NFSProcedure::ILLEGAL); } }

    // NFSv4.1 procedures

    void compound41(const RPCProcedure*  proc,
                   const struct NFS41::COMPOUND4args*,
                   const struct NFS41::COMPOUND4res*) override final { account(proc, NFS_V41); }

    // NFSv4.1 operations
    void access41(const RPCProcedure* proc,
                  const struct NFS41::ACCESS4args*,
                  const struct NFS41::ACCESS4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::ACCESS); } }

    void close41(const RPCProcedure* proc,
                  const struct NFS41::CLOSE4args*,
                  const struct NFS41::CLOSE4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::CLOSE); } }
    void commit41(const RPCProcedure* proc,
                  const struct NFS41::COMMIT4args*,
                  const struct NFS41::COMMIT4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::COMMIT); } }
    void create41(const RPCProcedure* proc,
                  const struct NFS41::CREATE4args*,
                  const struct NFS41::CREATE4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::CREATE); } }
    void delegpurge41(const RPCProcedure* proc,
                      const struct NFS41::DELEGPURGE4args*,
                      const struct NFS41::DELEGPURGE4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::DELEGPURGE); } }
    void delegreturn41(const RPCProcedure* proc,
                       const struct NFS41::DELEGRETURN4args*,
                       const struct NFS41::DELEGRETURN4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::DELEGRETURN); } }
    void getattr41(const RPCProcedure* proc,
                   const struct NFS41::GETATTR4args*,
                   const struct NFS41::GETATTR4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GETATTR); } }
    void getfh41(const RPCProcedure* proc,
                 const struct NFS41::GETFH4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GETFH); } }
    void link41(const RPCProcedure* proc,
                const struct NFS41::LINK4args*,
                const struct NFS41::LINK4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LINK); } }
    void lock41(const RPCProcedure* proc,
                const struct NFS41::LOCK4args*,
                const struct NFS41::LOCK4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOCK); } }
    void lockt41(const RPCProcedure* proc,
                 const struct NFS41::LOCKT4args*,
                 const struct NFS41::LOCKT4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOCKT); } }
    void locku41(const RPCProcedure* proc,
                 const struct NFS41::LOCKU4args*,
                 const struct NFS41::LOCKU4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOCKU); } }
    void lookup41(const RPCProcedure* proc,
                  const struct NFS41::LOOKUP4args*,
                  const struct NFS41::LOOKUP4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOOKUP); } }
    void lookupp41(const RPCProcedure* proc,
                   const struct NFS41::LOOKUPP4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LOOKUPP); } }
    void nverify41(const RPCProcedure* proc,
                   const struct NFS41::NVERIFY4args*,
                   const struct NFS41::NVERIFY4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::NVERIFY); } }
    void open41(const RPCProcedure* proc,
                const struct NFS41::OPEN4args*,
                const struct NFS41::OPEN4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::OPEN); } }
    void openattr41(const RPCProcedure* proc,
                    const struct NFS41::OPENATTR4args*,
                    const struct NFS41::OPENATTR4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::OPENATTR); } }
    void open_confirm41(const RPCProcedure* proc,
                        const struct NFS41::OPEN_CONFIRM4args*,
                        const struct NFS41::OPEN_CONFIRM4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::OPEN_CONFIRM); } }
    void open_downgrade41(const RPCProcedure* proc,
                          const struct NFS41::OPEN_DOWNGRADE4args*,
                          const struct NFS41::OPEN_DOWNGRADE4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::OPEN_DOWNGRADE); } }
    void putfh41(const RPCProcedure* proc,
                 const struct NFS41::PUTFH4args*,
                 const struct NFS41::PUTFH4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::PUTFH); } }
    void putpubfh41(const RPCProcedure* proc,
                    const struct NFS41::PUTPUBFH4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::PUTPUBFH); } }
    void putrootfh41(const RPCProcedure* proc,
                     const struct NFS41::PUTROOTFH4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::PUTROOTFH); } }
    void read41(const RPCProcedure* proc,
                const struct NFS41::READ4args*,
                const struct NFS41::READ4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::READ); } }
    void readdir41(const RPCProcedure* proc,
                   const struct NFS41::READDIR4args*,
                   const struct NFS41::READDIR4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::READDIR); } }
    void readlink41(const RPCProcedure* proc,
                    const struct NFS41::READLINK4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::READLINK); } }
    void remove41(const RPCProcedure* proc,
                  const struct NFS41::REMOVE4args*,
                  const struct NFS41::REMOVE4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::REMOVE); } }
    void rename41(const RPCProcedure* proc,
                  const struct NFS41::RENAME4args*,
                  const struct NFS41::RENAME4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RENAME); } }
    void renew41(const RPCProcedure* proc,
                 const struct NFS41::RENEW4args*,
                 const struct NFS41::RENEW4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RENEW); } }
    void restorefh41(const RPCProcedure* proc,
                     const struct NFS41::RESTOREFH4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RESTOREFH); } }
    void savefh41(const RPCProcedure* proc,
                  const struct NFS41::SAVEFH4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SAVEFH); } }
    void secinfo41(const RPCProcedure* proc,
                   const struct NFS41::SECINFO4args*,
                   const struct NFS41::SECINFO4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SECINFO); } }
    void setattr41(const RPCProcedure* proc,
                   const struct NFS41::SETATTR4args*,
                   const struct NFS41::SETATTR4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SETATTR); } }
    void setclientid41(const RPCProcedure* proc,
                       const struct NFS41::SETCLIENTID4args*,
                       const struct NFS41::SETCLIENTID4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SETCLIENTID); } }
    void setclientid_confirm41(const RPCProcedure* proc,
                               const struct NFS41::SETCLIENTID_CONFIRM4args*,
                               const struct NFS41::SETCLIENTID_CONFIRM4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SETCLIENTID_CONFIRM); } }
    void verify41(const RPCProcedure* proc,
                  const struct NFS41::VERIFY4args*,
                  const struct NFS41::VERIFY4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::VERIFY); } }
    void write41(const RPCProcedure* proc,
                 const struct NFS41::WRITE4args*,
                 const struct NFS41::WRITE4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::WRITE); } }
    void release_lockowner41(const RPCProcedure* proc,
                             const struct NFS41::RELEASE_LOCKOWNER4args*,
                             const struct NFS41::RELEASE_LOCKOWNER4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RELEASE_LOCKOWNER); } }
    void backchannel_ctl41(const RPCProcedure* proc,
                           const struct NFS41::BACKCHANNEL_CTL4args*,
                           const struct NFS41::BACKCHANNEL_CTL4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::BACKCHANNEL_CTL); } }
    void bind_conn_to_session41(const RPCProcedure* proc,
                                const struct NFS41::BIND_CONN_TO_SESSION4args*,
                                const struct NFS41::BIND_CONN_TO_SESSION4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::BIND_CONN_TO_SESSION); } }
    void exchange_id41(const RPCProcedure* proc,
                       const struct NFS41::EXCHANGE_ID4args*,
                       const struct NFS41::EXCHANGE_ID4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::EXCHANGE_ID); } }
    void create_session41(const RPCProcedure* proc,
                          const struct NFS41::CREATE_SESSION4args*,
                          const struct NFS41::CREATE_SESSION4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::CREATE_SESSION); } }
    void destroy_session41(const RPCProcedure* proc,
                           const struct NFS41::DESTROY_SESSION4args*,
                           const struct NFS41::DESTROY_SESSION4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::DESTROY_SESSION); } }
    void free_stateid41(const RPCProcedure* proc,
                        const struct NFS41::FREE_STATEID4args*,
                        const struct NFS41::FREE_STATEID4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::FREE_STATEID); } }
    void get_dir_delegation41(const RPCProcedure* proc,
                              const struct NFS41::GET_DIR_DELEGATION4args*,
                              const struct NFS41::GET_DIR_DELEGATION4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GET_DIR_DELEGATION); } }
    void getdeviceinfo41(const RPCProcedure* proc,
                         const struct NFS41::GETDEVICEINFO4args*,
                         const struct NFS41::GETDEVICEINFO4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GETDEVICEINFO); } }
    void getdevicelist41(const RPCProcedure* proc,
                         const struct NFS41::GETDEVICELIST4args*,
                         const struct NFS41::GETDEVICELIST4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::GETDEVICELIST); } }
    void layoutcommit41(const RPCProcedure* proc,
                        const struct NFS41::LAYOUTCOMMIT4args*,
                        const struct NFS41::LAYOUTCOMMIT4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LAYOUTCOMMIT); } }
    void layoutget41(const RPCProcedure* proc,
                     const struct NFS41::LAYOUTGET4args*,
                     const struct NFS41::LAYOUTGET4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LAYOUTGET); } }
    void layoutreturn41(const RPCProcedure* proc,
                        const struct NFS41::LAYOUTRETURN4args*,
                        const struct NFS41::LAYOUTRETURN4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::LAYOUTRETURN); } }
    void secinfo_no_name41(const RPCProcedure* proc,
                              const NFS41::SECINFO_NO_NAME4args*,
                              const NFS41::SECINFO_NO_NAME4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SECINFO_NO_NAME); } }
    void sequence41(const RPCProcedure* proc,
                    const struct NFS41::SEQUENCE4args*,
                    const struct NFS41::SEQUENCE4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SEQUENCE); } }
    void set_ssv41(const RPCProcedure* proc,
                   const struct NFS41::SET_SSV4args*,
                   const struct NFS41::SET_SSV4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::SET_SSV); } }
    void test_stateid41(const RPCProcedure* proc,
                        const struct NFS41::TEST_STATEID4args*,
                        const struct NFS41::TEST_STATEID4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::TEST_STATEID); } }
    void want_delegation41(const RPCProcedure* proc,
                           const struct NFS41::WANT_DELEGATION4args*,
                           const struct NFS41::WANT_DELEGATION4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::WANT_DELEGATION); } }
    void destroy_clientid41(const RPCProcedure* proc,
                            const struct NFS41::DESTROY_CLIENTID4args*,
                            const struct NFS41::DESTROY_CLIENTID4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::DESTROY_CLIENTID); } }
    void reclaim_complete41(const RPCProcedure* proc,
                            const struct NFS41::RECLAIM_COMPLETE4args*,
                            const struct NFS41::RECLAIM_COMPLETE4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::RECLAIM_COMPLETE); } }
    void illegal41(const RPCProcedure* proc,
                   const struct NFS41::ILLEGAL4res* res) override final { if(res) { account41_op(proc, ProcEnumNFS41::NFSProcedure::ILLEGAL); } }

    virtual void flush_statistics()
    {
         out << "###  Breakdown analyzer  ###"
             << std::endl
             << "NFSv3 total procedures: "
             << nfs3_proc_total
             << ". Per procedure:"
             << std::endl;
         for(unsigned int i = 0; i < ProcEnumNFS3::count ; ++i)
         {
              out.width(12);
              out << std::left
                  << print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(i));
              out.width(5);
              out << std::right
                  << nfs3_proc_count[i];
              out.width(7);
              out.setf(std::ios::fixed, std::ios::floatfield);
              out.precision(2);
              out << (nfs3_proc_total ? ((static_cast<double>(nfs3_proc_count[i]) / static_cast<double>(nfs3_proc_total)) * 100.0) : 0);
              out.setf(std::ios::fixed | std::ios::scientific , std::ios::floatfield);
              out << '%' << std::endl;
         }

         if(!nfs3_per_proc_stat.empty())  // is not empty?
         {
            out << "Per connection info: " << std::endl;

            std::stringstream session;

             for(auto& it : nfs3_per_proc_stat)
             {
                 const Breakdown& current = it.second;
                 uint64_t s_total_proc {0};
                 for(unsigned int i = 0; i < ProcEnumNFS3::count; ++i)
                 {
                     s_total_proc += current[i].get_count();
                 }
                 session.str("");
                 print_session(session, it.first);
                 print_per_session(current, session.str(), s_total_proc, 0, NFS_V3, 0);
                 std::ofstream file(("breakdown_" + session.str() + ".dat").c_str(), std::ios::out | std::ios::trunc);
                 store_per_session(file, current, session.str(), s_total_proc, 0, NFS_V3, 0);
             }
         }

        out << "\nNFSv4.0 total procedures: "
            << nfs4_proc_total
            << ". Per procedure:"
            << std::endl;
        for(unsigned int i = 0; i < ProcEnumNFS4::count; ++i)
        {
            if(i == ProcEnumNFS4::count_proc)
                out << "NFSv4.0 total operations: "
                    << nfs4_ops_total
                    << ". Per operation:"
                    << std::endl;
            out.width(22);
            out << std::left << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(i));
            out.width(5);
            out << std::right << nfs4_proc_count[i];
            out.width(7);
            out.setf(std::ios::fixed, std::ios::floatfield);
            out.precision(2);
            if(i>=ProcEnumNFS4::count_proc)
                out << (nfs4_ops_total ? ((static_cast<double>(nfs4_proc_count[i]) / static_cast<double>(nfs4_ops_total)) * 100.0) : 0);
            else
                out << (nfs4_proc_total ? ((static_cast<double>(nfs4_proc_count[i]) / static_cast<double>(nfs4_proc_total)) * 100.0) : 0);
            out.setf(std::ios::fixed | std::ios::scientific , std::ios::floatfield);
            out << '%' << std::endl;
        }

        if(!nfs4_per_proc_stat.empty())  // is not empty?
        {
            out << "Per connection info: " << std::endl;

            std::stringstream session;

            for(auto& it : nfs4_per_proc_stat)
            {
                const Breakdown& current = it.second;
                uint64_t s_total_proc {0};
                uint64_t s_total_ops  {0};
                for(unsigned int i = 0; i < ProcEnumNFS4::count_proc; ++i)
                    s_total_proc += current[i].get_count();
                for(unsigned int i = ProcEnumNFS4::count_proc; i < ProcEnumNFS4::count; ++i)
                    s_total_ops += current[i].get_count();
                session.str("");
                print_session(session, it.first);
                print_per_session(current, session.str(), s_total_proc, s_total_ops, NFS_V4, NFS_V40);
                std::ofstream file(("breakdown_" + session.str() + ".dat").c_str(), std::ios::out | std::ios::trunc);
                store_per_session(file, current, session.str(), s_total_proc, s_total_ops, NFS_V4, NFS_V40);
            }
        }

        out << "\nNFSv4.1 total procedures: "
            << nfs41_proc_total
            << ". Per procedure:"
            << std::endl;
        for(size_t i {0}; i < ProcEnumNFS41::count; ++i)
        {
            if(i == ProcEnumNFS41::count_proc)
                out << "NFSv4.1 total operations: "
                    << nfs41_ops_total
                    << ". Per operation:"
                    << std::endl;
            out.width(22);
            out << std::left << print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(i));
            out.width(5);
            out << std::right << nfs41_proc_count[i];
            out.width(7);
            out.setf(std::ios::fixed, std::ios::floatfield);
            out.precision(2);
            if(i>=ProcEnumNFS41::count_proc)
                out << (nfs41_ops_total ? ((static_cast<double>(nfs41_proc_count[i]) / static_cast<double>(nfs41_ops_total)) * 100.0) : 0);
            else
                out << (nfs41_proc_total ? ((static_cast<double>(nfs41_proc_count[i]) / static_cast<double>(nfs41_proc_total)) * 100.0) : 0);
            out.setf(std::ios::fixed | std::ios::scientific , std::ios::floatfield);
            out << '%' << std::endl;
        }

        if(nfs41_per_proc_stat.size())  // is not empty?
        {
            out << "Per connection info: " << std::endl;

            std::stringstream session;

            for(auto& it : nfs41_per_proc_stat)
            {
                const Breakdown& current = it.second;
                uint64_t s_total_proc {0};
                uint64_t s_total_ops  {0};
                for(size_t i {0}; i < ProcEnumNFS41::count_proc; ++i)
                    s_total_proc += current[i].get_count();
                for(size_t i {ProcEnumNFS41::count_proc}; i < ProcEnumNFS41::count; ++i)
                    s_total_ops += current[i].get_count();
                session.str("");
                print_session(session, it.first);
                print_per_session(current, session.str(), s_total_proc, s_total_ops, NFS_V4, NFS_V41);
                std::ofstream file(("breakdown_" + session.str() + ".dat").c_str(), std::ios::out | std::ios::trunc);
                store_per_session(file, current, session.str(), s_total_proc, s_total_ops, NFS_V4, NFS_V41);
            }
        }
    }

    void store_per_session(std::ostream& file,
                           const Breakdown& breakdown,
                           const std::string& session,
                           uint64_t s_total_proc,
                           uint64_t s_total_ops,
                           uint32_t nfs_major_vers,
                           uint32_t nfs_minor_vers) const
    {
        file << "Session: " << session << std::endl;

        uint32_t op_count {0};

        if(nfs_major_vers == NFS_V3)
            op_count = ProcEnumNFS3::count;
        if(nfs_major_vers == NFS_V4)
        {
            if(nfs_minor_vers == NFS_V40)
                op_count = ProcEnumNFS4::count;
            if(nfs_minor_vers == NFS_V41)
                op_count = ProcEnumNFS41::count;
        }

        for(size_t i {0}; i < op_count; ++i)
        {
            if(nfs_major_vers == NFS_V3)
                file << print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(i));
            if(nfs_major_vers == NFS_V4)
            {
                if(nfs_minor_vers == NFS_V40)
                    file << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(i));
                if(nfs_minor_vers == NFS_V41)
                    file << print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(i));
            }
            file << ' ' << breakdown[i].get_count() << ' ';

            if ((nfs_major_vers == NFS_V4 && nfs_minor_vers == NFS_V40 && i >= ProcEnumNFS4::count_proc) ||
                (nfs_major_vers == NFS_V4 && nfs_minor_vers == NFS_V41 && i >= ProcEnumNFS41::count_proc))
                file << (s_total_ops ? (((T)(breakdown[i].get_count()) / s_total_ops) * 100) : 0);
            else
                file << (s_total_proc ? (((T)(breakdown[i].get_count()) / s_total_proc) * 100) : 0);

            if ((nfs_major_vers == NFS_V4 && nfs_minor_vers == NFS_V40 && i >= ProcEnumNFS4::count_proc) ||
                (nfs_major_vers == NFS_V4 && nfs_minor_vers == NFS_V41 && i >= ProcEnumNFS41::count_proc))
                file << (s_total_ops ? (((T)(breakdown[i].get_count()) / s_total_ops) * 100) : 0);
            else
                file << (s_total_proc ? (((T)(breakdown[i].get_count()) / s_total_proc) * 100) : 0);
            file << ' ' << to_sec<T>(breakdown[i].get_min())
                 << ' ' << to_sec<T>(breakdown[i].get_max())
                 << ' ' << breakdown[i].get_avg()
                 << ' ' << breakdown[i].get_st_dev()
                 << std::endl;
        }
    }

    void print_per_session(const Breakdown& breakdown,
                           const std::string& session,
                           uint64_t s_total_proc,
                           uint64_t s_total_ops,
                           uint32_t nfs_major_vers,
                           uint32_t nfs_minor_vers) const
    {
        out << "Session: " << session << std::endl;

        uint32_t op_count {0};

        if(nfs_major_vers == NFS_V3)
            op_count = ProcEnumNFS3::count;
        if(nfs_major_vers == NFS_V4)
        {
            if(nfs_minor_vers == NFS_V40)
                op_count = ProcEnumNFS4::count;
            if(nfs_minor_vers == NFS_V41)
                op_count = ProcEnumNFS41::count;
        }

        out << "Total procedures: " << s_total_proc
            << ". Per procedure:"   << std::endl;
        for(size_t i {0}; i < op_count; ++i)
        {
            if(nfs_major_vers == NFS_V4)
            {
                if ((nfs_minor_vers == NFS_V40 && i == ProcEnumNFS4::count_proc) ||
                    (nfs_minor_vers == NFS_V41 && i == ProcEnumNFS41::count_proc))
                    out << "Total operations: "
                        << s_total_ops
                        << ". Per operation:"
                        << std::endl;
            }
            out.width(22);
            if(nfs_major_vers == NFS_V3)
                out << std::left
                    << print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(i));
            if(nfs_major_vers == NFS_V4)
            {
                if(nfs_minor_vers == NFS_V40)
                    out << std::left
                        << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(i));
                if(nfs_minor_vers == NFS_V41)
                    out << std::left
                        << print_nfs41_procedures(static_cast<ProcEnumNFS41::NFSProcedure>(i));
            }
            out.width(6);
            out << " Count:";
            out.width(5);
            out << std::right
                << breakdown[i].get_count()
                << ' ';
            out.precision(2);
            out << '(';
            out.width(6);
            if ((nfs_major_vers == NFS_V4 && nfs_minor_vers == NFS_V40 && i >= ProcEnumNFS4::count_proc) ||
                (nfs_major_vers == NFS_V4 && nfs_minor_vers == NFS_V41 && i >= ProcEnumNFS41::count_proc))
                out << std::fixed
                    << (s_total_ops ? (((T)(breakdown[i].get_count()) / s_total_ops) * 100) : 0);
            else
                out << std::fixed
                    << (s_total_proc ? (((T)(breakdown[i].get_count()) / s_total_proc) * 100) : 0);
            out << "%) Min: ";
            out.precision(3);
            out << std::fixed
                << to_sec<T>(breakdown[i].get_min())
                << " Max: "
                << std::fixed
                << to_sec<T>(breakdown[i].get_max())
                << " Avg: "
                << std::fixed
                << breakdown[i].get_avg();
            out.precision(8);
            out << " StDev: "
                << std::fixed
                << breakdown[i].get_st_dev()
                << std::endl;
        }
    }

private:
    void account(const RPCProcedure* proc, const unsigned int nfs_minor_vers = NFS_V41)
    {
        typename PerOpStat::iterator i;
        const u_int nfs_proc = proc->call.ru.RM_cmb.cb_proc;
        const u_int nfs_vers = proc->call.ru.RM_cmb.cb_vers;
        timeval latency{0,0};

        // diff between 'reply' and 'call' timestamps
        timersub(proc->rtimestamp, proc->ctimestamp, &latency);

        if(nfs_vers == NFS_V4)
        {
            if(nfs_minor_vers == NFS_V40)
            {
                ++nfs4_proc_total;
                ++nfs4_proc_count[nfs_proc];

                i = nfs4_per_proc_stat.find(*(proc->session));
                if(i == nfs4_per_proc_stat.end())
                {
                    auto session_res = nfs4_per_proc_stat.emplace(*(proc->session), Breakdown{});
                    if(session_res.second == false) return;
                    i = session_res.first;
                }
            }

            if(nfs_minor_vers == NFS_V41)
            {
                ++nfs41_proc_total;
                ++nfs41_proc_count[nfs_proc];

                i = nfs41_per_proc_stat.find(*(proc->session));
                if(i == nfs41_per_proc_stat.end())
                {
                    auto session_res = nfs41_per_proc_stat.emplace(*(proc->session), Breakdown{});
                    if(session_res.second == false) return;
                    i = session_res.first;
                }
            }
        }
        else if(nfs_vers == NFS_V3)
        {
            ++nfs3_proc_total;
            ++nfs3_proc_count[nfs_proc];

            i = nfs3_per_proc_stat.find(*(proc->session));
            if(i == nfs3_per_proc_stat.end())
            {
                auto session_res = nfs3_per_proc_stat.emplace(*(proc->session), Breakdown{});
                if(session_res.second == false) return;
                i = session_res.first;
            }
        }

        (i->second)[nfs_proc].add(latency);

    }

    void account40_op(const RPCProcedure* proc, const ProcEnumNFS4::NFSProcedure operation)
    {
        typename PerOpStat::iterator i;
        timeval latency{0,0};

        // diff between 'reply' and 'call' timestamps
        timersub(proc->rtimestamp, proc->ctimestamp, &latency);

        ++nfs4_ops_total;
        ++nfs4_proc_count[operation];

        i = nfs4_per_proc_stat.find(*(proc->session));
        if(i == nfs4_per_proc_stat.end())
        {
            auto session_res = nfs4_per_proc_stat.emplace(*(proc->session), Breakdown{});
            if(session_res.second == false) return;
            i = session_res.first;
        }

        (i->second)[operation].add(latency);
    }

    void account41_op(const RPCProcedure* proc, const ProcEnumNFS41::NFSProcedure operation)
    {
        typename PerOpStat::iterator i;
        timeval latency{0,0};

        // diff between 'reply' and 'call' timestamps
        timersub(proc->rtimestamp, proc->ctimestamp, &latency);

        ++nfs41_ops_total;
        ++nfs41_proc_count[operation];

        i = nfs41_per_proc_stat.find(*(proc->session));
        if(i == nfs41_per_proc_stat.end())
        {
            auto session_res = nfs41_per_proc_stat.emplace(*(proc->session), Breakdown{});
            if(session_res.second == false) return;
            i = session_res.first;
        }

        (i->second)[operation].add(latency);
    }

    uint64_t nfs3_proc_total;
    std::vector<int> nfs3_proc_count;
    PerOpStat nfs3_per_proc_stat;

    uint64_t nfs4_proc_total;
    uint64_t nfs4_ops_total;
    std::vector<int> nfs4_proc_count;
    PerOpStat nfs4_per_proc_stat;

    uint64_t nfs41_proc_total;
    uint64_t nfs41_ops_total;
    std::vector<int> nfs41_proc_count;
    PerOpStat nfs41_per_proc_stat;

    std::ostream& out;
};

extern "C"
{

const char* usage()
{
    return "ACC - for accurate evaluation(default), MEM - for memory efficient evaluation. Options cannot be combined";
}

IAnalyzer* create(const char* optarg)
{
    enum
    {
        ACC = 0,
        MEM
    };
    const char* token[] = {
        "ACC",
        "MEM",
         NULL
    };

    char* value = NULL;
    if(*optarg == '\0')
        return new BreakdownAnalyzer<long double, OnlineVariance>();
    else
        do
        {
            switch(getsubopt((char**)&optarg, (char**)token, &value))
            {
                case ACC:
                    return new BreakdownAnalyzer<long double, TwoPassVariance>();
                case MEM:
                    return new BreakdownAnalyzer<long double, OnlineVariance>();
                default:
                    return nullptr;
            }
        } while (*optarg != '\0');
    return nullptr;
}

void destroy(IAnalyzer* instance)
{
    delete instance;
}

NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

}//extern "C"
//------------------------------------------------------------------------------
