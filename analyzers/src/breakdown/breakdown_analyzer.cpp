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

    Latencies<T, Algorithm> latencies[ProcEnumNFS4::count];
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
                                                     out(o) { }
    virtual ~BreakdownAnalyzer() { }

    void null(const struct RPCProcedure* proc,
              const struct NFS3::NULL3args*,
              const struct NFS3::NULL3res*) override final { account(proc); }
    void getattr3(const struct RPCProcedure* proc,
                  const struct NFS3::GETATTR3args*,
                  const struct NFS3::GETATTR3res*) override final { account(proc); }
    void setattr3(const struct RPCProcedure* proc,
                  const struct NFS3::SETATTR3args*,
                  const struct NFS3::SETATTR3res*) override final { account(proc); }
    void lookup3(const struct RPCProcedure* proc,
                 const struct NFS3::LOOKUP3args*,
                 const struct NFS3::LOOKUP3res*) override final { account(proc); }
    void access3(const struct RPCProcedure* proc,
                 const struct NFS3::ACCESS3args*,
                 const struct NFS3::ACCESS3res*) override final { account(proc); }
    void readlink3(const struct RPCProcedure* proc,
                   const struct NFS3::READLINK3args*,
                   const struct NFS3::READLINK3res*) override final { account(proc); }
    void read3(const struct RPCProcedure* proc,
               const struct NFS3::READ3args*,
               const struct NFS3::READ3res*) override final { account(proc); }
    void write3(const struct RPCProcedure* proc,
                const struct NFS3::WRITE3args*,
                const struct NFS3::WRITE3res*) override final { account(proc); }
    void create3(const struct RPCProcedure* proc,
                 const struct NFS3::CREATE3args*,
                 const struct NFS3::CREATE3res*) override final { account(proc); }
    void mkdir3(const struct RPCProcedure* proc,
                const struct NFS3::MKDIR3args*,
                const struct NFS3::MKDIR3res*) override final { account(proc); }
    void symlink3(const struct RPCProcedure* proc,
                 const struct NFS3::SYMLINK3args*,
                 const struct NFS3::SYMLINK3res*) override final { account(proc); }
    void mknod3(const struct RPCProcedure* proc,
                const struct NFS3::MKNOD3args*,
                const struct NFS3::MKNOD3res*) override final { account(proc); }
    void remove3(const struct RPCProcedure* proc,
                 const struct NFS3::REMOVE3args*,
                 const struct NFS3::REMOVE3res*) override final { account(proc); }
    void rmdir3(const struct RPCProcedure* proc,
                const struct NFS3::RMDIR3args*,
                const struct NFS3::RMDIR3res*) override final { account(proc); }
    void rename3(const struct RPCProcedure* proc,
                 const struct NFS3::RENAME3args*,
                 const struct NFS3::RENAME3res*) override final { account(proc); }
    void link3(const struct RPCProcedure* proc,
               const struct NFS3::LINK3args*,
               const struct NFS3::LINK3res*) override final { account(proc); }
    void readdir3(const struct RPCProcedure* proc,
                  const struct NFS3::READDIR3args*,
                  const struct NFS3::READDIR3res*) override final { account(proc); }
    void readdirplus3(const struct RPCProcedure* proc,
                      const struct NFS3::READDIRPLUS3args*,
                      const struct NFS3::READDIRPLUS3res*) override final { account(proc); }
    void fsstat3(const struct RPCProcedure* proc,
                 const struct NFS3::FSSTAT3args*,
                 const struct NFS3::FSSTAT3res*) override final { account(proc); }
    void fsinfo3(const struct RPCProcedure* proc,
                 const struct NFS3::FSINFO3args*,
                 const struct NFS3::FSINFO3res*) override final { account(proc); }
    void pathconf3(const struct RPCProcedure* proc,
                   const struct NFS3::PATHCONF3args*,
                   const struct NFS3::PATHCONF3res*) override final { account(proc); }
    void commit3(const struct RPCProcedure* proc,
                 const struct NFS3::COMMIT3args*,
                 const struct NFS3::COMMIT3res*) override final { account(proc); }

    void null(const struct RPCProcedure* proc,
              const struct NFS4::NULL4args*,
              const struct NFS4::NULL4res*) override final { account(proc); }
    void compound4(const struct RPCProcedure*  proc,
                   const struct NFS4::COMPOUND4args*,
                   const struct NFS4::COMPOUND4res*  res) override final { account(proc, res); }

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

         if(nfs3_per_proc_stat.size())  // is not empty?
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
                 print_per_session(current, session.str(), s_total_proc, 0, NFS_V3);
                 std::ofstream file(("breakdown_" + session.str() + ".dat").c_str(), std::ios::out | std::ios::trunc);
                 store_per_session(file, current, session.str(), s_total_proc, 0, NFS_V3);
             }
         }

        out << "\nNFSv4 total procedures: "
            << nfs4_proc_total
            << ". Per procedure:"
            << std::endl;
        for(unsigned int i = 0; i < ProcEnumNFS4::count; ++i)
        {
            if(i == ProcEnumNFS4::count_proc)
                out << "NFSv4 total operations: "
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

        if(nfs4_per_proc_stat.size())  // is not empty?
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
                print_per_session(current, session.str(), s_total_proc, s_total_ops, NFS_V4);
                std::ofstream file(("breakdown_" + session.str() + ".dat").c_str(), std::ios::out | std::ios::trunc);
                store_per_session(file, current, session.str(), s_total_proc, s_total_ops, NFS_V4);
            }
        }
    }

    void store_per_session(std::ostream& file,
                           const Breakdown& breakdown,
                           const std::string& session,
                           uint64_t s_total_proc,
                           uint64_t s_total_ops,
                           unsigned int nfs_vers) const
    {
        file << "Session: " << session << std::endl;

        unsigned int op_count {0};

        if(nfs_vers == NFS_V3) op_count = ProcEnumNFS3::count;
        if(nfs_vers == NFS_V4) op_count = ProcEnumNFS4::count;

        for(unsigned i = 0; i < op_count; ++i)
        {
            if(nfs_vers == NFS_V3)
                file << print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(i));
            if(nfs_vers == NFS_V4)
                file << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(i));
            file << ' ' << breakdown[i].get_count() << ' ';
            if(nfs_vers == NFS_V4 && i>=ProcEnumNFS4::count_proc)
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
                           unsigned int nfs_vers) const
    {
        out << "Session: " << session << std::endl;

        unsigned int op_count {0};

        if(nfs_vers == NFS_V3) op_count = ProcEnumNFS3::count;
        if(nfs_vers == NFS_V4) op_count = ProcEnumNFS4::count;

        out << "Total procedures: " << s_total_proc
            << ". Per procedure:"   << std::endl;
        for(unsigned i = 0; i < op_count; ++i)
        {
            if(nfs_vers == NFS_V4 && i == ProcEnumNFS4::count_proc)
                out << "Total operations: "
                    << s_total_ops
                    << ". Per operation:"
                    << std::endl;
            out.width(22);
            if(nfs_vers == NFS_V3)
                out << std::left
                    << print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(i));
            if(nfs_vers == NFS_V4)
                out << std::left
                    << print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(i));
            out.width(6);
            out << " Count:";
            out.width(5);
            out << std::right
                << breakdown[i].get_count()
                << ' ';
            out.precision(2);
            out << '(';
            out.width(6);
            if(nfs_vers == NFS_V4 && i>=ProcEnumNFS4::count_proc)
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
    void account(const struct RPCProcedure* proc,
                 const struct NFS4::COMPOUND4res* res = nullptr)
    {
        typename PerOpStat::iterator i;
        const u_int nfs_proc = proc->rpc_call.ru.RM_cmb.cb_proc;
        const u_int nfs_vers = proc->rpc_call.ru.RM_cmb.cb_vers;
        timeval latency{0,0};

        // diff between 'reply' and 'call' timestamps
        timersub(proc->rtimestamp, proc->ctimestamp, &latency);

        if(nfs_vers == NFS_V4)
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

            if(res)
            {
                nfs4_ops_total += res->resarray.resarray_len;

                NFS4::nfs_resop4* current_el = res->resarray.resarray_val;
                for(unsigned j=0; j<(res->resarray.resarray_len); j++, current_el++)
                {
                    // In all cases we suppose, that NFSv4 operation ILLEGAL(10044)
                    // has the second position in ProcEnumNFS4
                    u_int nfs_oper = current_el->resop;
                    if(nfs_oper == ProcEnumNFS4::NFSProcedure::ILLEGAL) nfs_oper = 2;
                    ++nfs4_proc_count[nfs_oper];

                    (i->second)[nfs_oper].add(latency);
                }
            }
        }

        if(nfs_vers == NFS_V3)
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
    uint64_t nfs3_proc_total;
    std::vector<int> nfs3_proc_count;
    PerOpStat nfs3_per_proc_stat;

    uint64_t nfs4_proc_total;
    uint64_t nfs4_ops_total;
    std::vector<int> nfs4_proc_count;
    PerOpStat nfs4_per_proc_stat;

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
                    return NULL;
            }
        } while (*optarg != '\0');
    return NULL;
}

void destroy(IAnalyzer* instance)
{
    delete instance;
}

NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

}//extern "C"
//------------------------------------------------------------------------------
