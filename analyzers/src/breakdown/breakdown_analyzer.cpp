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
#include <list>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <map>
#include <vector>

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
    typedef std::list<timeval>::const_iterator ConstIterator;

public:
    TwoPassVariance() : count(0) {}
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

        ConstIterator i = latencies.begin();
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

        ConstIterator i = latencies.begin();
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
    TwoPassVariance(const TwoPassVariance&);    //Undefined
    void operator=(const TwoPassVariance&);     //Undefined

    uint32_t count;
    std::list<timeval> latencies;
};

template <typename T>
class OnlineVariance
{
public:
    OnlineVariance() : count(0), st_dev(), avg(), m2() {}
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
    OnlineVariance(const OnlineVariance&);    //Undefined
    void operator=(const OnlineVariance&);    //Undefined

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
    uint64_t       get_count()  const { return algorithm.get_count(); }
    long double    get_avg()    const { return algorithm.get_avg(); }
    long double    get_st_dev() const { return algorithm.get_st_dev(); }
    const timeval& get_min()    const { return min; }
    const timeval& get_max()    const { return max; }

private:
    Latencies(const Latencies&);       // Undefined
    void operator=(const Latencies&);  // Undefined

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
    BreakdownCounter(const BreakdownCounter& breakdown);  //Undefined
    void operator=(const BreakdownCounter&);       //Undefined

    Latencies<T, Algorithm> latencies[ProcEnum::count];
};

template
<
    typename T,
    template <class> class Algorithm
>
class BreakdownAnalyzer : public IAnalyzer
{
    struct Hash
    {
        std::size_t operator() (const Session& s) const
        {
            return s.port[0] + s.port[1] + s.ip.v4.addr[0] + s.ip.v4.addr[1];
        }
    };

    struct Pred
    {
        bool operator() (const Session& a, const Session& b) const
        {
            return (a.port[0] == b.port[0]) &&
                    (a.port[1] == b.port[1]) &&
                    (a.ip.v4.addr[0] == b.ip.v4.addr[0]) &&
                    (a.ip.v4.addr[1] == b.ip.v4.addr[1]);
        }
    };
    
    struct Less
    {
        bool operator() (const Session& a, const Session& b) const
        {
            return (a.port[0] < b.port[0]) &&
                    (a.port[1] < b.port[1]) &&
                    (a.ip.v4.addr[0] < b.ip.v4.addr[0]) &&
                    (a.ip.v4.addr[1] < b.ip.v4.addr[1]);
        }
    };

    typedef BreakdownCounter<T, Algorithm> Breakdown;
    typedef std::unordered_map<Session, Breakdown*, Hash, Pred> PerOpStat;
    typedef typename PerOpStat::value_type Pair;
public:
    BreakdownAnalyzer(std::ostream& o = std::cout) : total(0), ops_count(22, 0), out(o) { }
    virtual ~BreakdownAnalyzer()
    {
        typename PerOpStat::iterator i = per_op_stat.begin();
        typename PerOpStat::iterator end = per_op_stat.end();
        for(; i != end;)
        {
            delete i->second;
            i = per_op_stat.erase(i);
        }
    }

    virtual void null(const struct RPCProcedure* proc,
            const struct NULLargs*,
            const struct NULLres*) { account(proc); } 
    virtual void getattr3(const struct RPCProcedure* proc,
            const struct GETATTR3args*,
            const struct GETATTR3res*) { account(proc); }
    virtual void setattr3(const struct RPCProcedure* proc,
            const struct SETATTR3args*,
            const struct SETATTR3res*) { account(proc); }
    virtual void lookup3(const struct RPCProcedure* proc,
            const struct LOOKUP3args*,
            const struct LOOKUP3res*) { account(proc); }
    virtual void access3(const struct RPCProcedure* proc,
            const struct ACCESS3args*,
            const struct ACCESS3res*) { account(proc); }
    virtual void readlink3(const struct RPCProcedure* proc,
            const struct READLINK3args*,
            const struct READLINK3res*) { account(proc); }
    virtual void read3(const struct RPCProcedure* proc,
            const struct READ3args*,
            const struct READ3res*) { account(proc); }
    virtual void write3(const struct RPCProcedure* proc,
            const struct WRITE3args*,
            const struct WRITE3res*) { account(proc); }
    virtual void create3(const struct RPCProcedure* proc,
            const struct CREATE3args*,
            const struct CREATE3res*) { account(proc); }
    virtual void mkdir3(const struct RPCProcedure* proc,
            const struct MKDIR3args*,
            const struct MKDIR3res*) { account(proc); }
    virtual void symlink3(const struct RPCProcedure* proc,
            const struct SYMLINK3args*,
            const struct SYMLINK3res*) { account(proc); }
    virtual void mknod3(const struct RPCProcedure* proc,
            const struct MKNOD3args*,
            const struct MKNOD3res*) { account(proc); }
    virtual void remove3(const struct RPCProcedure* proc,
            const struct REMOVE3args*,
            const struct REMOVE3res*) { account(proc); }
    virtual void rmdir3(const struct RPCProcedure* proc,
            const struct RMDIR3args*,
            const struct RMDIR3res*) { account(proc); }
    virtual void rename3(const struct RPCProcedure* proc,
            const struct RENAME3args*,
            const struct RENAME3res*) { account(proc); }
    virtual void link3(const struct RPCProcedure* proc,
            const struct LINK3args*,
            const struct LINK3res*) { account(proc); }
    virtual void readdir3(const struct RPCProcedure* proc,
            const struct READDIR3args*,
            const struct READDIR3res*) { account(proc); }
    virtual void readdirplus3(const struct RPCProcedure* proc,
            const struct READDIRPLUS3args*,
            const struct READDIRPLUS3res*) { account(proc); }
    virtual void fsstat3(const struct RPCProcedure* proc,
            const struct FSSTAT3args*,
            const struct FSSTAT3res*) { account(proc); }
    virtual void fsinfo3(const struct RPCProcedure* proc,
            const struct FSINFO3args*,
            const struct FSINFO3res*) { account(proc); }
    virtual void pathconf3(const struct RPCProcedure* proc,
            const struct PATHCONF3args*,
            const struct PATHCONF3res*) { account(proc); }
    virtual void commit3(const struct RPCProcedure* proc,
            const struct COMMIT3args*,
            const struct COMMIT3res*) { account(proc); }

    virtual void flush_statistics()
    {
        out << "###  Breakdown analyzer  ###" << std::endl;
        out << "Total calls: " << total << ". Per operation:" << std::endl;
        for(int i = 0; i < ProcEnum::count; ++i)
        {
            out.width(12);
            out << std::left << static_cast<ProcEnum::NFSProcedure>(i);
            out.width(5);
            out << std::right << ops_count[i];
            out.width(7);
            out.precision(2);
            if(total)
                out << std::fixed << (double(ops_count[i]) / total) * 100;
            else
                out << 0;
            out << "%" << std::endl;
        }

        if(per_op_stat.size())  // is not empty?
        {
            out << "Per connection info: " << std::endl;

            std::stringstream session;

            // sort statistics by sessions
            typedef std::multimap<Session, Breakdown*, Less> Map;
            Map ordered(per_op_stat.begin(), per_op_stat.end());

            for(auto& it : ordered)
            {
                const Breakdown& current = *it.second;
                uint64_t s_total = 0;
                for(int i = 0; i < ProcEnum::count; ++i)
                {
                    s_total += current[i].get_count();
                }
                session.str("");
                session << it.first;
                print_per_session(current, session.str(), s_total);
                std::ofstream file(("breakdown_" + session.str() + ".dat").c_str(), std::ios::out | std::ios::trunc);
                store_per_session(file, current, session.str(), s_total);
            }
        }
    }

    void store_per_session(std::ostream& file, const Breakdown& breakdown, const std::string& session, uint64_t s_total) const
    {
        file << "Session: " << session << std::endl;

        for(int i = 0; i < ProcEnum::count; ++i)
        {
            file << static_cast<ProcEnum::NFSProcedure>(i) << ' ';
            file << breakdown[i].get_count() << ' ';
            file << ((T)(breakdown[i].get_count()) / s_total) * 100 << ' ';
            file << to_sec<T>(breakdown[i].get_min()) << ' ';
            file << to_sec<T>(breakdown[i].get_max()) << ' ';
            file << breakdown[i].get_avg() << ' ';
            file << breakdown[i].get_st_dev() << std::endl;
        }
    }

    void print_per_session(const Breakdown& breakdown, const std::string& session, uint64_t s_total) const
    {
        out << "Session: " << session << std::endl;

        out << "Total: " << s_total << ". Per operation:" << std::endl;
        for(int i = 0; i < ProcEnum::count; ++i)
        {
            out.width(14);
            out << std::left << static_cast<ProcEnum::NFSProcedure>(i);
            out.width(6);
            out << " Count:";
            out.width(5);
            out << std::right << breakdown[i].get_count();
            out << " ";
            out.precision(2);
            out << "(";
            out.width(6);
            out << std::fixed << ((T)(breakdown[i].get_count()) / s_total) * 100;
            out << "%)";
            out << " Min: ";
            out.precision(3);
            out << std::fixed << to_sec<T>(breakdown[i].get_min());
            out << " Max: ";
            out << std::fixed << to_sec<T>(breakdown[i].get_max());
            out << " Avg: ";
            out << std::fixed << breakdown[i].get_avg();
            out.precision(8);
            out << " StDev: ";
            out << std::fixed << breakdown[i].get_st_dev() << std::endl;
        }
    }

private:
    void account(const struct RPCProcedure* proc)
    {
        const int op = proc->call.proc;
        ++total;
        ++ops_count[op];

        typename PerOpStat::const_iterator i = per_op_stat.find(*(proc->session));
        if(i == per_op_stat.end())
        {
            std::pair<typename PerOpStat::iterator, bool> res = per_op_stat.insert(Pair(*(proc->session), reinterpret_cast<Breakdown*>(new Breakdown)));
            if(res.second == false)
            {
                return;
            }
            i = res.first;
        }

        timeval latency;
        timersub(proc->rtimestamp, proc->ctimestamp, &latency); // diff between 'reply' and 'call' timestamps

        Latencies<T, Algorithm>& lat = (*i->second)[op];
        lat.add(latency);
    }
    uint64_t total;
    std::vector<int> ops_count;
    PerOpStat per_op_stat;
    std::ostream& out;
};

NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

const char* usage()
{
    return "ACC - for accurate evaluation, MEM - for memory efficient evaluation(default). Options cannot be combined";
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
                    break;

                case MEM:
                    return new BreakdownAnalyzer<long double, OnlineVariance>();
                    break;

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
//------------------------------------------------------------------------------
