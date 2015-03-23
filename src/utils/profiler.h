//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Profiler class.
// Copyright (c) 2015 EPAM Systems
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
#ifndef PROFILER_H
#define PROFILER_H
//------------------------------------------------------------------------------
#include <functional>
#include <iostream>
#include <numeric>
#include <vector>

#include <sys/time.h>
//------------------------------------------------------------------------------
#ifdef PROFILING
#define PROF Profiler<__COUNTER__> p(__func__)
#else
#define PROF
#endif
//------------------------------------------------------------------------------
/*! \class Profiler class. Just for profiling, it is not production!
 * \param id - identificator of profiler. For different functions we have to use different id
 * How to use? You have to insert this class in the begining of only 1 function (callback?)
 * ...
 * void function() {
 *     Profiler<__COUNTER__> p(__func__);
 *     // or just
 *     PROF;
 * ...
 */
template<int id>
class Profiler
{
    const char* name = "";//!< Name of function
    const static size_t reservedBytes = 50 * 1000;//!< Reserved - calls count
    struct timespec startTime;//!< Timestamp of start function

    class Local
    {
        const char* name = "";
    public:
        std::vector<std::uint64_t> values;
        Local(const char* name)
            : name(name)
        {
            values.reserve(reservedBytes);
        }

        ~Local()
        {
            std::uint64_t sum = std::accumulate(values.begin(), values.end(), 0, std::plus<std::uint64_t>());
            std::cout << name << "(" << id << "): calls count=" << values.size() << ", avg time=" << sum / values.size() << " nanosecs" << std::endl;
        }
    };
public:

    /*! Constructor
     * \param name - name of function, which you are going to profile
     */
    Profiler(const char* name)
        : name(name)
    {
        clock_gettime(CLOCK_REALTIME, &startTime);
    }

    ~Profiler()
    {
        struct timespec stopTime;
        clock_gettime(CLOCK_REALTIME, &stopTime);

        static Local local(name);// Time of vector initialization is not included into statistics

        local.values.push_back(stopTime.tv_nsec - startTime.tv_nsec);// Assume, that time < 1 second!
    }

};
//------------------------------------------------------------------------------
#endif//PROFILER_H
//------------------------------------------------------------------------------
