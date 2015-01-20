//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Profiler class.
// Copyright (c) 2014 EPAM Systems
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
#include <vector>
#include <algorithm>
#include <iostream>

#include <sys/time.h>
//------------------------------------------------------------------------------
/*! \class Profiler class. Just for profiling, it is not production!
 * How to use? You have to insert this class in the begining of only 1 function (callback?)
 * ...
 * void function() {
 *     Profiler p(__func__);
 * ...
 */
class Profiler {
    const char* name = "";//!< Name of function
    const static size_t reservedBytes = 50 * 1000;//!< Reserved - calls count
    struct timespec tm1;//!< Timestamp of start function

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
            int sum = std::accumulate(values.begin(), values.end(), 0, std::plus<std::uint64_t>());
            std::cout << name << ": sum=" << sum << ", count=" << values.size() << ", avg=" << sum/values.size() << " nanosecs" << std::endl;
        }
    };
public:

    /*! Constructor
     * \param name - name of function, which you are going to profile
     */
    Profiler(const char* name)
        : name(name)
    {
        clock_gettime(CLOCK_REALTIME, &tm1);
    }

    ~Profiler()
    {
        static Local local(name);
        struct timespec tm2;
        clock_gettime(CLOCK_REALTIME, &tm2);
        local.values.push_back(tm2.tv_nsec - tm1.tv_nsec);// Assume, that time < 1 second!
    }
};
//------------------------------------------------------------------------------
#endif // PROFILER_H
//------------------------------------------------------------------------------
