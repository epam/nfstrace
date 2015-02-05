//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Calculator of average timeouts
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
#ifndef ONLINEVARIANCE_H
#define ONLINEVARIANCE_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <sys/time.h>
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
//------------------------------------------------------------------------------
/*!
 * \brief The OnlineVariance class
 * Calculates average timeouts
 */
class OnlineVariance
{
public:
    using T = long double;

    OnlineVariance();
    ~OnlineVariance();

    void add(const timeval& t);
    uint32_t get_count() const;
    T get_avg() const;
    T get_st_dev() const;
private:
    void operator=(const OnlineVariance&) = delete;

    uint32_t count;
    T avg;
    T m2;
};

template <typename T>
T to_sec(const timeval& val)
{
    return (((T)val.tv_sec) + ((T)val.tv_usec) / 1000000.0);
}

//------------------------------------------------------------------------------
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // ONLINEVARIANCE_H
//------------------------------------------------------------------------------

