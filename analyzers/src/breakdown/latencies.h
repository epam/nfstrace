//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Latencies calculator
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
#ifndef LATENCIES_H
#define LATENCIES_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <sys/time.h>
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{

/*!
 * \brief Latencies calculates latencies
 */
class Latencies
{
public:
    Latencies();

    /*! Adds value of latency
     * \param t - timeout
     */
    void add(const timeval& t);

    /*!
     * \brief gets count of timeouts
     * \return count of timeouts
     */
    uint64_t get_count() const;

    /*!
     * \brief get_avg Gets average latency
     * \return average timeout
     */
    long double get_avg() const;

    /*!
     * \brief get_st_dev Gets latency dispertion
     * \return timeout dispertion
     */
    long double get_st_dev() const;

    /*!
     * \brief get_min Gets minimal value of latencies
     * \return minimal latency
     */
    const timeval& get_min() const;

    /*!
     * \brief get_min Gets maximal value of latencies
     * \return maximal latency
     */
    const timeval& get_max() const;

private:
    void operator=(const Latencies&) = delete;

    void set_range(const timeval& t);

    timeval min;
    timeval max;

    uint64_t count;
    long double avg;
    long double m2;
};

/*!
 * \brief to_sec Converts timeval to double
 * \param val - time struct
 * \return converted value
 */
long double to_sec(const timeval& val);

} // namespace breakdown
} // namespace NST
//------------------------------------------------------------------------------
#endif//LATENCIES_H
//------------------------------------------------------------------------------
