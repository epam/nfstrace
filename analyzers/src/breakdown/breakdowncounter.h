//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Statistics counter
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
#ifndef BREAKDOWNCOUNTER_H
#define BREAKDOWNCOUNTER_H
//------------------------------------------------------------------------------
#include <cinttypes>
#include <vector>

#include "latencies.h"
//------------------------------------------------------------------------------
/*! Counts and keeps breakdown statistics for session
 */
class BreakdownCounter
{
public:
    BreakdownCounter(std::size_t count);
    ~BreakdownCounter();

    /*!
     * \brief operator [] returns statistics by index (command number)
     * \param index - command number
     * \return statistics
     */
    const NST::breakdown::Latencies operator[](int index) const;

    /*!
     * \brief operator [] returns statistics by index (command number)
     * \param index - command number
     * \return statistics
     */
    NST::breakdown::Latencies& operator[](int index);

    /*!
     * \brief get_total_count returns total amount of commands
     * \return commands count
     */
    uint64_t get_total_count () const;

private:
    void operator= (const BreakdownCounter&) = delete;
    std::vector<NST::breakdown::Latencies> latencies;
};
//------------------------------------------------------------------------------
#endif//BREAKDOWNCOUNTER_H
//------------------------------------------------------------------------------
