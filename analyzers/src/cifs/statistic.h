//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Statistic structure
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
#ifndef STATISTIC_H
#define STATISTIC_H
//------------------------------------------------------------------------------
#include <api/plugin_api.h>

#include "breakdowncounter.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
//------------------------------------------------------------------------------
/*! \class Comparator for session
 */
struct Less
{
    bool operator() (const Session& a, const Session& b) const;
};

/*! \class All statistic data
 */
struct Statistic
{
    using PerOpStat = std::map<Session, BreakdownCounter, Less>;
    using ProceduresCount = std::map<int, int>;

    uint64_t procedures_total_count;//!< Total amount of procedures
    ProceduresCount procedures_count;//!< Count of each procedure
    PerOpStat per_procedure_statistic;//!< Statistic for each procedure

    Statistic();
};
//------------------------------------------------------------------------------
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // STATISTIC_H
//------------------------------------------------------------------------------

