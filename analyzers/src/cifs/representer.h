//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Representer of statistic
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
#ifndef REPRESENTER_H
#define REPRESENTER_H
//------------------------------------------------------------------------------
#include <memory>
#include <ostream>

#include "commandrepresenter.h"
#include "breakdowncounter.h"
#include "statistic.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
/*! \class Represents statistic and sends it to screen
 */
class Representer
{
    std::ostream& out;
    std::unique_ptr<CommandRepresenter> cmdRepresenter;
    size_t space_for_cmd_name;

    void store_per_session(std::ostream& file,
                           const BreakdownCounter& breakdown,
                           const std::string& session,
                           uint64_t s_total_proc) const;

    void print_per_session(const BreakdownCounter& breakdown,
                           const std::string& session,
                           uint64_t s_total_proc) const;
public:
    Representer(std::ostream& o, CommandRepresenter* cmdRep, size_t space_for_cmd_name = 12);

    /*!
     * \brief flush_statistics outs statistic on screen
     * \param statistic - statistics data
     */
    void flush_statistics(const Statistic& statistic);
};
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // REPRESENTER_H
//------------------------------------------------------------------------------
