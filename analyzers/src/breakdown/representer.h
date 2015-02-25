//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Representer of statistics
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
#include "statistics.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{
/*! \class Represents statistics and sends it to screen
 */
class Representer
{
    std::ostream& out;
    std::unique_ptr<CommandRepresenter> cmd_representer;
    size_t space_for_cmd_name;

    void store_per_session(std::ostream& file,
                           const Statistics& statistics,
                           const Session& session,
                           const std::string& ssession) const;

    void print_per_session(const Statistics& statistics, const Session& session, const std::string& ssession) const;
protected:
    /**
     * @brief handler of one procedure output event
     * @param o - stream
     * @param breakdown - current counter
     * @param procedure - procedure ID
     */
    virtual void onProcedureInfoPrinted(std::ostream& o, const BreakdownCounter& breakdown, unsigned procedure) const;
public:
    /**
     * @brief Representer's constructor
     * @param o - output stream
     * @param cmd_representer - command representer
     * @param space_for_cmd_name - spaces amount in output table (column's wifth)
     */
    Representer(std::ostream& o, CommandRepresenter* cmd_representer, size_t space_for_cmd_name = 12);

    /*!
     * \brief flush_statistics outs statistics on screen
     * \param statistics - statistics data
     */
    void flush_statistics(const Statistics& statistics);
};
} // breakdown
} // NST
//------------------------------------------------------------------------------
#endif // REPRESENTER_H
//------------------------------------------------------------------------------
