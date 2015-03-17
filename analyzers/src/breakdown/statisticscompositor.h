//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Statistics compositor
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
#ifndef STATISTICSCOMPOSITOR_H
#define STATISTICSCOMPOSITOR_H
//------------------------------------------------------------------------------
#include "statistics.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{

/**
 * @brief Composes 2 statistics: for procedures and functions
 * It is useful for NFS v4.* protocols
 */
class StatisticsCompositor : public Statistics
{
    Statistics& procedures_stats;
public:
    StatisticsCompositor(Statistics& procedures_stats, Statistics& operations_stats);
    void for_each_procedure(std::function<void(const BreakdownCounter&, size_t)> on_procedure) const override;
    void for_each_procedure_in_session(const Session& session, std::function<void(const BreakdownCounter&, size_t)> on_procedure) const override;
    bool has_session() const override;
};

} // namespace breakdown
} // namespace NST
//------------------------------------------------------------------------------
#endif//STATISTICSCOMPOSITOR_H
//------------------------------------------------------------------------------
