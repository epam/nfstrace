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
#include <fstream>
#include <iostream>
#include <sstream>

#include "representer.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
NST::breakdown::Representer::Representer(std::ostream& o, NST::breakdown::CommandRepresenter* cmd_representer, size_t space_for_cmd_name)
    : out(o)
    , cmdRepresenter(cmd_representer)
    , space_for_cmd_name(space_for_cmd_name)
{
}

void Representer::flush_statistics(const Statistics& statistics)
{
    out << "###  Breakdown analyzer  ###"
        << std::endl
        << cmdRepresenter->protocol_name()
        << " protocol"
        << std::endl;

    statistics.for_each_procedure([&](const BreakdownCounter & breakdown, size_t procedure)
    {
        onProcedureInfoPrinted(out, breakdown, procedure);
        size_t procedure_count = breakdown[procedure].get_count();
        out.width(space_for_cmd_name);
        out << std::left
            << cmdRepresenter->command_name(procedure);
        out.width(5);
        out << std::right
            << procedure_count;
        out.width(7);
        out.setf(std::ios::fixed, std::ios::floatfield);
        out.precision(2);
        out << (breakdown.get_total_count() ? ((1.0 * procedure_count / breakdown.get_total_count()) * 100.0) : 0);
        out.setf(std::ios::fixed | std::ios::scientific , std::ios::floatfield);
        out << '%' << std::endl;
    });

    if (statistics.per_session_statistics.size())  // is not empty?
    {
        out << "Per connection info: " << std::endl;

        statistics.for_each_session([&](const Session & session)
        {
            std::stringstream ssession;
            print_session(ssession, session);
            print_per_session(statistics, session, ssession.str());
            std::ofstream file("breakdown_" + ssession.str() + ".dat", std::ios::out | std::ios::trunc);
            store_per_session(file, statistics, session, ssession.str());
        });
    }
}

void Representer::store_per_session(std::ostream& file, const Statistics& statistics, const Session& session, const std::string& ssession) const
{
    //TODO: does it make sense to join store_per_session & print_per_session?
    file << "Session: " << ssession << std::endl;

    statistics.for_each_procedure_in_session(session, [&](const BreakdownCounter & breakdown, size_t procedure)
    {
        uint64_t s_total_proc = breakdown.get_total_count();
        file << cmdRepresenter->command_name(procedure);
        file << ' ' << breakdown[procedure].get_count() << ' ';
        file << (s_total_proc ? (((long double)(breakdown[procedure].get_count()) / s_total_proc) * 100) : 0);
        file << ' ' << to_sec(breakdown[procedure].get_min())
             << ' ' << to_sec(breakdown[procedure].get_max())
             << ' ' << breakdown[procedure].get_avg()
             << ' ' << breakdown[procedure].get_st_dev()
             << std::endl;
    });
}

void Representer::print_per_session(const Statistics& statistics, const Session& session, const std::string& ssession) const
{
    out << "Session: " << ssession << std::endl;

    statistics.for_each_procedure_in_session(session, [&](const BreakdownCounter & breakdown, size_t procedure)
    {
        uint64_t s_total_proc = breakdown.get_total_count();
        onProcedureInfoPrinted(out, breakdown, procedure);
        out.width(22);
        out << std::left
            << cmdRepresenter->command_name(procedure);
        out.width(6);
        out << " Count:";
        out.width(5);
        out << std::right
            << breakdown[procedure].get_count()
            << ' ';
        out.precision(2);
        out << '(';
        out.width(6);
        out << std::fixed
            << (s_total_proc ? (static_cast<long double>(breakdown[procedure].get_count()) * 100 / s_total_proc) : 0);
        out << "%) Min: ";
        out.precision(3);
        out << std::fixed
            << to_sec(breakdown[procedure].get_min())
            << " Max: "
            << std::fixed
            << to_sec(breakdown[procedure].get_max())
            << " Avg: "
            << std::fixed
            << breakdown[procedure].get_avg();
        out.precision(8);
        out << " StDev: "
            << std::fixed
            << breakdown[procedure].get_st_dev()
            << std::endl;
    });
}

void Representer::onProcedureInfoPrinted(std::ostream& o, const BreakdownCounter& breakdown, unsigned procedure) const
{
    if (procedure == 0)
    {
        o << "Total operations: " << breakdown.get_total_count()
          << ". Per operation:"   << std::endl;
    }
}
//------------------------------------------------------------------------------
