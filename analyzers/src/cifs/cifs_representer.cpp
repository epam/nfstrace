//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Representer of CIFS messages
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

#include "cifs_representer.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
NST::breakdown::Representer::Representer(std::ostream& o, NST::breakdown::CommandRepresenter* cmdRep)
    : out(o)
    , cmdRepresenter(cmdRep)
{
}

void Representer::flush_statistics(const Statistic& statistic)
{
    out << "###  Breakdown analyzer  ###"
        << std::endl
        << "CIFS total procedures: "
        << statistic.procedures_total_count
        << ". Per procedure:"
        << std::endl;

    for (const auto& procedure : statistic.procedures_count)
    {
        //FIXME: Sync primitives to be used
        out.width(12);
        out << std::left
            << cmdRepresenter->command_description(procedure.first);
        out.width(5);
        out << std::right
            << procedure.second;
        out.width(7);
        out.setf(std::ios::fixed, std::ios::floatfield);
        out.precision(2);
        out << (statistic.procedures_total_count ? ((1.0 * procedure.second / statistic.procedures_total_count) * 100.0) : 0);
        out.setf(std::ios::fixed | std::ios::scientific , std::ios::floatfield);
        out << '%' << std::endl;
    };

    if (statistic.per_procedure_statistic.size())  // is not empty?
    {
        out << "Per connection info: " << std::endl;

        std::stringstream session;

        for (auto& it : statistic.per_procedure_statistic)
        {
            const BreakdownCounter& current = it.second;
            uint64_t s_total_proc = current.get_total_count();

            session.str("");
            //print_session(session, it.first);//FIXME: print session
            print_per_session(current, session.str(), s_total_proc);
            std::ofstream file(("breakdown_" + session.str() + ".dat").c_str(), std::ios::out | std::ios::trunc);
            store_per_session(file, current, session.str(), s_total_proc);
        }
    }
}

void Representer::store_per_session(std::ostream& file, const BreakdownCounter& breakdown, const std::string& session, uint64_t s_total_proc) const
{
    file << "Session: " << session << std::endl;

    for (unsigned i = 0; i < cmdRepresenter->commands_count(); ++i)
    {
        file << cmdRepresenter->command_name(i);
        file << ' ' << breakdown[i].get_count() << ' ';
        file << (s_total_proc ? (((long double)(breakdown[i].get_count()) / s_total_proc) * 100) : 0);
        file << ' ' << to_sec(breakdown[i].get_min())
             << ' ' << to_sec(breakdown[i].get_max())
             << ' ' << breakdown[i].get_avg()
             << ' ' << breakdown[i].get_st_dev()
             << std::endl;
    }
}

void Representer::print_per_session(const BreakdownCounter& breakdown, const std::string& session, uint64_t s_total_proc) const
{
    out << "Session: " << session << std::endl;

    out << "Total procedures: " << s_total_proc
        << ". Per procedure:"   << std::endl;
    for (unsigned i = 0; i < cmdRepresenter->commands_count(); ++i)
    {
        out.width(22);
        out << std::left
            << cmdRepresenter->command_name(i);
        out.width(6);
        out << " Count:";
        out.width(5);
        out << std::right
            << breakdown[i].get_count()
            << ' ';
        out.precision(2);
        out << '(';
        out.width(6);
        out << std::fixed
            << (s_total_proc ? (((long double)(breakdown[i].get_count()) / s_total_proc) * 100) : 0);
        out << "%) Min: ";
        out.precision(3);
        out << std::fixed
            << to_sec(breakdown[i].get_min())
            << " Max: "
            << std::fixed
            << to_sec(breakdown[i].get_max())
            << " Avg: "
            << std::fixed
            << breakdown[i].get_avg();
        out.precision(8);
        out << " StDev: "
            << std::fixed
            << breakdown[i].get_st_dev()
            << std::endl;
    }
}
//------------------------------------------------------------------------------
