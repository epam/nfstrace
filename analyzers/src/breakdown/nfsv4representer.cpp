//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Representer of NFSv4 statistics
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
#include "nfsv4representer.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
NFSv4Representer::NFSv4Representer(std::ostream& o, CommandRepresenter* cmdRep, size_t space_for_cmd_name, size_t count_of_compounds)
    : Representer(o, cmdRep, space_for_cmd_name)
    , count_of_compounds(count_of_compounds)
{
}

void NFSv4Representer::onProcedureInfoPrinted(std::ostream& o, const BreakdownCounter& breakdown, unsigned procedure) const
{
    if(procedure == 0)
    {
        o << "Total procedures: " << breakdown.get_total_count()
          << ". Per procedure:" << std::endl;
    }
    if(procedure == count_of_compounds)
    {
        o << "Total operations: " << breakdown.get_total_count()
          << ". Per operation:" << std::endl;
    }
}
