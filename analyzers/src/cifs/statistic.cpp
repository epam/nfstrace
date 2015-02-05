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
#include "statistic.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
bool Less::operator()(const Session& a, const Session& b) const
{
    return ((a.port[0] < b.port[0]) && (a.port[1] <= b.port[1])) ||
           ((a.ip.v4.addr[0] < b.ip.v4.addr[0]) && (a.ip.v4.addr[1] <= b.ip.v4.addr[1]));
}

Statistic::Statistic() : procedures_total_count {0} {}
//------------------------------------------------------------------------------
