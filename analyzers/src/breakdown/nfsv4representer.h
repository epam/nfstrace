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
#ifndef NFSV4REPRESENTER_H
#define NFSV4REPRESENTER_H
//------------------------------------------------------------------------------
#include "representer.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace breakdown
{

/**
 * @brief The NFSv4Representer class
 * Splits output into commands/operations lists for NFS v4.* protocols
 */
class NFSv4Representer : public Representer
{
    const size_t count_of_compounds;
public:
    NFSv4Representer(std::ostream& o, CommandRepresenter* cmdRep, size_t space_for_cmd_name, size_t count_of_compounds);
    void onProcedureInfoPrinted(std::ostream& o, const BreakdownCounter& breakdown, unsigned procedure) const override final;
};

} // namespace breakdown
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFSV4REPRESENTER_H
//------------------------------------------------------------------------------
