///------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Operation CIFS analyzer. Identify clients that are busier than others.
// Copyright (c) 2014 EPAM Systems
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
#include <api/plugin_api.h>

#include "cifsv1breakdownanalyzer.h"
#include "cifsv2breakdownanalyzer.h"
#include "nfsv3breakdownanalyzer.h"
#include "nfsv41breakdownanalyzer.h"
#include "nfsv4breakdownanalyzer.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;
//------------------------------------------------------------------------------
class Analyzer : public CIFSBreakdownAnalyzer, public CIFSv2BreakdownAnalyzer, public NFSv3BreakdownAnalyzer, public NFSv4BreakdownAnalyzer, public NFSv41BreakdownAnalyzer
{
public:
    void flush_statistics() override final
    {
        CIFSBreakdownAnalyzer::flush_statistics();
        CIFSv2BreakdownAnalyzer::flush_statistics();
        NFSv3BreakdownAnalyzer::flush_statistics();
        NFSv4BreakdownAnalyzer::flush_statistics();
        NFSv41BreakdownAnalyzer::flush_statistics();
    }
};

extern "C"
{

    const char* usage()
    {
        return "No options";
    }

    IAnalyzer* create(const char*)
    {
        return new Analyzer();
    }

    void destroy(IAnalyzer* instance)
    {
        delete instance;
    }

    NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

}//extern "C"
//------------------------------------------------------------------------------
