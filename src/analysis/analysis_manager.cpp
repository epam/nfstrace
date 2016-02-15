//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manager for all instances created inside analysis module.
// Copyright (c) 2013 EPAM Systems
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
#include "analysis/analysis_manager.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{
AnalysisManager::AnalysisManager(RunningStatus& status, const Parameters& params)
    : analysiss{nullptr}
    , queue{nullptr}
    , parser_thread{nullptr}
{
    analysiss.reset(new Analyzers(params));

    queue.reset(new FilteredDataQueue(params.queue_capacity(), 1));

    Parsers parser(*analysiss);
    parser_thread.reset(new ParserThread<Parsers>(parser, *queue, status));
}

void AnalysisManager::start()
{
    parser_thread->start();
}

void AnalysisManager::stop()
{
    parser_thread->stop();
    analysiss->flush_statistics();
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
