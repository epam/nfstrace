//------------------------------------------------------------------------------
// Author: Dzianis Huznou
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
#ifndef ANALYSIS_MANAGER_H
#define ANALYSIS_MANAGER_H
//------------------------------------------------------------------------------
#include <memory>

#include "analysis/analyzers.h"
#include "analysis/parser_thread.h"
#include "controller/parameters.h"
#include "controller/running_status.h"
#include "utils/filtered_data.h"
#include "analysis/parsers.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class AnalysisManager
{
    using Parameters        = NST::controller::Parameters;
    using RunningStatus     = NST::controller::RunningStatus;
    using FilteredDataQueue = NST::utils::FilteredDataQueue;
public:
    AnalysisManager(RunningStatus& status, const Parameters& params);
    AnalysisManager(const AnalysisManager&)            = delete;
    AnalysisManager& operator=(const AnalysisManager&) = delete;
    ~AnalysisManager() = default;

    FilteredDataQueue& get_queue() { return *queue; }

    void start();
    void stop();

private:
    std::unique_ptr<Analyzers> analysiss;
    std::unique_ptr<FilteredDataQueue> queue;
    std::unique_ptr<ParserThread<Parsers>> parser_thread;
    const NST::controller::NetProtocol protocol;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYSIS_MANAGER_H
//------------------------------------------------------------------------------
