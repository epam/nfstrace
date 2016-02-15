//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside filtration module.
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
#ifndef FILTRATION_MANAGER_H
#define FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
#include <memory>
#include <vector>

#include "controller/parameters.h"
#include "controller/running_status.h"
#include "utils/filtered_data.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
class FiltrationManager
{
    using Parameters        = NST::controller::Parameters;
    using RunningStatus     = NST::controller::RunningStatus;
    using FilteredDataQueue = NST::utils::FilteredDataQueue;

public:
    FiltrationManager(RunningStatus&);
    ~FiltrationManager();
    FiltrationManager(const FiltrationManager&) = delete;
    FiltrationManager& operator=(const FiltrationManager&) = delete;

    void add_online_dumping(const Parameters& params);                             // dump to file
    void add_offline_dumping(const Parameters& params);                            // dump to file from input file
    void add_online_analysis(const Parameters& params, FilteredDataQueue& queue);  // capture to queue
    void add_offline_analysis(const std::string& ifile, FilteredDataQueue& queue); // read file to queue

    void start();
    void stop();

private:
    RunningStatus& status;

    std::vector<std::unique_ptr<class ProcessingThread>> threads;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif // FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
