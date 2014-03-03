//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "utils/filtered_data.h"
#include "controller/controller.h"
#include "controller/parameters.h"
//------------------------------------------------------------------------------
using NST::utils::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

Controller::Controller(const Parameters& params)
    : logger     {::stderr}
    , signals    {status}
    , analysis   {}
    , filtration {new FiltrationManager{status}}
{
    logger.set_output_file(params.program_name() + ".log");
    NST::utils::Logger::set_global(&logger);

    const RunningMode mode = params.running_mode();

    if(mode == Profiling)
    {
        analysis.reset(new AnalysisManager{status, params});

        filtration->add_online_analysis(params, analysis->get_queue());
    }
    else if(mode == Dumping)
    {
        filtration->add_online_dumping(params);
    }
    else if(mode == Analysis)
    {
        analysis.reset(new AnalysisManager{status, params});

        filtration->add_offline_analysis(params.input_file(),
                                         analysis->get_queue());
    }
}

Controller::~Controller()
{
}

int Controller::run()
{
    // Start modules to processing
    filtration->start();
    if(analysis)
    {
        analysis->start();
    }

    // Waiting some exception or user-signal for handling
    // TODO: add code for recovery processing
    try
    {
        while(true)
        {
            status.wait_and_rethrow_exception();
        }
    }
    catch(...)
    {
        filtration->stop();
        if(analysis)
        {
            analysis->stop();
        }

        {
            Logger::Buffer buffer;
            status.print(buffer);
        }

        throw;
    }

    return 0;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
