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
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

Controller::Controller(const Parameters& params)
    : glog       {params.program_name() + ".log"}
    , gout       {utils::Out::Level(params.verbose_level())}
    , signals    {status}
    , analysis   {}
    , filtration {new FiltrationManager{status}}
{
    switch(params.running_mode())
    {
        case RunningMode::Profiling:
        {
            analysis.reset(new AnalysisManager{status, params});

            filtration->add_online_analysis(params, analysis->get_queue());
        }
        break;
        case RunningMode::Dumping:
        {
            filtration->add_online_dumping(params);
        }
        break;
        case RunningMode::Analysis:
        {
            analysis.reset(new AnalysisManager{status, params});

            filtration->add_offline_analysis(params.input_file(),
                                             analysis->get_queue());
        }
        break;
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

    if(utils::Out message{})
    {
        message << "Processing packets. Press CTRL-C to quit and view results.";
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

        if(utils::Log message{})
        {
            status.print(message);
        }

        throw;
    }

    return 0;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
