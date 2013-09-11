//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "controller.h"
#include "parameters.h"
#include "../auxiliary/filtered_data.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

Controller::Controller(const Parameters& params) : logger(::stderr), sig_handler(status), filtration(status), analysis(status)
{
    logger.set_output_file(params.program_name() + ".log");
    NST::auxiliary::Logger::set_global(&logger);

    const RunningMode mode = params.running_mode();

    if(mode == Profiling)
    {
        FilteredDataQueue& queue = analysis.init(params);

        filtration.capture_to_queue(queue, params);
    }
    else if(mode == Filtration)
    {
        filtration.dump_to_file(params);
    }
    else if(mode == Analysis)
    {
        FilteredDataQueue& queue = analysis.init(params);

        filtration.read_to_queue(queue, params);
    }
}

Controller::~Controller()
{
}

int Controller::run()
{
    // Start handling user signals
    sig_handler.create();

    // Start modules to processing
    filtration.start();
    analysis.start();

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
        filtration.stop();
        analysis.stop();
        {
            Logger::Buffer buffer;
            status.print(buffer);
        }
        sig_handler.stop();
        throw;
    }

    return 0;
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
