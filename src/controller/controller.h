//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CONTROLLER_H
#define CONTROLLER_H
//------------------------------------------------------------------------------
#include <memory>

#include "analysis/analysis_manager.h"
#include "filtration/filtration_manager.h"
#include "controller/parameters.h"
#include "controller/running_status.h"
#include "controller/signal_handler.h"
#include "utils/log.h"
#include "utils/out.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class Controller
{
    using AnalysisManager   = NST::analysis::AnalysisManager;
    using FiltrationManager = NST::filtration::FiltrationManager;

public:
    Controller(const Parameters& parameters);
    Controller(const Controller&)            = delete;
    Controller& operator=(const Controller&) = delete;
    ~Controller();

    int run();

private:

    // initializer for global logger
    utils::Log::Global glog;
    // initializer for global outptut
    utils::Out::Global gout;

    // storage for exceptions
    RunningStatus status;

    // signal handler
    SignalHandler signals;

    // controller subsystems
    std::unique_ptr<AnalysisManager>   analysis;
    std::unique_ptr<FiltrationManager> filtration;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif//CONTROLLER_H
//------------------------------------------------------------------------------
