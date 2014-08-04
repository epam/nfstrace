//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Class providing initializing of modules and control
// of the application.
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
namespace NST
{
namespace controller
{

class ControllerError : public std::runtime_error
{
public:
    explicit ControllerError(const std::string& msg) : std::runtime_error{msg} { }
};

class Controller
{
    using AnalysisManager   = NST::analysis::AnalysisManager;
    using FiltrationManager = NST::filtration::FiltrationManager;

    class Running
    {
    public:
        inline Running(Controller&);
        Running()                                = delete;
        Running(const Running&)                  = delete;
        const Running& operator=(const Running&) = delete;
        inline ~Running();
    private:
        Controller &controller;
    };

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
void droproot(const std::string& dropuser);

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif//CONTROLLER_H
//------------------------------------------------------------------------------
