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
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils/filtered_data.h"
#include "controller/controller.h"
#include "controller/parameters.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

Controller::Running::Running(Controller& i)
    : controller(i)
{
    controller.filtration->start();
    if(controller.analysis)
    {
        controller.analysis->start();
    }
    if(utils::Out message{})
    {
        message << "Processing packets. Press CTRL-C to quit and view results.";
    }
}

Controller::Running::~Running()
{
    controller.filtration->stop();
    if(controller.analysis)
    {
        controller.analysis->stop();
    }
}

Controller::Controller(const Parameters& params) try
    : gout       {utils::Out::Level(params.verbose_level())}
    , glog       {params.program_name()}
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
        case RunningMode::Draining:
        {
            filtration->add_offline_dumping(params);
        }
        break;
    }
    droproot(params.dropuser());
}
catch(const filtration::pcap::PcapError& e)
{
    if(utils::Out message{})
    {
        message << "Note: This operation may require that you have special privileges.";
    }
    throw;
}

Controller::~Controller()
{
}

int Controller::run()
{
    try
    {
        Running running{*this};
        status.wait_and_rethrow_exception();
    }
    catch(ProcessingDone& e)
    {
        if(utils::Out message{})
        {
            message << e.what();
        }
    }
    if(utils::Log message{})
    {
        status.print(message);
    }
    return 0;
}

void droproot(const std::string& dropuser)
{
    if(dropuser.empty()) // username is not passed
    {
        if(utils::Out message{})
        {
            message << "Note: It's potentially unsafe to run this program as root "
                    << "without dropping root privileges.\n"
                    << "Note: Use -Z username option for dropping root privileges "
                    << "when you run this program as user with root privileges.";
        }
        return;
    }
    try
    {
        struct passwd *pw = getpwnam(dropuser.c_str());//get user uid&gid
        if(!pw)
        {
            throw ControllerError{std::string{"The user is not found: "} + dropuser};
        }
        int status{0};
        if( 
           (status = initgroups(pw->pw_name, pw->pw_gid)) ||
           (status = setgid(pw->pw_gid)) ||
           (status = setuid(pw->pw_uid))
          )
        {
            throw ControllerError{strerror(status)};
        }
        //check if we've really dropped privileges to non-root capable user
        if(setuid(0) != -1) throw ControllerError{"Managed to regain root privileges"};
    }
    catch(const ControllerError& e)
    {
        if(utils::Out message{})
        {
            message << "Superuser privileges can not be dropped.";
        }
        throw;
    }
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
