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
#include <signal.h>
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
    , glog       {params.log_path()}
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
        while(true)
        {
            try
            {
                status.wait_and_rethrow_exception();
            }
            catch(SignalHandler::Signal& s)
            {
                if(s.signal_number == SIGHUP)
                {
                    glog.reopen();
                }
                else
                {
                    throw ProcessingDone{std::string{"Unhandled signal presents: "} + s.what()};
                }
            }
        }
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
    gid_t re_gid = getgid();
    gid_t ef_gid = getegid();

    uid_t re_uid = getuid();
    uid_t ef_uid = geteuid();

    gid_t new_gid;
    uid_t new_uid;

    if(re_gid != ef_gid || re_uid != ef_uid) // suid bit is being set
    {
        new_gid = re_gid;
        new_uid = re_uid;

        if(!dropuser.empty())
        {
            if(utils::Out message{})
            {
                message << "Note: Ignoring -Z option since SUID bit is set.";
            }
        }
    }
    else if(!dropuser.empty())
    {
        struct passwd *pw = getpwnam(dropuser.c_str()); //get user uid & gid

        if(!pw)
        {
            throw ControllerError{std::string{"The user is not found: "} + dropuser};
        }

        new_gid = pw->pw_gid;
        new_uid = pw->pw_uid;
    }
    else
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
        if(setgroups(1, &new_gid) == -1 ||
           setgid(new_gid) == -1 ||
           setuid(new_uid) == -1)
        {
            throw ControllerError{std::string{"Error dropping root: "} +
                                  std::string{strerror(errno)}};
        }

        //check if we've really dropped privileges
        if(setuid(0) != -1)
        {
            throw ControllerError{"Managed to regain root privileges"};
        }
    }
    catch(const ControllerError& e)
    {
        if(utils::Out message{})
        {
            message << "Error dropping superuser privileges: " << e.what();
        }
        throw;
    }
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
