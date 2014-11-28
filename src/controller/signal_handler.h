//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Handling signals and map them to exceptions.
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
#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H
//------------------------------------------------------------------------------
#include <atomic>
#include <stdexcept>
#include <thread>

#include "controller/running_status.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class SignalHandler
{
public:
    class Signal : public std::runtime_error
    {
    public:
        explicit Signal(int sig);
        const int signal_number;
    };

    SignalHandler(RunningStatus&);
    SignalHandler(const SignalHandler&)            = delete;
    SignalHandler& operator=(const SignalHandler&) = delete;
    ~SignalHandler();

private:
    std::thread handler;
    std::atomic_flag running;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif//SIGNAL_HANDLER_H
//------------------------------------------------------------------------------

