//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for WatchAnalyzer based on TestAnalyzer.h
// Copyright (c) 2015 EPAM Systems. All Rights Reserved.
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
#include <exception>
#include <iostream>
#include <system_error>

#include <unistd.h>

#include <api/plugin_api.h>
#include "user_gui.h"
//------------------------------------------------------------------------------
UserGUI::UserGUI(const char* opts)
:
, _running {ATOMIC_FLAG_INIT}
, _refresh_delta {900000}
{
    if(opts != nullptr && *opts != '\0' ) try
    {
        refresh_delta = std::stoul(opts);
    }
    catch(std::exception& e)
    {
        throw std::runtime_error{std::string{"Error in plugin options processing. OPTS: "} + opts + std::string(" Error: ") + e.what()};
    }

    _runnning.test_and_set();
    _guiThread = std::thread(&UserGUI::run, this);
}

UserGUI::~UserGUI()
{
    _run.clear();
    _guiThread.join();
}


void UserGUI::run()
{
    try
    {
        // prepare for select
        fd_set rfds;

        MainWindow _main;
        HeaderWindow     _headerWindow(_main);
        StatisticsWindow _statisticsWindow(_main);

        /* Watch stdin (fd 0) to see when it has input. */
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);

        /* Wait up to five seconds. */
        struct timeval tv;
        tv.tv_sec = refresh_delta / MSEC;
        tv.tv_usec = refresh_delta % MSEC;

        int sel_rez;
        uint16_t key = 0;
        while (_run.test_and_set())
        {
            if(_shouldResize)
            {
                _main.resize();
                _headerWindow.resize(_main);
                _statisticsWindow.resize(_main);
                _shouldRefresh = false;
            }
            _headerWindow.refresh();
            _statisticsWindow.refresh();
            sel_rez = select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv);

            if (sel_rez == -1)
               break;
            else
            {
                key = _main.keyboard();
            }
            tv.tv_sec = refresh_delta / MSEC;
            tv.tv_usec = refresh_delta % MSEC;
        }
    }
    catch(LibWatchException& e)
    {
        std::cerr << "Watch plugin error: " << e.what();
    }
}
//------------------------------------------------------------------------------
