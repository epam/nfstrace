//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source for UserGui.
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
//-----------------------------------------------------------------------------
namespace
{
    const int SCROLL_UP = 1;
    const int SCROLL_DOWN = -1;
    const unsigned int MSEC = 1000000;
}
//------------------------------------------------------------------------------
void UserGUI::run()
{
    try
    {
        // prepare for select
        fd_set rfds;

        MainWindow mainWindow;
        HeaderWindow     headerWindow(mainWindow);
        StatisticsWindow statisticsWindow(mainWindow, _statisticsConteiner.at(_activeProtocolId));

        /* Watch stdin (fd 0) to see when it has input. */
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);

        /* Wait up to five seconds. */
        struct timeval tv;
        tv.tv_sec = _refresh_delta / MSEC;
        tv.tv_usec = _refresh_delta % MSEC;

        int sel_rez;
        uint16_t key = 0;

        std::vector<std::size_t> tmp(1, 0);

        statisticsWindow.updateProtocol(_activeProtocolId);

        while (_running.test_and_set())
        {
            if(_shouldResize)
            {
                mainWindow.resize();
                headerWindow.resize(mainWindow);
                statisticsWindow.resize(mainWindow);
                statisticsWindow.updateProtocol(static_cast<int>(_activeProtocolId));

                _shouldResize = false;
            }
            {
                std::unique_lock<std::mutex>lck(_statisticsDeltaMutex);
                tmp = _statisticsConteiner.at(_activeProtocolId);
            }
            headerWindow.update();
            statisticsWindow.update(tmp);
            mainWindow.update();

            sel_rez = select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv);
            if (sel_rez == -1)
               break;
            else
            {
                key = mainWindow.inputKeys();
                if(key == KEY_LEFT)
                {
                    if(_activeProtocolId != NFSv3)
                    {
                        _activeProtocolId = static_cast<ProtocolId>(static_cast<int>(_activeProtocolId) - 1);
                        statisticsWindow.setProtocol(static_cast<int>(_activeProtocolId));
                        statisticsWindow.resize(mainWindow);
                        headerWindow.update();
                        statisticsWindow.update(tmp);
                    }
                }
                else if(key == KEY_RIGHT)
                {
                    if(_activeProtocolId != CIFSv2)
                    {
                        _activeProtocolId = static_cast<ProtocolId>(static_cast<int>(_activeProtocolId) + 1);
                        statisticsWindow.setProtocol(static_cast<int>(_activeProtocolId));
                        statisticsWindow.resize(mainWindow);
                        headerWindow.update();
                        statisticsWindow.update(tmp);
                    }
                }
                else if(key == KEY_UP)
                {
                    statisticsWindow.scrolling(SCROLL_UP);
                    statisticsWindow.updateProtocol(static_cast<int>(_activeProtocolId));
                    statisticsWindow.update(tmp);
                }
                else if(key == KEY_DOWN)
                {
                    statisticsWindow.scrolling(SCROLL_DOWN);
                    statisticsWindow.updateProtocol(static_cast<int>(_activeProtocolId));
                    statisticsWindow.update(tmp);
                }
            }
            tv.tv_sec = _refresh_delta / MSEC;
            tv.tv_usec = _refresh_delta % MSEC;
        }
    }
    catch(std::runtime_error& e)
    {
        std::cerr << "Watch plugin error: " << e.what();
    }
}

UserGUI::UserGUI(const char* opts)
: _refresh_delta {900000}
, _isRunning {ATOMIC_FLAG_INIT}
, _shouldResize{false}
, _statisticsConteiner({{static_cast<int>(NFSv3),  std::vector<std::size_t>(ProcEnumNFS3::count,  0)},
                        {static_cast<int>(NFSv4),  std::vector<std::size_t>(ProcEnumNFS4::count,  0)},
                        {static_cast<int>(NFSv41), std::vector<std::size_t>(ProcEnumNFS41::count, 0)},
                        {static_cast<int>(CIFSv1), std::vector<std::size_t>(10, 0)},
                        {static_cast<int>(CIFSv2), std::vector<std::size_t>(10 ,0)}
                        })
, _activeProtocolId(NFSv3)
{
    if(opts != nullptr && *opts != '\0' ) try
    {
        _refresh_delta = std::stoul(opts);
    }
    catch(std::exception& e)
    {
        throw std::runtime_error{std::string{"Error in plugin options processing. OPTS: "} + opts + std::string(" Error: ") + e.what()};
    }
    _running.test_and_set();
    _guiThread = std::thread(&UserGUI::run, this);
}

UserGUI::~UserGUI()
{
    _running.clear();
    _guiThread.join();
}

void UserGUI::update(int p, std::vector<std::size_t>& d)
{
    std::vector<std::size_t>::iterator it;
    std::vector<std::size_t>::iterator st;
    std::unique_lock<std::mutex>lck(_statisticsDeltaMutex);
    for(it = (_statisticsConteiner.at(p)).begin(), st = d.begin(); it != (_statisticsConteiner.at(p)).end() && st != d.end(); ++it, ++st)
    {
        (*it) += (*st);
    }
}

void UserGUI::enableUpdate()
{
    _shouldResize = true;
}

//------------------------------------------------------------------------------
