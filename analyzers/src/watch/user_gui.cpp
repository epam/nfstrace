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
#include <algorithm>
#include <exception>
#include <iostream>
#include <system_error>

#include <unistd.h>

#include <api/plugin_api.h>
#include "nc_windows/header_window.h"
#include "nc_windows/main_window.h"
#include "nc_windows/statistics_window.h"
#include "user_gui.h"
//-----------------------------------------------------------------------------
namespace
{
const int SCROLL_UP   = 1;
const int SCROLL_DOWN = -1;
const int MSEC        = 1000000;
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
        StatisticsWindow statisticsWindow(mainWindow, _statisticsContainers);

        /* Watch stdin (fd 0) to see when it has input. */
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);

        /* Set wait time. */
        struct timeval tv = getTimeval();

        uint16_t key = 0;

        std::vector<std::size_t> tmp;

        statisticsWindow.updateProtocol(_activeProtocol);

        while (_running.test_and_set())
        {
            if (_shouldResize)
            {
                mainWindow.resize();
                headerWindow.resize(mainWindow);
                statisticsWindow.resize(mainWindow);
                statisticsWindow.updateProtocol(_activeProtocol);

                _shouldResize = false;
            }
            if (_running.test_and_set())
            {
                std::unique_lock<std::mutex>lck(_statisticsDeltaMutex);
                tmp = _statisticsContainers.at(_activeProtocol);
            }
            headerWindow.update();
            statisticsWindow.update(tmp);
            mainWindow.update();

            if( select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv) == -1)
            {
                break;
            }
            else
            {
                key = mainWindow.inputKeys();
                if (key == KEY_LEFT || key == KEY_RIGHT)
                {
                    auto it = find_if (_allProtocols.begin(), _allProtocols.end(), [&](std::string s)
                    {
                        return !(s.compare(_activeProtocol->getProtocolName()));
                    });
                    if (it != _allProtocols.end())
                    {
                        if (key == KEY_LEFT)
                        {
                            if (it + 1 == _allProtocols.end())
                                it = _allProtocols.begin();
                            else
                                ++it;
                        }
                        else if (key == KEY_RIGHT)
                        {
                            if (it == _allProtocols.begin())
                                it = _allProtocols.end() - 1;
                            else
                                --it;
                        }
                        auto a = find_if ( _statisticsContainers.begin(), _statisticsContainers.end(),[&](std::pair<AbstractProtocol*, std::vector<std::size_t> > p)
                        {
                            return !(p.first->getProtocolName().compare(*it));
                        });
                        if (a != _statisticsContainers.end())
                        {
                            _activeProtocol = a->first;
                            statisticsWindow.setProtocol(_activeProtocol);
                            statisticsWindow.resize(mainWindow);
                            {
                                std::unique_lock<std::mutex>lck(_statisticsDeltaMutex);
                                tmp = a->second;
                            }
                            statisticsWindow.update(tmp);
                        }
                    }
                }
                else if (key == KEY_UP)
                {
                    statisticsWindow.scrollContent(SCROLL_UP);
                    statisticsWindow.update(tmp);
                }
                else if (key == KEY_DOWN)
                {
                    statisticsWindow.scrollContent(SCROLL_DOWN);
                    statisticsWindow.update(tmp);
                }
            }
            tv = getTimeval();
        }
    }
    catch (std::runtime_error& e)
    {
        std::cerr << "Watch plugin error: " << e.what();
    }
}

timeval UserGUI::getTimeval()
{
    struct timeval tv;
    tv.tv_sec = _refresh_delta / MSEC;
    tv.tv_usec = _refresh_delta % MSEC;
    return tv;
}

UserGUI::UserGUI(const char* opts, std::vector<AbstractProtocol* >& data)
: _refresh_delta {900000}
, _shouldResize {false}
, _running {ATOMIC_FLAG_INIT}
, _activeProtocol(nullptr)
{
    try
    {
        if (opts != nullptr && *opts != '\0' )
        {
            _refresh_delta = std::stoul(opts);
        }
        for (auto it = data.begin(); it != data.end(); ++it)
        {
            _allProtocols.push_back((*it)->getProtocolName());
            _statisticsContainers.insert(std::make_pair<AbstractProtocol*, std::vector<std::size_t> >((AbstractProtocol*&&)(*it), std::vector<std::size_t>((*it)->getAmount(), 0)));
        }
        if (_activeProtocol == nullptr && ! data.empty())
        {
            _activeProtocol = data.back();
        }
    }
    catch (std::exception& e)
    {
        throw std::runtime_error {std::string{"Error in plugin options processing. OPTS: "} + opts + std::string(" Error: ") + e.what()};
    }
    _running.test_and_set();
    _guiThread = std::thread(&UserGUI::run, this);
}

UserGUI::~UserGUI()
{
    _running.clear();
    _guiThread.join();
}

void UserGUI::update(AbstractProtocol* p, std::vector<std::size_t>& d)
{
    std::vector<std::size_t>::iterator it;
    std::vector<std::size_t>::iterator st;
    std::unique_lock<std::mutex>lck(_statisticsDeltaMutex);
    for (it = (_statisticsContainers.at(p)).begin(), st = d.begin(); it != (_statisticsContainers.at(p)).end() && st != d.end(); ++it, ++st)
    {
        (*it) += (*st);
    }
}

void UserGUI::enableUpdate()
{
    _shouldResize = true;
}
//------------------------------------------------------------------------------
