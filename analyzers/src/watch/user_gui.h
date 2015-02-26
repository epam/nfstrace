//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for UserGUI
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
#ifndef USERGUI_H
#define USERGUI_H
//------------------------------------------------------------------------------
#include <atomic>
#include <cstdlib>
#include <mutex>
#include <vector>
#include <thread>

#include <ncurses.h>
#include "nc_windows.h"
//------------------------------------------------------------------------------
class UserGUI
{
public:
    using ProtocolStatistic = std::vector<std::size_t>;
    using StatisticsContainers = std::unordered_map<AbstractProtocol* , ProtocolStatistic>;

private:
    unsigned long _refresh_delta;

    std::atomic<bool> _shouldResize;
    std::mutex _statisticsDeltaMutex;
    std::atomic_flag _running;

    StatisticsContainers _statisticsContainers;

    ProtocolId _activeProtocolId;
    AbstractProtocol* _activeProtocol;
    std::thread _guiThread;
    std::vector<std::string> _allProtocols;
    void run();
public:

    UserGUI() = delete;
    explicit UserGUI(const char*);
    ~UserGUI();

    /*! Used for save all protocols.
    */
    void push_protocols(const std::vector<AbstractProtocol*>&);

    /*! Update Protocol's data.
    */
    void update(AbstractProtocol* , std::vector<std::size_t>&);

    /*! Enable screen full update. Use for resize main window.
    */
    void enableUpdate();
 };
//------------------------------------------------------------------------------
#endif // USERGUI_H
//------------------------------------------------------------------------------
