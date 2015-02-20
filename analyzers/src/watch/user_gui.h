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
#ifndef USERGUI_H
#define USERGUI_H
//------------------------------------------------------------------------------
#include <atomic>
#include <cstdlib>
#include <mutex>
#include <vector>
#include <thread>

#include <ncurses.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
class UserGUI
{
    using StatisticsConteiner = std::unordered_map<ProtocolId, NetStatistic>;

    unsigned long _refresh_delta;

    std::atomic<bool> _isRunning;
    std::atomic<bool> _shouldResize;
    std::mutex _statisticsDeltaMutex;
    std::atomic_flag _running;

    StatisticsConteiner _statisticsConteiner;

    ProtocolId activeProtocolId;

    std::thread _guiThread;

    void run();
    void selectProtocol(ProtocolId); // TODO not implemented
public:
    UserGUI() = delete;
    explicit UserGUI(const char*);
    ~UserGUI();

    void update(const ProtocolId& , const StatisticsConteiner&); // TODO not implemented
    void refresh();                                              // TODO not implemented
    void enableUpdate();                                         // TODO not implemented
 };
//------------------------------------------------------------------------------
#endif // USERGUI_H
//------------------------------------------------------------------------------
