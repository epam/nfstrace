//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for descriprin ncurses windows
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
#include <cstdlib>

#include <ncurses.h>
//------------------------------------------------------------------------------
class LibWatchException : public std::exception
{
}
//------------------------------------------------------------------------------
class HeaderWindow
{
    WINDOW* _window;
    ProtocolId _activeProtocol;
    time_t _start_time;
    void destroy();

public:
    HeaderWindow() = delete;
    HeaderWindow(MainWindow&&);
    ~HeaderWindow();
    void selectProtocol(const ProtocolId&);
    void refresh();
    void resize(MainWindow&&);
};
//------------------------------------------------------------------------------
class StatisticsWindow
{
    using StatisticsConteiner = std::unordered_map<ProtocolId, NetStatistic>;

    WINDOW* _window;
    ProtocolId _activeProtocol;
    std::unordered_map<ProtocolId, int> _scrollOffset;
    std::unordered_map<std::size_t, std::size_t> _statistic;
    void destroy();

public:
    StatisticsWindow() = delete;
    StatisticsWindow(MainWindow&&);
    ~StatisticsWindow();
    void reset(const ProtocolId& , const StatisticsConteiner&);
    void scroll(unsigned int);
    void selectProtocol(const ProtocolId&);
    void refresh();
    void resize(MainWindow&&);
};
//------------------------------------------------------------------------------
class MainWindow
{
    friend class StatisticsWindow;
    friend class HeaderWindow;
    WINDOW* _window;

    uint16_t inputKeys();
    void init();
    void destroy();

public:
    MainWindow();
    ~MainWindow();
    void resize();
}
//------------------------------------------------------------------------------
