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
#ifndef NC_WINDOWS_H
#define NC_WINDOWS_H
//------------------------------------------------------------------------------
#include <cstdlib>
#include <unordered_map>
#include <vector>

#include <ncurses.h>
//------------------------------------------------------------------------------
class LibWatchException : public std::exception
{
};
//------------------------------------------------------------------------------
enum ProtocolId
{
    NFSv3,
    NFSv4,
    NFSv41,
    CIFSv1,
    CIFSv2
};

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
class MainWindow
{
    friend class StatisticsWindow;
    friend class HeaderWindow;
    WINDOW* _window;

    void init();
    void destroy();

public:
    uint16_t inputKeys();
    MainWindow();
    ~MainWindow();
    void resize();
};
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
class HeaderWindow
{
    WINDOW* _window;
    time_t _start_time;
    ProtocolId _activeProtocol;
    void destroy();

public:
    HeaderWindow() = delete;
    HeaderWindow(MainWindow&);
    ~HeaderWindow();
    void updateProtocol(int);
    void update();
    void resize(MainWindow&);
};
//------------------------------------------------------------------------------
class StatisticsWindow
{
public:
    using ProtocolStatistic = std::vector<std::size_t>;

private:
    WINDOW* _window;
    ProtocolId _activeProtocol;
    std::unordered_map<int, unsigned int> _scrollOffset;
    ProtocolStatistic _statistic;
    void destroy();

public:
    StatisticsWindow() = delete;
    StatisticsWindow(MainWindow&, ProtocolStatistic&);
    ~StatisticsWindow();
    void scrolling(int);
    void updateProtocol(int);
    void update(const ProtocolStatistic&);
    void resize(MainWindow&);
    void setProtocol(int);
};
//------------------------------------------------------------------------------
#endif // NC_WINDOWS_H
//------------------------------------------------------------------------------
