//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for description ncurses windows.
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
#include <stdexcept>

#include <ncurses.h>
//------------------------------------------------------------------------------
enum ProtocolId
{
    NFSv3,  //!< NFS version 3
    NFSv4,  //!< NFS version 4
    NFSv41, //!< NFS version 4.1
    CIFSv1, //!< CIFS version 1
    CIFSv2  //!< CIFS version 2
};
//------------------------------------------------------------------------------
class MainWindow
{
    friend class StatisticsWindow;
    friend class HeaderWindow;
    WINDOW* _window;

    void init();
    void destroy();

public:

    /*! Get iput keys
    */
    uint16_t inputKeys();
    MainWindow();
    ~MainWindow();

    /*! Resize Main Window
    */
    void resize();

    /*! Update Main Window
    */
    void update();
};
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
class HeaderWindow
{
    WINDOW* _window;
    time_t _start_time;
    void destroy();

public:
    HeaderWindow() = delete;
    HeaderWindow(MainWindow&);
    ~HeaderWindow();

    /*! Update Header Window
    */
    void update();

    /*! Resize Header Window
    */
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

    /*! Scroll content of Statistic Winodow Up or Down
    */
    void scrollContent(int);

    /*! Change active protocol. Print new protocl's commands.
    */
    void updateProtocol(int);

    /*! Update counters on Statistics Window
    */
    void update(const ProtocolStatistic&);

    /*! Resize Statistic Window
    */
    void resize(MainWindow&);

    /*! Only set active protocol, do not update new protocol's commands.
    */
    void setProtocol(int);
};
//------------------------------------------------------------------------------
#endif // NC_WINDOWS_H
//------------------------------------------------------------------------------
