//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for describe ncurses statistic window.
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
#ifndef STATISTICS_WINDOW_H
#define STATISTICS_WINDOW_H
//------------------------------------------------------------------------------
#include <unordered_map>
#include <vector>

#include "../protocols/abstract_protocol.h"
#include "main_window.h"
//------------------------------------------------------------------------------
class StatisticsWindow
{
    using ProtocolStatistic = std::vector<std::size_t>;
    using StatisticsContainers = std::unordered_map<AbstractProtocol*, ProtocolStatistic>;

private:
    WINDOW* _window;
    AbstractProtocol* _activeProtocol;
    std::vector<std::string> _allProtocols;
    std::unordered_map<AbstractProtocol*, unsigned int> _scrollOffset;
    ProtocolStatistic _statistic;
    void destroy();
    bool canWrite(unsigned int);

public:
    StatisticsWindow() = delete;
    StatisticsWindow(MainWindow&, StatisticsContainers&);
    ~StatisticsWindow();

    /*! Scroll content of Statistic Winodow Up or Down
    */
    void scrollContent(int);

    /*! Change active protocol. Print new protocl's commands.
    */
    void updateProtocol(AbstractProtocol*);

    /*! Update counters on Statistics Window
    */
    void update(const ProtocolStatistic&);

    /*! Resize Statistic Window
    */
    void resize(MainWindow&);

    /*! Only set active protocol, do not update new protocol's commands.
    */
    void setProtocol(AbstractProtocol*);
};
//------------------------------------------------------------------------------
#endif // STATISTICS_WINDOWS_H
//------------------------------------------------------------------------------
