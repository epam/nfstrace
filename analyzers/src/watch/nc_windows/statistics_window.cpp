//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source for describe ncurses statistics window.
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
#include <ctime>
#include <unistd.h>

#include "nc_window_const.h"
#include "statistics_window.h"
//------------------------------------------------------------------------------
namespace STATISTICS
{
const int PROTOCOLS_LINE = 1;
const int FIRST_OPERATION_LINE = 3;
const int DEFAULT_LINES = 10;
}

void StatisticsWindow::destroy()
{
    if (_window == nullptr)
    {
        return;
    }
    werase(_window);
    wclear(_window);
    delwin(_window);
    _window = nullptr;
}

bool StatisticsWindow::canWrite(unsigned int i)
{
    return (i >= _scrollOffset.at(_activeProtocol) && i - _scrollOffset.at(_activeProtocol) + BORDER_SIZE < static_cast<unsigned int>(_window->_maxy));
}

StatisticsWindow::StatisticsWindow(MainWindow& w, StatisticsContainers& c)
: _window {nullptr}
, _activeProtocol {nullptr}
{
    if (w._window == nullptr)
    {
        throw std::runtime_error("Initialization of Header window failed.");
    }
    for (auto i : c)
    {
        _allProtocols.push_back((i.first)->getProtocolName());
        _scrollOffset.insert(std::make_pair<AbstractProtocol*, std::size_t>((AbstractProtocol*)i.first, 0));
    }
    _activeProtocol = (c.begin())->first;
    _statistic = c.at(_activeProtocol);
    resize(w);
}

StatisticsWindow::~StatisticsWindow()
{
}

void StatisticsWindow::scrollContent(int i)
{
    if (i > 0 && _scrollOffset.at(_activeProtocol) <= MAXSHIFT - SHIFTCU)
    {
        _scrollOffset.at(_activeProtocol) += SHIFTCU;
    }
    else if (i < 0 && _scrollOffset.at(_activeProtocol) >= SHIFTCU)
    {
        _scrollOffset.at(_activeProtocol) -= SHIFTCU;
    }
}

void StatisticsWindow::updateProtocol(AbstractProtocol* p)
{
    _activeProtocol = p;
    if (_window == nullptr)
    {
        return;
    }
    werase(_window);
    wborder(_window, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);

    std::string tmp("  ");
    for (auto s : _allProtocols)
    {
        if (!s.compare(_activeProtocol->getProtocolName()))
        {
            tmp += std::string(" < ") + s + std::string(" > ");
        }
        else
        {
            tmp += std::string("   ") + s + std::string("   ");
        }
    }

    mvwprintw(_window, STATISTICS::PROTOCOLS_LINE , FIRST_CHAR_POS, "%s", tmp.c_str());

    for (unsigned int i = 0; i < p->getAmount(); i++)
    {
        if ( canWrite(i))
        {
            mvwprintw(_window, i + STATISTICS::FIRST_OPERATION_LINE - (_scrollOffset.at(p)), FIRST_CHAR_POS, "%s", p->printProcedure(i));
        }
    }
}

void StatisticsWindow::update(const ProtocolStatistic& d)
{
    _statistic = d;
    std::size_t m = 0; // sum of all counters
    if (_statistic.empty() || _window == nullptr)
    {
        return;
    }
    for (auto p : _statistic)
    {
        m += p;
    }
    for (unsigned int i = 0; i < _statistic.size(); i++)
    {
        if ( canWrite(i))
        {
            mvwprintw(_window, i + STATISTICS::FIRST_OPERATION_LINE - _scrollOffset.at(_activeProtocol), COUNTERS_POS, "%lu ", _statistic[i]);
            mvwprintw(_window, i + STATISTICS::FIRST_OPERATION_LINE - _scrollOffset.at(_activeProtocol), PERSENT_POS, "%-3.2f%% ",
                      m > 0 ? static_cast<double>(_statistic[i]) / static_cast<double>(m) * 100.0 : 0.0);
        }
    }

    wrefresh(_window);
}

void StatisticsWindow::resize(MainWindow& m)
{
    if (_window != nullptr)
    {
        destroy();
    }
    int tmp_size;
    if (_activeProtocol != nullptr)
    {
        tmp_size = _activeProtocol->getAmount() + 2 * BORDER_SIZE + 2 * EMPTY_LINE + STATISTICS::PROTOCOLS_LINE;
    }
    else
    {
        tmp_size = STATISTICS::DEFAULT_LINES;
    }
    if (m._window != nullptr && m._window->_maxy > GUI_HEADER_HEIGHT)
    {
        _window = subwin(m._window, std::min(static_cast<int>(m._window->_maxy - GUI_HEADER_HEIGHT), tmp_size),
                         std::min(static_cast<int>(m._window->_maxx), GUI_LENGTH), GUI_HEADER_HEIGHT - BORDER_SIZE, 0);
        updateProtocol(_activeProtocol);
    }
}

void StatisticsWindow::setProtocol(AbstractProtocol* p)
{
    _activeProtocol = (p);
}
//------------------------------------------------------------------------------