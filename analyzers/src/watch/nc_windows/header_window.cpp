//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source for descripne ncurses header window.
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
#include <stdexcept>
#include <unistd.h>

#include "header_window.h"
#include "nc_window_const.h"
//------------------------------------------------------------------------------
namespace HEADER
{
const int MEMO_LINE = 1;
const int HOST_LINE = 2;
const int DATE_LINE = 3;
const int ELAPSED_LINE = 4;
const int HOST_SIZE = 128;
}

void HeaderWindow::destroy()
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

HeaderWindow::HeaderWindow(MainWindow& w)
: _start_time {time(NULL)}
{
    if (w._window == nullptr)
    {
        throw std::runtime_error("Initialization of Header window failed.");
    }
    resize(w);
}

HeaderWindow::~HeaderWindow()
{
}

void HeaderWindow::update()
{
    if (_window == nullptr)
    {
        return;
    }
    time_t actual_time = time(nullptr);
    tm* t = localtime(&actual_time);
    time_t shift_time = actual_time - _start_time;
    /* tm starts with 0 month and 1900 year*/
    mvwprintw(_window, HEADER::DATE_LINE, FIRST_CHAR_POS, "Date: \t %d.%d.%d \t Time: %d:%d:%d  ", t->tm_mday, t->tm_mon + 1, t->tm_year + 1900, t->tm_hour, t->tm_min, t->tm_sec);
    mvwprintw(_window, HEADER::ELAPSED_LINE, FIRST_CHAR_POS, "Elapsed time:  \t %d days; %d:%d:%d times",
              shift_time / SECINDAY, shift_time % SECINDAY / SECINHOUR, shift_time % SECINHOUR / SECINMIN, shift_time % SECINMIN);
    wrefresh (_window);
}

void HeaderWindow::resize(MainWindow& m)
{
    if (_window != nullptr)
    {
        destroy();
    }
    if (m._window != nullptr)
    {
        _window = subwin(m._window, std::min(static_cast<int>(m._window->_maxy), GUI_HEADER_HEIGHT), std::min(static_cast<int>(m._window->_maxx), GUI_LENGTH), 0, 0);
    }
    if (_window != nullptr)
    {
        werase(_window);
        wborder(_window, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);
        char HOST_NAME[HEADER::HOST_SIZE];
        gethostname(HOST_NAME, HEADER::HOST_SIZE);
        mvwprintw(_window, HEADER::MEMO_LINE, FIRST_CHAR_POS, "%s", "Nfstrace watch plugin. To scroll press up or down keys. Ctrl + c to exit.");
        mvwprintw(_window, HEADER::HOST_LINE, FIRST_CHAR_POS, "Host name:\t %s", HOST_NAME);
    }
}
//------------------------------------------------------------------------------
