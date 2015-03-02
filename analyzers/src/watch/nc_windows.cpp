//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source for description ncurses windows.
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
#include <unistd.h>

#include "nc_windows.h"
//------------------------------------------------------------------------------
namespace
{
    const unsigned int SECINMIN  = 60;
    const unsigned int SECINHOUR = 60 * 60;
    const unsigned int SECINDAY  = 60 * 60 * 24;

    const unsigned int BORDER_SIZE = 1;

    const int MAXSHIFT = 25;
    const int SHIFTCU  = 1;

    const int GUI_LENGTH        = 80;
    const int GUI_HEADER_HEIGHT = 6;
    const int PERSENT_POS       = 29;
    const int COUNTERS_POS      = 22;

    const int FIRST_CHAR_POS = 1;
    const int EMPTY_LINE     = 1;
}
//------------------------------------------------------------------------------
uint16_t MainWindow::inputKeys()
{
    int key = wgetch(_window);
    if(key == KEY_UP || key == KEY_DOWN || key == KEY_LEFT || key == KEY_RIGHT)
    {
        if(key == KEY_UP)
        {
            do
            {
                key = getch();
            }
            while ((key != EOF) && (key != '\n') && (key != ' '));
            return KEY_UP;
        }
        else if(key == KEY_DOWN)
        {
            do
            {
                key = getch();
            }
            while ((key != EOF) && (key != '\n') && (key != ' '));
            return KEY_DOWN;
        }
        else if(key == KEY_LEFT)
        {
            do
            {
                key = getch();
            }
            while ((key != EOF) && (key != '\n') && (key != ' '));
            return KEY_LEFT;
        }
        else if(key == KEY_RIGHT)
        {
            do
            {
                key = getch();
            }
            while ((key != EOF) && (key != '\n') && (key != ' '));
            return KEY_RIGHT;
        }
    }
    else
    {
        do
        {
            key = getch();
        }
        while ((key != EOF) && (key != '\n') && (key != ' '));
    }
    return 0;
}

void MainWindow::init()
{
    if(_window != nullptr) destroy();
    _window = initscr();
    if(_window == nullptr)
    {
        throw std::runtime_error("Initialization of Main window failed.");
    }
    noecho();
    cbreak();
    intrflush(stdscr, false);     // flush main window
    curs_set(0);                  // disable blinking cursore

    keypad(_window, true);        // init keyboard
    timeout(200);                 // set keyboard timeout

    start_color();                // set background color
    if(_window != nullptr)
        werase(_window);
}

void MainWindow::destroy()
{
    nocbreak();
    echo();
    clrtoeol();
    refresh();
    endwin();
    _window = nullptr;
}

MainWindow::MainWindow()
: _window{nullptr}
{
    init();
}

MainWindow::~MainWindow()
{
    destroy();
}

void MainWindow::resize()
{
    if(_window != nullptr) destroy();
    init();
}

void MainWindow::update()
{
    if(_window != nullptr)
        refresh();
}
//------------------------------------------------------------------------------
namespace HEADER
{
    const int MEMO_LINE = 1;
    const int HOST_LINE = 2;
    const int DATE_LINE = 3;
    const int ELAPSED_LINE = 4;
}

void HeaderWindow::destroy()
{
    if(_window == nullptr) return;
    werase(_window);
    wclear(_window);
    delwin(_window);
    _window = nullptr;
}

HeaderWindow::HeaderWindow(MainWindow& w)
: _start_time{time(NULL)}
{
    if(w._window == nullptr)
    {
        throw std::runtime_error("Initialization of Header window failed.");
    }
    resize(w);
}

HeaderWindow::~HeaderWindow()
{
    destroy();
}

void HeaderWindow::update()
{
    if(_window == nullptr) return;
    time_t actual_time = time(nullptr);
    tm* t = localtime(&actual_time);
    time_t shift_time = actual_time - _start_time;
    /* tm starts with 0 month and 1900 year*/
    mvwprintw(_window, HEADER::DATE_LINE, FIRST_CHAR_POS,"Date: \t %d.%d.%d \t Time: %d:%d:%d  ",t->tm_mday, t->tm_mon + 1, t->tm_year + 1900,t->tm_hour, t->tm_min, t->tm_sec);
    mvwprintw(_window, HEADER::ELAPSED_LINE, FIRST_CHAR_POS,"Elapsed time:  \t %d days; %d:%d:%d times",
              shift_time/SECINDAY, shift_time%SECINDAY/SECINHOUR, shift_time%SECINHOUR/SECINMIN, shift_time%SECINMIN);
//    mvwhline (_window, 5, 1, ACS_HLINE, 78);
//    mvwhline (_window, 6, 1, ACS_HLINE, 78);
    wrefresh (_window);
}

void HeaderWindow::resize(MainWindow& m)
{
    if(_window != nullptr)
        destroy();
    if(m._window != nullptr)
        _window = subwin(m._window, m._window->_maxy > GUI_HEADER_HEIGHT ? GUI_HEADER_HEIGHT : m._window->_maxy, m._window->_maxx > GUI_LENGTH ? GUI_LENGTH : m._window->_maxx, 0, 0);
    if(_window != nullptr)
    {
        werase(_window);
        wborder(_window, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);
        char HOST_NAME[128];
        gethostname(HOST_NAME, 128);
        mvwprintw(_window, HEADER::MEMO_LINE, FIRST_CHAR_POS,"%s","Nfstrace watch plugin. To scroll press up or down keys. Ctrl + c to exit.");
        mvwprintw(_window, HEADER::HOST_LINE, FIRST_CHAR_POS,"Host name:\t %s",HOST_NAME);
    }
}
//------------------------------------------------------------------------------
namespace STATISTICS
{
    const int PROTOCOLS_LINE = 1;
    const int FIRST_OPERATION_LINE = 3;
    const int DEFAULT_LINES = 10;
}

void StatisticsWindow::destroy()
{
    if(_window == nullptr) return;
    werase(_window);
    wclear(_window);
    delwin(_window);
    _window = nullptr;
}

StatisticsWindow::StatisticsWindow(MainWindow& w, StatisticsContainers& c)
: _window{nullptr}
, _activeProtocol{nullptr}
{
    if(w._window == nullptr)
    {
        throw std::runtime_error("Initialization of Header window failed.");
    }
    for(auto i : c)
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
    destroy();
}

void StatisticsWindow::scrollContent(int i)
{
    if(i > 0 && _scrollOffset.at(_activeProtocol) <= MAXSHIFT - SHIFTCU)
        _scrollOffset.at(_activeProtocol) += SHIFTCU;
    else if(i < 0 && _scrollOffset.at(_activeProtocol) >= SHIFTCU)
        _scrollOffset.at(_activeProtocol) -= SHIFTCU;
}

void StatisticsWindow::updateProtocol(AbstractProtocol* p)
{
    _activeProtocol = p;
    if(_window == nullptr) return;
    werase(_window);
    wborder(_window, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);

    std::string tmp("  ");
    for(auto s : _allProtocols)
    {
        if(!s.compare(_activeProtocol->getProtocolName()))
        {
            tmp = tmp + std::string(" < ") + s + std::string(" > ");
        }
        else
        {
            tmp = tmp + std::string("   ") + s + std::string("   ");
        }
    }

    mvwprintw(_window, STATISTICS::PROTOCOLS_LINE , FIRST_CHAR_POS,"%s", tmp.c_str());

    for(unsigned int i = 0; i < p->getAmount(); i++)
    {
        if( i >= _scrollOffset.at(p) && i - _scrollOffset.at(p) + BORDER_SIZE < static_cast<unsigned int>(_window->_maxy))
            mvwprintw(_window, i + STATISTICS::FIRST_OPERATION_LINE - (_scrollOffset.at(p)), FIRST_CHAR_POS, "%s", p->printProcedure(i));
    }
}

void StatisticsWindow::update(const ProtocolStatistic& d)
{
    _statistic = d;
    std::size_t m = 0; // sum of all counters
    if(_statistic.empty() || _window == nullptr) return;
    for(auto p : _statistic)
    {
        m += p;
    }
    for(unsigned int i = 0; i < _statistic.size(); i++)
    {
        if(i >= _scrollOffset.at(_activeProtocol) && i - _scrollOffset.at(_activeProtocol) + BORDER_SIZE < static_cast<unsigned int>(_window->_maxy))
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
    if(_window != nullptr)
        destroy();
    short tmp_size;
    if(_activeProtocol != nullptr)
        tmp_size = _activeProtocol->getAmount() + 2 * BORDER_SIZE + 2 * EMPTY_LINE + STATISTICS::PROTOCOLS_LINE;
    else
        tmp_size = STATISTICS::DEFAULT_LINES;
    if(m._window != nullptr && m._window->_maxy > GUI_HEADER_HEIGHT)
    {
        _window = subwin(m._window, (m._window->_maxy - GUI_HEADER_HEIGHT > tmp_size) ? tmp_size : (m._window->_maxy - GUI_HEADER_HEIGHT) ,
                                     m._window->_maxx > GUI_LENGTH ? GUI_LENGTH : m._window->_maxx, GUI_HEADER_HEIGHT - 1, 0);
        updateProtocol(_activeProtocol);
    }
}

void StatisticsWindow::setProtocol(AbstractProtocol* p)
{
    _activeProtocol = (p);
}
