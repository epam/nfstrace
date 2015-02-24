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
#include <unistd.h>

#include <api/plugin_api.h> // include plugin development definitions
#include "nc_windows.h"
//------------------------------------------------------------------------------
namespace
{
    const char *ProtocolsNames[] = {"NFS v3", "NFS v4", "NFS v41", "CIFS v1", "CIFS v2", nullptr};
    const char *ProtocolsActiveNames[] = {"< NFS v3 >", "< NFS v4 >", "< NFS v41 >", "< CIFS v1 >", "< CIFS v2 >", nullptr};
    const unsigned int SECINMIN  = 60;
    const unsigned int SECINHOUR = 60 * 60;
    const unsigned int SECINDAY  = 60 * 60 * 24;

    const int MAXSHIFT = 25;
    const int SHIFTCU  = 1;

    const int GUI_LENGTH = 80;
    const int GUI_HEADER_HEIGHT = 9;
    const int GUI_STATISTIC_HEIGHT = 40;
    const int PERSENT_POS = 29;
    const int COUNTERS_POS = 22;
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
        }
        else if(key == KEY_DOWN)
        {
            do
            {
                key = getch();
            }
            while ((key != EOF) && (key != '\n') && (key != ' '));
        }
        else if(key == KEY_LEFT)
        {
            do
            {
                key = getch();
            }
            while ((key != EOF) && (key != '\n') && (key != ' '));
        }
        else if(key == KEY_RIGHT)
        {
            do
            {
                key = getch();
            }
            while ((key != EOF) && (key != '\n') && (key != ' '));
        }
    }
    else
    {
        do
        {
            key = getch();
        }
        while ((key != EOF) && (key != '\n') && (key != ' '));
        key = 0;
    }
    return key;
}

void MainWindow::init()
{
    if(_window != nullptr) destroy();
    _window = initscr();
    if(_window == nullptr)
    {
        throw LibWatchException(); //"Initialization of Main window failed.");
    }
    noecho();
    cbreak();
    intrflush(stdscr, false);     // flush main window
    curs_set(0);                  // disable blinking cursore

    keypad(_window, true);        // init keyboard
    timeout(200);                 // set keyboard timeout
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
    _window = nullptr;
    nocbreak();
    echo();
    clrtoeol();
    refresh();
    endwin();
}
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void HeaderWindow::destroy()
{
    if(_window == nullptr) return;
    wclear(_window);
    delwin(_window);
    _window = nullptr;
}

HeaderWindow::HeaderWindow(MainWindow& w)
: _start_time{time(NULL)}
, _activeProtocol{NFSv3}
{
    if(w._window == nullptr)
    {
        throw LibWatchException(); //"Initialization of Header window failed.");
    }
    resize(w);
}

HeaderWindow::~HeaderWindow()
{
    destroy();
}

void HeaderWindow::updateProtocol(int p)
{

    _activeProtocol = static_cast<ProtocolId>(p);
    if(_window == nullptr) return;

    mvwprintw(_window, 7, 1,"%s    |%s    |%s    |%s    |%s",
              _activeProtocol == NFSv3  ? ProtocolsActiveNames[static_cast<int>(NFSv3) ] : ProtocolsNames[static_cast<int>(NFSv3) ],
              _activeProtocol == NFSv4  ? ProtocolsActiveNames[static_cast<int>(NFSv4) ] : ProtocolsNames[static_cast<int>(NFSv4) ],
              _activeProtocol == NFSv41 ? ProtocolsActiveNames[static_cast<int>(NFSv41)] : ProtocolsNames[static_cast<int>(NFSv41)],
              _activeProtocol == CIFSv1 ? ProtocolsActiveNames[static_cast<int>(CIFSv1)] : ProtocolsNames[static_cast<int>(CIFSv1)],
              _activeProtocol == CIFSv2 ? ProtocolsActiveNames[static_cast<int>(CIFSv2)] : ProtocolsNames[static_cast<int>(CIFSv2)]);
}

void HeaderWindow::update()
{
    if(_window == nullptr) return;
    time_t actual_time = time(nullptr);
    tm* t = localtime(&actual_time);
    time_t shift_time = actual_time - _start_time;
    mvwprintw(_window, 3, 1,"Date: \t %d.%d.%d \t Time: %d:%d:%d  ",t->tm_mday, t->tm_mon + 1, t->tm_year + 1900,t->tm_hour, t->tm_min, t->tm_sec);
    mvwprintw(_window, 4, 1,"Elapsed time:  \t %d days; %d:%d:%d times",
             shift_time/SECINDAY, shift_time%SECINDAY/SECINHOUR, shift_time%SECINHOUR/SECINMIN, shift_time%SECINMIN);
    mvwprintw(_window, 5, 1,"Date: \t %d.%d.%d \t Time: %d:%d:%d  ",t->tm_mday, t->tm_mon + 1, t->tm_year + 1900,t->tm_hour, t->tm_min, t->tm_sec);
    mvwhline (_window, 6, 1, ACS_HLINE, 78);
    updateProtocol(static_cast<int>(_activeProtocol));
    wrefresh (_window);
}

void HeaderWindow::resize(MainWindow& m)
{
    if(_window != nullptr) destroy();
    _window = subwin(m._window, m._window->_maxy > GUI_HEADER_HEIGHT ? GUI_HEADER_HEIGHT : m._window->_maxy, m._window->_maxx > GUI_LENGTH ? GUI_LENGTH : m._window->_maxx, 0, 0);
    if(_window != nullptr)
    {
        wborder(_window, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);
        char HOST_NAME[128];
        gethostname(HOST_NAME, 128);
        mvwprintw(_window, 1, 1,"%s","Nfstrace watch plugin. To scroll press up or down keys. Ctrl + c to exit.");
        mvwprintw(_window, 2, 1,"Host name:\t %s",HOST_NAME);
    }
    update();
}
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void StatisticsWindow::destroy()
{
    if(_window == nullptr) return;
    wclear(_window);
    delwin(_window);
    _window = nullptr;
}

StatisticsWindow::StatisticsWindow(MainWindow& w, ProtocolStatistic& c)
: _window{nullptr}
, _activeProtocol{NFSv3}
, _scrollOffset({{static_cast<int>(NFSv3), 0}, {static_cast<int>(NFSv4), 0} ,{static_cast<int>(NFSv41), 0}, {static_cast<int>(CIFSv1), 0}, {static_cast<int>(CIFSv2), 0}})
, _statistic(c)
{
    if(w._window == nullptr)
    {
        throw LibWatchException();//"Initialization of Header window failed.");
    }
    resize(w);
}

StatisticsWindow::~StatisticsWindow()
{
    destroy();
}

void StatisticsWindow::scrolling(int i)
{
    if(i > 0 && _scrollOffset.at(_activeProtocol) <= MAXSHIFT - SHIFTCU)
        _scrollOffset.at(static_cast<int>(_activeProtocol)) += SHIFTCU;
    else if(i < 0 && _scrollOffset.at(_activeProtocol) >= SHIFTCU)
        _scrollOffset.at(static_cast<int>(_activeProtocol)) -= SHIFTCU;
}

void StatisticsWindow::updateProtocol(int /*p*/, const ProtocolStatistic& /*d*/)
{
/*
    _activeProtocol = static_cast<ProtocolId>(p);
//    _statistic.clear();
    _statistic = d;
    if(_window == nullptr) return;
    werase(_window);
    wborder(_window, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);
    switch (p)
    {
        case NFSv3 :
            for(unsigned int i = 0; i < ProcEnumNFS3::count; i++)
            {
                if( i > _scrollOffset.at(p) && i < _window->_maxy + _scrollOffset.at(p))
                    mvwprintw(_window, i + _scrollOffset.at(p), 1, "%s", print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(i)));
            }
        break;
        case NFSv4 :
            for(unsigned int i = 0; i < ProcEnumNFS4::count; i++)
            {
                if( i > _scrollOffset.at(p) && i < _window->_maxy + _scrollOffset.at(p))
                    mvwprintw(_window, i + _scrollOffset.at(p), 1, "%s", print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(i)));
            }
        break;
        default :
            mvwprintw(_window, 1, 1, "%s", "\tThis protocol not implemented yet");
            mvwprintw(_window, 2, 1, "%s", "\t\tin libwatch plugin of nfstrace.");
            mvwprintw(_window, 3, 1, "%s", "\tTry to download latest version.");
        break;
    }
    update();
*/
}

void StatisticsWindow::update()
{
/*
    std::size_t m = 0; // sum of all counters
    for(auto p : _statistic)
    {
        m += p;
    }
    switch (_activeProtocol)
    {
        case NFSv3 :
            for(unsigned int i = 0; i < ProcEnumNFS3::count; i++)
            {
                if( i > _scrollOffset.at(static_cast<int>(_activeProtocol)) && i < _window->_maxy + _scrollOffset.at(static_cast<int>(_activeProtocol)))
                {
                    mvwprintw(_window, i + _scrollOffset.at(static_cast<int>(_activeProtocol)), COUNTERS_POS, "%d  ", _statistic[i]);
                    mvwprintw(_window, i + _scrollOffset.at(static_cast<int>(_activeProtocol)), PERSENT_POS, "%-3.2f%% ",
                              m > 0 ? static_cast<double>(_statistic[i]) / static_cast<double>(m) * 100.0 : 0.0);
                }
            }
        break;
        case NFSv4 :
            for(unsigned int i = 0; i < ProcEnumNFS4::count; i++)
            {
                if( i > _scrollOffset.at(static_cast<int>(_activeProtocol)) && i < _window->_maxy + _scrollOffset.at(static_cast<int>(_activeProtocol)))
                {
                    mvwprintw(_window, i + _scrollOffset.at(static_cast<int>(_activeProtocol)), PERSENT_POS, "%d  ", _statistic[i]);
                    mvwprintw(_window, i + _scrollOffset.at(static_cast<int>(_activeProtocol)), PERSENT_POS, "%-3.2f%% ",
                              m > 0 ? static_cast<double>(_statistic[i]) / static_cast<double>(m) * 100.0 : 0.0);
                }
            }
        break;
        default :
        break;
    }
    wrefresh(_window);
*/
}

void StatisticsWindow::resize(MainWindow& m)
{
    if(_window != nullptr) destroy();
    if(m._window->_maxy > GUI_HEADER_HEIGHT + GUI_STATISTIC_HEIGHT)
        _window = subwin(m._window,m._window->_maxy > GUI_HEADER_HEIGHT ? GUI_STATISTIC_HEIGHT + GUI_HEADER_HEIGHT : m._window->_maxy - GUI_HEADER_HEIGHT ,
                                   m._window->_maxx > GUI_LENGTH ? GUI_LENGTH : m._window->_maxx, GUI_HEADER_HEIGHT, 0);
    update();
}
