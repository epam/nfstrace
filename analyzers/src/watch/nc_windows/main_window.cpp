//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Source for describe ncurses main window.
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
#include <stdexcept>

#include <unistd.h>

#include "main_window.h"
//------------------------------------------------------------------------------
void MainWindow::init()
{
    if (_window != nullptr)
    {
        destroy();
    }
    _window = initscr();
    if (_window == nullptr)
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
    if (_window != nullptr)
    {
        werase(_window);
    }
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

void MainWindow::cleanStdin(int key)
{
    while ((key != EOF) && (key != '\n') && (key != ' '))
    {
        key = getch();
    }
}

MainWindow::MainWindow()
: _window {nullptr}
{
    init();
}

MainWindow::~MainWindow()
{
    destroy();
}

int MainWindow::inputKeys()
{
    int key = wgetch(_window);

    if (key != KEY_UP && key != KEY_DOWN && key != KEY_LEFT && key != KEY_RIGHT)
    {
        key = 0;
    }
    cleanStdin(key);
    return key;
}

void MainWindow::resize()
{
    if (_window != nullptr)
    {
        destroy();
    }
    init();
}

void MainWindow::update()
{
    if (_window != nullptr)
    {
        refresh();
    }
}
//------------------------------------------------------------------------------