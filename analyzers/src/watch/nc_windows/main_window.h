//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for describe ncurses main window.
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
#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H
//------------------------------------------------------------------------------
#include <ncurses.h>
//------------------------------------------------------------------------------
class MainWindow
{
    friend class HeaderWindow;
    friend class StatisticsWindow;
    WINDOW* _window;

    void init();
    void destroy();
    static void cleanStdin(int);

public:

    MainWindow();
    ~MainWindow();

    /*! Get iput keys
    */
    int inputKeys();

    /*! Resize Main Window
    */
    void resize();

    /*! Update Main Window
    */
    void update() const;
};
//------------------------------------------------------------------------------
#endif//MAIN_WINDOW_H
//------------------------------------------------------------------------------
