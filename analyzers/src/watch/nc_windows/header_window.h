//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for describe ncurses header window.
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
#ifndef HEADER_WINDOWS_H
#define HEADER_WINDOWS_H
//------------------------------------------------------------------------------
#include <ncurses.h>

#include "main_window.h"
//------------------------------------------------------------------------------
class HeaderWindow
{
    WINDOW* _window;
    time_t  _start_time;
    void    destroy();

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
#endif //HEADER_WINDOWS_H
//------------------------------------------------------------------------------
