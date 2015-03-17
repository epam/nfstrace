//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for description all ncurses windows constants.
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
#ifndef NC_WINDOW_CONST_H
#define NC_WINDOW_CONST_H
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
#endif//NC_WINDOW_CONST_H
//------------------------------------------------------------------------------
