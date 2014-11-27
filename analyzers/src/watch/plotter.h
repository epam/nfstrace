//------------------------------------------------------------------------------
// Author: Vitali Adamenka
// Description: Header for WatchAnalyzer based on TestAnalyzer.h
// Copyright (c) 2014 EPAM Systems. All Rights Reserved.
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
#ifndef PLOTTER_H
#define PLOTTER_H
//------------------------------------------------------------------------------
#include <atomic>
#include <cstdlib>
#include <vector>
#include <thread>

#include <ncurses.h>
//------------------------------------------------------------------------------
struct operation_data
{
    uint16_t start_x;
    uint16_t start_y;

    WINDOW* my_win;
    uint16_t mod_pos;
    uint16_t n_colum;
    uint16_t st_colum;
    uint16_t max_y;
    uint16_t y_board_shift;
    uint16_t x_board_shift;
};
//------------------------------------------------------------------------------
class Plotter
{
public:
    Plotter();
    virtual ~Plotter();
    void updatePlot(const uint64_t &nfs3_total, const std::vector<int> &nfs3_pr_count,
                    const uint64_t &nfs4_ops_total, const uint64_t &nfs4_pr_total,
                    const std::vector<int> &nfs4_pr_count);

    uint16_t inputData();
    static void enableResize(int);
    inline void keyboard_thread();

    const static time_t start_time;
    const static uint32_t SECINMIN;
    const static uint32_t SECINHOUR;
    const static uint32_t SECINDAY;

private:
    void chronoUpdate();
    void designPlot();
    void destroyPlot();
    void initPlot();
    void updateAll();

    static int resize;
    std::atomic_flag monitor_running;
    std::thread keyboard_proc;

    std::vector<WINDOW*> all_windows;
    uint16_t scroll_shift;
    uint16_t x_max;
    uint16_t y_max;

    uint16_t column_shift;
};
//------------------------------------------------------------------------------
#endif // PLOTTER_H
//------------------------------------------------------------------------------