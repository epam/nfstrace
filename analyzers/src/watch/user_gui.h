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
#ifndef USERGUI_H
#define USERGUI_H
//------------------------------------------------------------------------------
#include <atomic>
#include <cstdlib>
#include <condition_variable>
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
class UserGUI
{
public:
    UserGUI(const char *);
    virtual ~UserGUI();
    void updateCounters(const uint64_t &nfs3_total, const std::vector<int> &nfs3_pr_count,
                        const uint64_t &nfs4_ops_total, const uint64_t &nfs4_pr_total,
                        const std::vector<int> &nfs4_pr_count);

    inline void setUpdate()
    {
        enableUpdate = true;
    }

private:
    std::atomic<bool> enableUpdate;

    void updatePlot();
    uint16_t inputData();
    void keyboard();

    const time_t start_time;
    const uint32_t SECINMIN;
    const uint32_t SECINHOUR;
    const uint32_t SECINDAY;
    const uint32_t MSEC;

    void chronoUpdate();
    void designPlot();
    void destroyPlot();
    void initPlot();
    void updateAll();
    void thread();

    std::mutex mut;
    std::vector<WINDOW*> all_windows;
    std::thread gui_thread;

    uint16_t scroll_shift;
    uint16_t x_max;
    uint16_t y_max;
    uint16_t column_shift;

    std::atomic_flag _run;

    uint64_t nfs3_procedure_total;
    std::vector<int> nfs3_count;
    uint64_t nfs4_procedure_total;
    uint64_t nfs4_operations_total;
    std::vector<int> nfs4_count;

    long int refresh_delta;
};
//------------------------------------------------------------------------------
#endif // USERGUI_H
//------------------------------------------------------------------------------
