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
#include <exception>
#include <iostream>
#include <system_error>

#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <api/plugin_api.h>
#include "plotter.h"
//------------------------------------------------------------------------------
const time_t   Plotter::start_time = time(NULL);
const uint32_t Plotter::SECINMIN   = 60;
const uint32_t Plotter::SECINHOUR  = 60*60;
const uint32_t Plotter::SECINDAY   = 60*60*24;

int Plotter::resize = 0;

operation_data nfsv3_total   {1, 1, NULL, 28 , 2, 10 ,0 , 0, 0};
operation_data nfsv3_proc    {1, 3, NULL, 18 , 2, 10 ,0 , 0, 0};
operation_data nfsv4_op_total{1, 1, NULL, 28 , 2, 9  ,0 , 0, 0};
operation_data nfsv4_oper    {1, 3, NULL, 22 , 2, 9  ,0 , 0, 0};
operation_data nfsv4_pr_total{1, 1, NULL, 28 , 2, 9  ,0 , 0, 0};
operation_data nfsv4_proc    {1, 3, NULL, 22 , 2, 9  ,0 , 0, 0};

operation_data date_time     {1, 8, NULL, 1 , 2, 9  ,999, 0, 0};
operation_data el_time       {1, 8, NULL, 1 , 2, 9  ,999, 0, 0};
operation_data packets       {1, 8, NULL, 1 , 2, 9  ,999, 0, 0};
//------------------------------------------------------------------------------
Plotter::Plotter()
: all_windows(3, NULL)
, scroll_shift {0}
, column_shift {0}
{
    try
    {
        monitor_running.test_and_set();
        std::cout << "\n\n";
        initPlot();
        designPlot();
        signal(SIGWINCH, enableResize);
        keyboard_proc = std::thread(&Plotter::keyboard_thread, this);
    }
    catch (std::runtime_error& err)
    {
        monitor_running.clear();
        keyboard_proc.join();
        destroyPlot();
        std::cerr << "Error in libwatch plugin: " << err.what();
        throw std::runtime_error("Error in Plotter screen initialization.");
    }
}
Plotter::~Plotter()
{
    monitor_running.clear();
    keyboard_proc.join();
    destroyPlot();
}

void Plotter::updatePlot(const uint64_t &nfs3_total, const std::vector<int> &nfs3_pr_count,
                         const uint64_t &nfs4_ops_total, const uint64_t &nfs4_pr_total,
                         const std::vector<int> &nfs4_op_count)
{
    if(resize)
    {
        destroyPlot();
        initPlot();
        designPlot();
        if(resize > 0) resize--;
    }
    uint16_t counter = nfsv3_total.start_y;
    if(nfsv3_total.max_y + scroll_shift > counter && counter > scroll_shift)
    {
        mvwprintw( nfsv3_total.my_win, counter - scroll_shift, nfsv3_total.mod_pos, "%lu", nfs3_total);
        counter++;
    }

    counter = nfsv3_proc.start_y;
    if(counter > scroll_shift)
        counter++;

    for(auto i : nfs3_pr_count)
    {
        if(nfsv3_proc.max_y + scroll_shift > counter && counter > scroll_shift)
            mvwprintw(nfsv3_proc.my_win, counter - scroll_shift, nfsv3_proc.mod_pos  ,"%lu", i);
        if(nfsv3_proc.max_y + scroll_shift > counter && counter > scroll_shift)
            mvwprintw(nfsv3_proc.my_win, counter - scroll_shift, nfsv3_proc.mod_pos + nfsv3_proc.st_colum ,"%s", "       ");
        if(nfsv3_proc.max_y + scroll_shift > counter && counter > scroll_shift)
            mvwprintw(nfsv3_proc.my_win, counter -scroll_shift, nfsv3_proc.mod_pos + nfsv3_proc.st_colum ,"%-3.2f%%",
                     (double) (nfs3_total > 0 ? (double)i / (double)nfs3_total * 100 : 0));
        counter++;
    }

    counter = nfsv4_pr_total.start_y;
    if(nfsv4_pr_total.max_y + scroll_shift > counter && counter > scroll_shift)
    {
        mvwprintw(nfsv4_pr_total.my_win, counter - scroll_shift, nfsv4_pr_total.mod_pos ,"%lu",nfs4_pr_total);
        counter++;
    }

    if(counter > scroll_shift)
        counter++;

    for(uint16_t i = 0; i < ProcEnumNFS4::count_proc && i <= nfs4_op_count.size(); i++)
    {
        if(nfsv4_proc.max_y + scroll_shift > counter && counter > scroll_shift )
            mvwprintw(nfsv4_proc.my_win, counter - scroll_shift, nfsv4_proc.mod_pos ,"%lu",nfs4_op_count[i]);
        if(nfsv4_proc.max_y + scroll_shift > counter && counter > scroll_shift)
            mvwprintw(nfsv4_proc.my_win, counter - scroll_shift, nfsv4_proc.mod_pos + nfsv4_proc.st_colum ,"%s", "       ");
        if(nfsv4_proc.max_y + scroll_shift> counter && counter > scroll_shift)
            mvwprintw(nfsv4_proc.my_win, counter - scroll_shift,nfsv4_proc.mod_pos + nfsv4_proc.st_colum ,"%-3.2f%%",
                     (double) (nfs4_pr_total > 0 ? (double)nfs4_op_count[i] / (double)nfs4_pr_total * 100 : 0) );
        counter++;
    }

    counter = nfsv4_op_total.start_y;
    if(nfsv4_op_total.max_y + scroll_shift> counter && counter > scroll_shift)
    {
        mvwprintw(nfsv4_op_total.my_win, counter - scroll_shift, nfsv4_op_total.mod_pos ,"%lu", nfs4_ops_total);
        counter++;
    }

    if(counter > scroll_shift)
        counter++;

    for(uint16_t i = ProcEnumNFS4::count_proc ; i < ProcEnumNFS4::count && i <= nfs4_op_count.size(); i++)
    {
        if(nfsv4_proc.max_y + scroll_shift> counter && counter > scroll_shift)
            mvwprintw(nfsv4_oper.my_win, counter - scroll_shift, nfsv4_oper.mod_pos ,"%lu",nfs4_op_count[i]);
        if(nfsv4_proc.max_y + scroll_shift> counter && counter > scroll_shift)
            mvwprintw(nfsv4_oper.my_win, counter - scroll_shift, nfsv4_oper.mod_pos + nfsv4_proc.st_colum ,"%s", "       ");
        if(nfsv4_proc.max_y + scroll_shift> counter && counter > scroll_shift)
            mvwprintw(nfsv4_oper.my_win, counter - scroll_shift, nfsv4_oper.mod_pos + nfsv4_oper.st_colum ,"%-3.2f%%",
                     (double) (nfs4_pr_total > 0 ? (double)nfs4_op_count[i] / (double)nfs4_pr_total * 100 : 0) );
        counter++;
    }
    chronoUpdate();
    updateAll();
}

uint16_t Plotter::inputData()
{
    int c = wgetch(all_windows[0]);
    return (c == KEY_UP || c == KEY_DOWN) ? c : 0;
}

void Plotter::enableResize(int)
{
    resize ++;
}

void Plotter::keyboard_thread()
{
    while(monitor_running.test_and_set())
    {
        int key = inputData();

        if(key != 0 )
        {
            if(key == KEY_UP)
            {
                if(scroll_shift > 0)
                {
                    scroll_shift--;
                    resize++;
                }
            }
            else if(key == KEY_DOWN)
            {
                if(scroll_shift < 25)
                {
                    scroll_shift++;
                    resize++;
                }
            }
        }
        sleep(1);
    }
}

void Plotter::chronoUpdate()
{
    time_t actual_time = time(NULL);
    tm* t = localtime(&actual_time);
    time_t shift_time = actual_time - start_time;
    mvprintw(date_time.start_y, date_time.start_x,"Date: \t %d.%d.%d \t Time: %d:%d:%d",t->tm_mday, t->tm_mon + 1, t->tm_year + 1900,t->tm_hour, t->tm_min, t->tm_sec);
    mvprintw(el_time.start_y, el_time.start_x,"Elapsed time:  \t %d days; %d:%d:%d times",
             shift_time/SECINDAY, shift_time%SECINDAY/SECINHOUR, shift_time%SECINHOUR/SECINMIN, shift_time%SECINMIN);
//    mvprintw(packets.start_y, packets.start_x,"Total packets:  %lu(network)  %lu(to host)  %lu(dropped)", 999, 999 , 999);
}

void Plotter::designPlot()
{
    char HOST_NAME[128];
    gethostname(HOST_NAME, 128);
    clear();
    column_shift = 0;
    mvprintw(column_shift, 1,"%s","Nfstrace watch plugin. To scroll press up or down keys. Ctrl + c to exit.");
    column_shift++;
    mvprintw(column_shift, 1,"Host name:\t %s",HOST_NAME);
    column_shift++;
    date_time.start_y = column_shift;
    column_shift++;
    el_time.start_y   = column_shift;
    column_shift++;
    packets.start_y   = column_shift;
    column_shift++;
    chronoUpdate();

    WINDOW* f_win = NULL;
    WINDOW* s_win = NULL;
    uint16_t column_hei = 0;
    uint16_t column_hei_base = 0;

    // all columns has similar y start position and similar hight
    column_hei_base = ProcEnumNFS3::count > ProcEnumNFS4::count ? ProcEnumNFS3::count :ProcEnumNFS4::count + nfsv3_total.start_y + 1;

    if(column_hei_base + column_shift > y_max) column_hei = y_max - column_shift;
    else column_hei = column_hei_base;

    if( column_hei > column_hei_base - scroll_shift && column_hei ) column_hei = column_hei_base - scroll_shift;

    f_win = subwin(all_windows[0], column_hei, 40, column_shift, 1);
    all_windows[1] = f_win;
    nfsv3_proc.max_y = column_hei - 1;
    nfsv3_total.max_y = column_hei - 1;
    nfsv4_proc.max_y = column_hei - 1;
    nfsv4_pr_total.max_y = column_hei - 1;
    nfsv3_proc.y_board_shift = column_shift + 1;
    nfsv3_total.y_board_shift = column_shift + 1;
    nfsv4_proc.y_board_shift = column_shift + 1;
    nfsv4_pr_total.y_board_shift = column_shift + 1;

    s_win = subwin(all_windows[0], column_hei, 40, column_shift, 40);
    all_windows[2] = s_win;
    nfsv4_op_total.max_y = column_hei - 1;
    nfsv4_oper.max_y = column_hei - 1;
    nfsv4_op_total.y_board_shift = column_shift + 1;
    nfsv4_oper.y_board_shift = column_shift + 1;

    nfsv3_proc.my_win     = f_win;
    nfsv3_total.my_win    = f_win;
    nfsv4_pr_total.my_win = f_win;
    nfsv4_proc.my_win     = f_win;
    nfsv4_op_total.my_win = s_win;
    nfsv4_oper.my_win     = s_win;

    int tmp = 1;
    wborder(f_win, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);
    wborder(s_win, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);

    nfsv3_total.start_y = tmp;
    if(nfsv3_total.max_y + scroll_shift > tmp && tmp > scroll_shift)
    {
        mvwprintw(f_win, tmp - scroll_shift, 2, "NFSv3 total procedures:");
        tmp++;
    }

    nfsv3_proc.start_y = tmp;
    if(nfsv3_proc.max_y + scroll_shift > tmp && tmp > scroll_shift)
    {
        mvwprintw(f_win, tmp - scroll_shift, 2, "Per procedure:");
        tmp++;
    }

    for(unsigned int i = 0; i < ProcEnumNFS3::count; i++)
    {
        if(nfsv3_proc.max_y + scroll_shift > tmp &&  tmp > scroll_shift)
            mvwprintw(f_win, tmp - scroll_shift, 2, "%s", print_nfs3_procedures(static_cast<ProcEnumNFS3::NFSProcedure>(i)));
        tmp++;
    }

    if(tmp > scroll_shift)
    {
        mvwhline(f_win, tmp - scroll_shift, 1, ACS_HLINE, 38);
        tmp++;
    }
    tmp++;

    nfsv4_pr_total.start_y = tmp;
    if(nfsv4_pr_total.max_y + scroll_shift > tmp && tmp > scroll_shift)
    {
        mvwprintw(f_win, tmp - scroll_shift, 2, "NFSv4 total procedures:");
        tmp++;
    }

    if(nfsv4_proc.max_y + scroll_shift> tmp && tmp > scroll_shift)
    {
        mvwprintw(f_win, tmp - scroll_shift, 2, "Per procedure:");
        tmp++;
    }
    for(unsigned int i = 0; i < ProcEnumNFS4::count_proc; i++)
    {
        if(nfsv4_proc.max_y + scroll_shift> tmp && tmp > scroll_shift)
        {
            mvwprintw(f_win, tmp - scroll_shift, 2, "%s", print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(i)));
        }
        tmp++;
    }

    tmp = 1;
    nfsv4_op_total.start_y = tmp;
    if(nfsv4_op_total.max_y + scroll_shift > tmp && tmp > scroll_shift)
    {
        mvwprintw(s_win, tmp - scroll_shift,2,"NFSv4 total operations:");
        tmp++;
    }

    nfsv4_oper.start_y = tmp;
    if(nfsv4_oper.max_y + scroll_shift> tmp && tmp > scroll_shift)
    {
        mvwprintw(s_win, tmp - scroll_shift, 2, "Per operation:");
        tmp++;
    }
    for(unsigned int i = ProcEnumNFS4::count_proc ; i < ProcEnumNFS4::count; i++)
    {
        if(nfsv4_oper.max_y + scroll_shift> tmp && tmp > scroll_shift)
        {
            mvwprintw(s_win, tmp - scroll_shift, 2,"%s", print_nfs4_procedures(static_cast<ProcEnumNFS4::NFSProcedure>(i)));
        }
        tmp++;
    }
    updateAll();
}

void Plotter::destroyPlot()
{
    nocbreak();
    echo();
    clrtoeol();
    refresh();
    endwin();
}

void Plotter::initPlot()
{
    WINDOW *ww = initscr();
    all_windows[0] = ww;
    if(ww == NULL)
    {
        throw std::runtime_error("Initialization of main window failed.");
    }
    x_max = ww->_maxx;
    y_max = ww->_maxy;
    noecho();
    cbreak();
    intrflush(stdscr, false);     // flush main window
    curs_set(0);                  // disable blinking cursore

    keypad(all_windows[0], true); // init keyboard
    timeout(200);                 // set keyboard timeout
}

void Plotter::updateAll()
{
    for(auto i : all_windows)
    {
        wrefresh(i);
    }
}
