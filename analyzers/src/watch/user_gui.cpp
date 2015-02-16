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
#include <exception>
#include <iostream>
#include <system_error>

#include <unistd.h>

#include <api/plugin_api.h>
#include "user_gui.h"
//------------------------------------------------------------------------------

operation_data nfsv3_total   {1, 1, nullptr, 28 , 2, 10 ,0 , 0, 0};
operation_data nfsv3_proc    {1, 3, nullptr, 18 , 2, 10 ,0 , 0, 0};
operation_data nfsv4_op_total{1, 1, nullptr, 28 , 2, 9  ,0 , 0, 0};
operation_data nfsv4_oper    {1, 3, nullptr, 22 , 2, 9  ,0 , 0, 0};
operation_data nfsv4_pr_total{1, 1, nullptr, 28 , 2, 9  ,0 , 0, 0};
operation_data nfsv4_proc    {1, 3, nullptr, 22 , 2, 9  ,0 , 0, 0};

operation_data date_time     {1, 8, nullptr, 1 , 2, 9  ,999, 0, 0};
operation_data el_time       {1, 8, nullptr, 1 , 2, 9  ,999, 0, 0};
operation_data packets       {1, 8, nullptr, 1 , 2, 9  ,999, 0, 0};
//------------------------------------------------------------------------------
UserGUI::UserGUI(const char *opts)
: enableUpdate{false}
, start_time  {time(nullptr)}
, SECINMIN    {60}
, SECINHOUR   {60*60}
, SECINDAY    {60*60*24}
, MSEC        {1000000}
, all_windows(3, nullptr)
, scroll_shift {0}
, column_shift {0}
, _run {ATOMIC_FLAG_INIT}
, nfs3_procedure_total   {0}
, nfs3_count (ProcEnumNFS3::count, 0)
, nfs4_procedure_total   {0}
, nfs4_operations_total  {0}
, nfs4_count (ProcEnumNFS4::count, 0)
, refresh_delta {900000}
, max_read        {5}
, read_counter    {0}
{
    if(opts != nullptr && *opts != '\0' ) try
    {
        refresh_delta = std::stoul(opts);
    }
    catch(std::exception& e)
    {
        throw std::runtime_error{std::string{"Error in plugin options processing. OPTS: "} + opts + std::string(" Error: ") + e.what()};
    }

    _run.test_and_set();
    gui_thread = std::thread(&UserGUI::thread, this);
}

UserGUI::~UserGUI()
{
    if (gui_thread.joinable())
    {
        _run.clear();
        gui_thread.join();
    }
    destroyPlot();
}

void UserGUI::updatePlot()
{
    std::unique_lock<std::mutex> lck(mut);

    if(enableUpdate)
    {
        destroyPlot();
        initPlot();
        enableUpdate = false;
    }

    uint64_t nfs3_procedure_total_copy = nfs3_procedure_total;
    std::vector<int> nfs3_count_copy = nfs3_count;
    uint64_t nfs4_procedure_total_copy = nfs4_procedure_total;
    uint64_t nfs4_operations_total_copy = nfs4_operations_total;
    std::vector<int> nfs4_count_copy = nfs4_count;
    lck.unlock();
    uint16_t counter = nfsv3_total.start_y;
    if(nfsv3_total.max_y + scroll_shift > counter && counter > scroll_shift)
    {
        mvwprintw( nfsv3_total.my_win, counter - scroll_shift, nfsv3_total.mod_pos, "%lu ", nfs3_procedure_total_copy);
        counter++;
    }

    counter = nfsv3_proc.start_y;
    if(counter > scroll_shift)
        counter++;

    for(auto i : nfs3_count_copy)
    {
        if(nfsv3_proc.max_y + scroll_shift > counter && counter > scroll_shift)
            mvwprintw(nfsv3_proc.my_win, counter - scroll_shift, nfsv3_proc.mod_pos  ,"%lu ", i);
        if(nfsv3_proc.max_y + scroll_shift > counter && counter > scroll_shift)
            mvwprintw(nfsv3_proc.my_win, counter -scroll_shift, nfsv3_proc.mod_pos + nfsv3_proc.st_colum ,"%-3.2f%% ",
                     (double) (nfs3_procedure_total_copy > 0 ? (double)i / (double)nfs3_procedure_total_copy * 100 : 0));
        counter++;
    }

    counter = nfsv4_pr_total.start_y;
    if(nfsv4_pr_total.max_y + scroll_shift > counter && counter > scroll_shift)
    {
        mvwprintw(nfsv4_pr_total.my_win, counter - scroll_shift, nfsv4_pr_total.mod_pos ,"%lu ",nfs4_procedure_total_copy);
        counter++;
    }

    if(counter > scroll_shift)
        counter++;

    for(uint16_t i = 0; i < ProcEnumNFS4::count_proc && i <= nfs4_count_copy.size(); i++)
    {
        if(nfsv4_proc.max_y + scroll_shift > counter && counter > scroll_shift )
            mvwprintw(nfsv4_proc.my_win, counter - scroll_shift, nfsv4_proc.mod_pos ,"%lu ",nfs4_count_copy[i]);
        if(nfsv4_proc.max_y + scroll_shift> counter && counter > scroll_shift)
            mvwprintw(nfsv4_proc.my_win, counter - scroll_shift,nfsv4_proc.mod_pos + nfsv4_proc.st_colum ,"%-3.2f%% ",
                     (double) (nfs4_procedure_total_copy > 0 ? (double)nfs4_count_copy[i] / (double)nfs4_procedure_total_copy * 100 : 0) );
        counter++;
    }

    counter = nfsv4_op_total.start_y;
    if(nfsv4_op_total.max_y + scroll_shift> counter && counter > scroll_shift)
    {
        mvwprintw(nfsv4_op_total.my_win, counter - scroll_shift, nfsv4_op_total.mod_pos ,"%lu ", nfs4_operations_total_copy);
        counter++;
    }

    if(counter > scroll_shift)
        counter++;

    for(uint16_t i = ProcEnumNFS4::count_proc ; i < ProcEnumNFS4::count && i <= nfs4_count_copy.size(); i++)
    {
        if(nfsv4_proc.max_y + scroll_shift> counter && counter > scroll_shift)
            mvwprintw(nfsv4_oper.my_win, counter - scroll_shift, nfsv4_oper.mod_pos ,"%lu ",nfs4_count_copy[i]);
        if(nfsv4_proc.max_y + scroll_shift> counter && counter > scroll_shift)
            mvwprintw(nfsv4_oper.my_win, counter - scroll_shift, nfsv4_oper.mod_pos + nfsv4_oper.st_colum ,"%-3.2f%% ",
                     (double) (nfs4_procedure_total_copy > 0 ? (double)nfs4_count_copy[i] / (double)nfs4_procedure_total_copy * 100 : 0) );
        counter++;
    }
    chronoUpdate();
    updateAll();
}

void UserGUI::updateCounters(const uint64_t &nfs3_total, const std::vector<int> &nfs3_pr_count,
                             const uint64_t &nfs4_ops_total, const uint64_t &nfs4_pr_total,
                             const std::vector<int> &nfs4_op_count)
{
    std::unique_lock<std::mutex> lck(mut);

    nfs3_procedure_total += nfs3_total;
    std::vector<int>::const_iterator f;
    std::vector<int>::iterator s;
    for( f = nfs3_pr_count.begin(), s = nfs3_count.begin(); f != nfs3_pr_count.end() && s != nfs3_count.end(); ++f, ++s)
    {
        (*s) += (*f);
    }

    nfs4_procedure_total += nfs4_pr_total;
    nfs4_operations_total += nfs4_ops_total;
    for(f = nfs4_op_count.begin(), s = nfs4_count.begin(); f != nfs4_op_count.end() && s != nfs4_count.end(); ++f, ++s)
    {
        (*s) += (*f);
    }
}

uint16_t UserGUI::inputData()
{
    int c = wgetch(all_windows[0]);
    return (c == KEY_UP || c == KEY_DOWN) ? c : 0;
}

void UserGUI::keyboard()
{
    int key = inputData();
    if(key != 0 )
    {
        if(key == KEY_UP)
        {
            if(scroll_shift > 0)
            {
                scroll_shift--;
                enableUpdate = true;
                do key = getch(); while ((key != EOF) && (key != '\n') && (key != ' '));
            }
        }
        else if(key == KEY_DOWN)
        {
            if(scroll_shift < 25)
            {
                scroll_shift++;
                enableUpdate = true;
                do key = getch(); while ((key != EOF) && (key != '\n') && (key != ' '));
            }
        }
        else
            do key = getch(); while ((key != EOF) && (key != '\n') && (key != ' '));
    }
}

void UserGUI::chronoUpdate()
{
    time_t actual_time = time(nullptr);
    tm* t = localtime(&actual_time);
    time_t shift_time = actual_time - start_time;
    mvprintw(date_time.start_y, date_time.start_x,"Date: \t %d.%d.%d \t Time: %d:%d:%d  ",t->tm_mday, t->tm_mon + 1, t->tm_year + 1900,t->tm_hour, t->tm_min, t->tm_sec);
    mvprintw(el_time.start_y, el_time.start_x,"Elapsed time:  \t %d days; %d:%d:%d times",
             shift_time/SECINDAY, shift_time%SECINDAY/SECINHOUR, shift_time%SECINHOUR/SECINMIN, shift_time%SECINMIN);
}

void UserGUI::designPlot()
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

    WINDOW* f_win = nullptr;
    WINDOW* s_win = nullptr;
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

void UserGUI::destroyPlot()
{
    if(all_windows[0] == nullptr) return;
    if(all_windows[1] != nullptr)
    {
        wclear(all_windows[1]);
        delwin(all_windows[1]);
    }
    if(all_windows[2] != nullptr)
    {
        wclear(all_windows[2]);
        delwin(all_windows[2]);
    }
    nocbreak();
    echo();
    clrtoeol();
    refresh();
    endwin();

    all_windows[0] = nullptr;
    all_windows[1] = nullptr;
    all_windows[2] = nullptr;
}

void UserGUI::initPlot()
{
    WINDOW *ww = initscr();
    all_windows[0] = ww;
    if(ww == nullptr)
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
    designPlot();                 // print basic windows
}

void UserGUI::updateAll()
{
    for(auto i : all_windows)
    {
        wrefresh(i);
    }
}

void UserGUI::thread()
{
    try
    {
        initPlot();
        // prepare for select
        fd_set rfds;

        /* Watch stdin (fd 0) to see when it has input. */
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);

        /* Wait up to five seconds. */
        struct timeval tv;
        tv.tv_sec = refresh_delta / MSEC;
        tv.tv_usec = refresh_delta % MSEC;

        int sel_rez;
        while (_run.test_and_set())
        {
            updatePlot();
            sel_rez = select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv);

            if (sel_rez == -1)
               break;
            else
                keyboard();

            tv.tv_sec = refresh_delta / MSEC;
            tv.tv_usec = refresh_delta % MSEC;
        }
        destroyPlot();
    }
    catch(std::exception& e)
    {
        destroyPlot();
        std::cerr << "Watch plugin error: " << e.what();
    }
}
//------------------------------------------------------------------------------
