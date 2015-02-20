#include "nc_windows.h"
//------------------------------------------------------------------------------
namespace
{
    const char *ProtocolsNames[] = {"NFS v3", "NFS v4", "NFS v41", "CIFS v1", "CIFS v2", nullptr};
    const char *ProtocolsActiveNames[] = {"< NFS v3 >", "< NFS v4 >", "< NFS v41 >", "< CIFS v1 >", "< CIFS v2 >", nullptr};
    const unsigned int SECINMIN  = 60;
    const unsigned int SECINHOUR = 60 * 60;
    const unsigned int SECINDAY  = 60 * 60 * 24;
    const unsigned int MSEC      = 1000000;

    const int MAXSHIFT = 25;
    const int SHIFTCU  = 1;
}
//------------------------------------------------------------------------------
uint16_t MainWindow::inputKeys()
{
    int c = wgetch(_window);
    if(c == KEY_UP || c == KEY_DOWN || c == LEFT_KEY || c == RIGHT_KEY)
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
        while ((key != EOF) && (key != '\n') && (key != ' '))
        key = 0;
    }
    return k;
}

void MainWindow::init()
{
    if(_window != nullptr) destroy();
    _window = initscr();
    if(_window == nullptr)
    {
        throw LibWatchException("Initialization of Main window failed.");
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
    _window = nullptr;
    nocbreak();
    echo();
    clrtoeol();
    refresh();
    endwin();
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

MainWindow::resize()
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
}
HeaderWindow::HeaderWindow(MainWindow&& w)
:_start_time{time(NULL)}
{
    if(w._window == nullptr)
    {
        throw LibWatchException("Initialization of Header window failed.");
    }
    resize(w);
}

HeaderWindow::~HeaderWindow()
{
    destroy();
}

void HeaderWindow::selectProtocol(const ProtocolId& p)
{
    _activeProtocol = p;
    if(_window == nullptr) return;
    mvwprintw(_window, 7, 1,"\t%s    |\t%s    |\t%s    |\t%s    |\t%s",
              _activeProtocol == NFSv3  ? ProtocolsActiveNames[(const int)NFSv3]  : ProtocolsNames[(const int)NFSv3 ],
              _activeProtocol == NFSv4  ? ProtocolsActiveNames[(const int)NFSv4]  : ProtocolsNames[(const int)NFSv4 ],
              _activeProtocol == NFSv41 ? ProtocolsActiveNames[(const int)NFSv41] : ProtocolsNames[(const int)NFSv41],
              _activeProtocol == CIFSv1 ? ProtocolsActiveNames[(const int)CIFSv1] : ProtocolsNames[(const int)CIFSv1],
              _activeProtocol == CIFSv2 ? ProtocolsActiveNames[(const int)CIFSv2] : ProtocolsNames[(const int)CIFSv2]);
    wrefresh(_window);
}

void HeaderWindow::refresh()
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
}

void HeaderWindow::resize(MainWindow&& m)
{
    if(_window != nullptr) destroy();
    _window = subwin(m._window, 8, 80, 0, 0);
    if(_window != nullptr)
    {
        wborder(_window, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);
        char HOST_NAME[128];
        gethostname(HOST_NAME, 128);
        mvwprintw(_window, 1, 1,"%s","Nfstrace watch plugin. To scroll press up or down keys. Ctrl + c to exit.");
        mvwprintw(_window, 2, 1,"Host name:\t %s",HOST_NAME);
    }
}
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void StatisticsWindow::destroy()
{
    if(_window == nullptr) return;
    wclear(_window);
    delwin(_window);
}

StatisticsWindow::StatisticsWindow(MainWindow&& m)
{
    if(w._window == nullptr)
    {
        throw LibWatchException("Initialization of Header window failed.");
    }
    resize(w);
}

StatisticsWindo::~StatisticsWindow()
{
    destroy();
}

void StatisticsWindo::reset(const ProtocolId& , const StatisticsConteiner&)
{
    //TODO RESET 
}

void StatisticsWindow::scroll(int i)
{
    if(i > 0 && _scrollOffset.at(_activeProtocol) <= MAXSHIFT - SHIFTCU)
        _scrollOffset.at(_activeProtocol) += SHIFTCU;
    else if(i < 0 && _scrollOffset.at(_activeProtocol) >= SHIFTCU)
        _scrollOffset.at(_activeProtocol) -= SHIFTCU;
}

void StatisticsWindow::selectProtocol(const ProtocolId& p)
{
    _activeProtocol = p;
    if(_window == nullptr) return;
    werase(_window);
    // TODO chouse protocol
}

void StatisticsWindow::refresh()
{
    //TODO refresh
}

void StatisticsWindow::resize(MainWindow&& m)
{
    if(_window != nullptr) destroy();
    _window = subwin(m._window,/* TODO SET SIZE OF WINDOW FOR one column*/ , 80, 8, 0);
    if(_window != nullptr)
    {
        wborder(_window, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE, ACS_ULCORNER, ACS_URCORNER , ACS_LLCORNER, ACS_LRCORNER);
        // TODO draw list of commands
    }
}
