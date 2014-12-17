//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: JSON analyzer plugin
// Copyright (c) 2013-2014 EPAM Systems
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
#define DEFAULT_PORT 8888
#define DEFAULT_HOST TcpEndpoint::WildcardAddress
#define DEFAULT_WORKERS_AMOUNT 10U
#define DEFAULT_BACKLOG 15
#define DEFAULT_MAX_SERVING_DURATION_MS 500
//------------------------------------------------------------------------------
#include "api/plugin_api.h" // include plugin development definitions
#include "json_analyzer.h"
//------------------------------------------------------------------------------
extern "C"
{

    const char* usage()
    {
        return "host - Network interface to listen (default is to listen all interfaces)\n"
               "port - IP-port to bind to (default is 8888)\n"
               "workers - Amount of worker threads (default is 10)\n"
               "duration - Max serving duration in milliseconds (default is 500 ms)\n"
               "backlog - Listen backlog (default is 15)";
    }

    IAnalyzer* create(const char* opts)
    {
        // Initializing plugin options with default values
        int backlog = DEFAULT_BACKLOG;
        std::size_t maxServingDurationMs = DEFAULT_MAX_SERVING_DURATION_MS;
        std::string host(DEFAULT_HOST);
        int port = DEFAULT_PORT;
        std::size_t workersAmount = DEFAULT_WORKERS_AMOUNT;
        // Parising plugin options
        enum
        {
            BACKLOG_SUBOPT_INDEX = 0,
            DURATION_SUBOPT_INDEX,
            HOST_SUBOPT_INDEX,
            PORT_SUBOPT_INDEX,
            WORKERS_SUBOPT_INDEX
        };
        char backlogSubOptName[] = "backlog";
        char durationSubOptName[] = "duration";
        char hostSubOptName[] = "host";
        char portSubOptName[] = "port";
        char workersSubOptName[] = "workers";
        char* const tokens[] =
        {
            backlogSubOptName,
            durationSubOptName,
            hostSubOptName,
            portSubOptName,
            workersSubOptName,
            NULL
        };
        std::size_t optsLen = strlen(opts);
        std::vector<char> optsBuf(opts, opts + optsLen + 2);
        char* optionp = &optsBuf[0];
        char* valuep;
        int optIndex;
        while ((optIndex = getsubopt(&optionp, tokens, &valuep)) >= 0)
        {
            try
            {
                switch (optIndex)
                {
                case BACKLOG_SUBOPT_INDEX:
                    backlog = std::stoi(valuep);
                    break;
                case DURATION_SUBOPT_INDEX:
                    maxServingDurationMs = std::stoul(valuep);
                    break;
                case HOST_SUBOPT_INDEX:
                    host = valuep;
                    break;
                case PORT_SUBOPT_INDEX:
                    port = std::stoi(valuep);
                    break;
                case WORKERS_SUBOPT_INDEX:
                    workersAmount = std::stoul(valuep);
                    break;
                default:
                    throw std::runtime_error(std::string("Invalid suboption index: ") + std::to_string(optIndex));
                }
            }
            catch (std::logic_error& e)
            {
                throw std::runtime_error(std::string("Invalid value provided for '") + tokens[optIndex] + "' suboption");
            }
        }
        // Creating and returning plugin
        return new JsonAnalyzer(workersAmount, port, host, maxServingDurationMs, backlog);
    }

    void destroy(IAnalyzer* instance)
    {
        delete instance;
    }

    NST_PLUGIN_ENTRY_POINTS (&usage, &create, &destroy)

} //extern "C"
//------------------------------------------------------------------------------
