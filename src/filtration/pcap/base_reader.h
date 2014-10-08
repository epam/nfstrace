//------------------------------------------------------------------------------
// Author: Pavel Karneliuk (Dzianis Huznou)
// Description: High level interface for passing info Processor.
// Copyright (c) 2013 EPAM Systems
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
#ifndef BASE_READER_H
#define BASE_READER_H
//------------------------------------------------------------------------------
#include <ostream>
#include <string>

#include <pcap/pcap.h>

#include "filtration/pcap/pcap_error.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

inline const char* library_version() { return pcap_lib_version(); }

class BaseReader
{
protected:
    BaseReader(const std::string& input)
    : handle{nullptr}
    , source{input}
    {
    }

    virtual ~BaseReader()
    {
        if(handle)
        {
            pcap_close(handle);
        }
    }

public:
    bool loop(void* user, pcap_handler callback, int count=0)
    {
        const int err = pcap_loop(handle, count, callback, (u_char*)user);
        if(err == -1) throw PcapError("pcap_loop", pcap_geterr(handle));

        return err == 0; // count is exhausted
    }

    inline void     break_loop() { pcap_breakloop(handle); }
    inline pcap_t*& get_handle() { return handle;          }

    inline        int         datalink             () const { return pcap_datalink(handle); }
    inline static const char* datalink_name        (const int dlt) { return pcap_datalink_val_to_name(dlt);        }
    inline static const char* datalink_description (const int dlt) { return pcap_datalink_val_to_description(dlt); }

    virtual void print_statistic(std::ostream& out) const = 0;

protected:
    pcap_t* handle;
    const std::string source;
};

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_READER_H
//------------------------------------------------------------------------------
