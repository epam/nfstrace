//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Composite filtrator which composites both CIFS&NFS
// TODO: THIS CODE MUST BE TOTALLY REFACTORED!
// Copyright (c) 2014 EPAM Systems
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
#ifndef FILTRATORS_H
#define FILTRATORS_H
//------------------------------------------------------------------------------
#include "cifs_filtrator.h"
#include "rpc_filtrator.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

/*!
 * Composite filtrator which composites both CIFS&NFS
 */
template<typename Writer>
class Filtrators
{
    CIFSFiltrator<Writer> filtratorCIFS;
    RPCFiltrator<Writer> filtratorRPC;
public:
    Filtrators()
    {
    }

    Filtrators(Filtrators&&)                 = delete;
    Filtrators(const Filtrators&)            = delete;
    Filtrators& operator=(const Filtrators&) = delete;

    inline void reset()
    {
        filtratorCIFS.reset();
        filtratorRPC.reset ();
    }

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t max_rpc_hdr)
    {
        assert(w);
        filtratorCIFS.set_writer (session_ptr, w, max_rpc_hdr);
        filtratorRPC.set_writer (session_ptr, w, max_rpc_hdr);
    }

    inline void lost(const uint32_t n) // we are lost n bytes in sequence
    {
        filtratorCIFS.lost (n);
        filtratorRPC.lost (n);
    }

    void push(PacketInfo& info)
    {
        if (filtratorCIFS.inProgress(info))
        {
            filtratorCIFS.push (info);
        }
        else if (filtratorRPC.inProgress(info))
        {
            filtratorRPC.push (info);
        }
        else
        {
            //LOG("Unknown packet")
        }
    }
};// Filtrators

}// filtration

}// NST
//------------------------------------------------------------------------------
#endif // FILTRATORS_H
//------------------------------------------------------------------------------
