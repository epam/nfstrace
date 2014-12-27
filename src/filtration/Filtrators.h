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

template<typename Writer>
class Filtrators
{
    CIFSFiltrator<Writer> filtratorCIFS;
    RPCFiltrator<Writer> filtratorRPC;
public:
    Filtrators()
    {
    }

    inline void reset()
    {
        filtratorCIFS.reset();
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

    Filtrators(Filtrators&&)                 = delete;
    Filtrators(const Filtrators&)            = delete;
    Filtrators& operator=(const Filtrators&) = delete;

    void push(PacketInfo& info)
    {
        filtratorCIFS.push (info);
        filtratorRPC.push (info);
    }
};
}
}

#endif // FILTRATORS_H
