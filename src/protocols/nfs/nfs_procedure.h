//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition and fill up NFS procedures.
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
#ifndef NFS_PROCEDURE_H
#define NFS_PROCEDURE_H
//------------------------------------------------------------------------------
#include <rpc/rpc.h>

#include "api/rpc_procedure.h"
#include "protocols/nfs3/nfs3_utils.h"
#include "protocols/nfs4/nfs4_utils.h"
#include "utils/sessions.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
using namespace NFS3;
using namespace NFS4;

template
<
    typename ArgType, // structure of RPC procedure parameters
    typename ResType  // structure of RPC procedure results
>
class NFSProcedure: public NST::API::RPCProcedure
{
public:
    inline NFSProcedure(xdr::XDRDecoder& c, xdr::XDRDecoder& r, const Session* s)
    : parg{&arg}    // set pointer to argument
    , pres{&res}    // set pointer to result
    {
        memset(&call, 0,sizeof(call ));
        memset(&reply,0,sizeof(reply));
        memset(&arg,      0,sizeof(arg      ));
        memset(&res,      0,sizeof(res      ));

        // fill call
        if(!xdr_callmsg(c.xdr(), &call))
        {
            xdr_free((xdrproc_t)xdr_callmsg, (char*)&call);
            throw xdr::XDRDecoderError{"XDRDecoder: cann't read call data"};
        }

        // fill call arguments
        if(!proc_t_of(arg)(c.xdr(),&arg))
        {
            xdr_free((xdrproc_t)proc_t_of(arg), (char*)&arg     );
            xdr_free((xdrproc_t)xdr_callmsg,    (char*)&call);
            throw xdr::XDRDecoderError{"XDRDecoder: cann't read call arguments"};
        }

        reply.ru.RM_rmb.ru.RP_ar.ru.AR_results.proc = &return_true;

        // fill reply
        if(!xdr_replymsg (r.xdr(), &reply))
        {
            xdr_free((xdrproc_t)xdr_replymsg,  (char*)&reply);
            xdr_free((xdrproc_t)proc_t_of(arg),(char*)&arg      );
            xdr_free((xdrproc_t)xdr_callmsg,   (char*)&call );
            throw xdr::XDRDecoderError{"XDRDecoder: cann't read reply data"};
        }
  
        if(reply.ru.RM_rmb.rp_stat == reply_stat::MSG_ACCEPTED &&
           reply.ru.RM_rmb.ru.RP_ar.ar_stat == accept_stat::SUCCESS)
        {
            // fill reply results
            if(!proc_t_of(res)(r.xdr(),&res))
            {
                xdr_free((xdrproc_t)proc_t_of(res), (char*)&res      );
                xdr_free((xdrproc_t)xdr_replymsg,   (char*)&reply);
                xdr_free((xdrproc_t)proc_t_of(arg), (char*)&arg      );
                xdr_free((xdrproc_t)xdr_callmsg,    (char*)&call );
                throw xdr::XDRDecoderError{"XDRDecoder: cann't read reply results"};
            }
        }
        else
        {
            pres = nullptr;
        }

        session = s;

        ctimestamp = &c.data().timestamp;
        rtimestamp = &r.data().timestamp;
    }

    inline ~NFSProcedure()
    {
        if(pres) xdr_free((xdrproc_t)proc_t_of(res), (char*)&res      );
                 xdr_free((xdrproc_t)xdr_replymsg,   (char*)&reply);
                 xdr_free((xdrproc_t)proc_t_of(arg), (char*)&arg      );
                 xdr_free((xdrproc_t)xdr_callmsg,    (char*)&call );
    }

    // pointers to procedure specific argument and result
    ArgType* parg;
    ResType* pres;

private:
    inline static bool_t return_true(XDR*, void*, ...) { return 1; }
    inline static bool_t return_true(XDR*, ...)        { return 1; }

    ArgType arg;
    ResType res;
};

namespace NFS3
{

namespace NFS3 = NST::API::NFS3;
using NFSPROC3RPCGEN_NULL        = NFSProcedure <NFS3::NULL3args,        NFS3::NULL3res>;
using NFSPROC3RPCGEN_GETATTR     = NFSProcedure <NFS3::GETATTR3args,     NFS3::GETATTR3res>;
using NFSPROC3RPCGEN_SETATTR     = NFSProcedure <NFS3::SETATTR3args,     NFS3::SETATTR3res>;
using NFSPROC3RPCGEN_LOOKUP      = NFSProcedure <NFS3::LOOKUP3args,      NFS3::LOOKUP3res>;
using NFSPROC3RPCGEN_ACCESS      = NFSProcedure <NFS3::ACCESS3args,      NFS3::ACCESS3res>;
using NFSPROC3RPCGEN_READLINK    = NFSProcedure <NFS3::READLINK3args,    NFS3::READLINK3res>;
using NFSPROC3RPCGEN_READ        = NFSProcedure <NFS3::READ3args,        NFS3::READ3res>;
using NFSPROC3RPCGEN_WRITE       = NFSProcedure <NFS3::WRITE3args,       NFS3::WRITE3res>;
using NFSPROC3RPCGEN_CREATE      = NFSProcedure <NFS3::CREATE3args,      NFS3::CREATE3res>;
using NFSPROC3RPCGEN_MKDIR       = NFSProcedure <NFS3::MKDIR3args,       NFS3::MKDIR3res>;
using NFSPROC3RPCGEN_SYMLINK     = NFSProcedure <NFS3::SYMLINK3args,     NFS3::SYMLINK3res>;
using NFSPROC3RPCGEN_MKNOD       = NFSProcedure <NFS3::MKNOD3args,       NFS3::MKNOD3res>;
using NFSPROC3RPCGEN_REMOVE      = NFSProcedure <NFS3::REMOVE3args,      NFS3::REMOVE3res>;
using NFSPROC3RPCGEN_RMDIR       = NFSProcedure <NFS3::RMDIR3args,       NFS3::RMDIR3res>;
using NFSPROC3RPCGEN_RENAME      = NFSProcedure <NFS3::RENAME3args,      NFS3::RENAME3res>;
using NFSPROC3RPCGEN_LINK        = NFSProcedure <NFS3::LINK3args,        NFS3::LINK3res>;
using NFSPROC3RPCGEN_READDIR     = NFSProcedure <NFS3::READDIR3args,     NFS3::READDIR3res>;
using NFSPROC3RPCGEN_READDIRPLUS = NFSProcedure <NFS3::READDIRPLUS3args, NFS3::READDIRPLUS3res>;
using NFSPROC3RPCGEN_FSSTAT      = NFSProcedure <NFS3::FSSTAT3args,      NFS3::FSSTAT3res>;
using NFSPROC3RPCGEN_FSINFO      = NFSProcedure <NFS3::FSINFO3args,      NFS3::FSINFO3res>;
using NFSPROC3RPCGEN_PATHCONF    = NFSProcedure <NFS3::PATHCONF3args,    NFS3::PATHCONF3res>;
using NFSPROC3RPCGEN_COMMIT      = NFSProcedure <NFS3::COMMIT3args,      NFS3::COMMIT3res>;
}

namespace NFS4
{

namespace NFS4 = NST::API::NFS4;
using NFSPROC4RPCGEN_NULL        = NFSProcedure <NFS4::NULL4args,     NFS4::NULL4res>;
using NFSPROC4RPCGEN_COMPOUND    = NFSProcedure <NFS4::COMPOUND4args, NFS4::COMPOUND4res>;
}

} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PROCEDURE_H
//------------------------------------------------------------------------------
