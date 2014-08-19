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
    typename ArgType,   // structure of RPC procedure parameters
    typename ResType    // structure of RPC procedure results
>
class NFSProcedure: public NST::API::RPCProcedure
{
public:
    inline NFSProcedure(xdr::XDRDecoder& c, xdr::XDRDecoder& r, const Session* s)
    : parg{&arg}    // set pointer to argument
    , pres{&res}    // set pointer to result
    {
        memset(&rpc_call, 0,sizeof(rpc_call ));
        memset(&rpc_reply,0,sizeof(rpc_reply));
        memset(&arg,      0,sizeof(arg));
        memset(&res,      0,sizeof(res));

        // fill call
        if(!xdr_callmsg(c.xdr(), &rpc_call))
        {
            xdr_free((xdrproc_t)xdr_callmsg, (char*)&rpc_call);
            throw xdr::XDRDecoderError{"XDRDecoder: cann't read call data"};
        }

        // fill call arguments
        if(!proc_t_of(arg)(c.xdr(),&arg))
        {
            xdr_free((xdrproc_t)proc_t_of(arg), (char*)&arg);
            xdr_free((xdrproc_t)xdr_callmsg,    (char*)&rpc_call);
            throw xdr::XDRDecoderError{"XDRDecoder: cann't read call arguments"};
        }

        rpc_reply.ru.RM_rmb.ru.RP_ar.ru.AR_results.proc = &r.return_true;

        // fill reply
        if(!xdr_replymsg (r.xdr(), &rpc_reply))
        {
            xdr_free((xdrproc_t)xdr_replymsg,  (char*)&rpc_reply);
            xdr_free((xdrproc_t)proc_t_of(arg),(char*)&arg);
            xdr_free((xdrproc_t)xdr_callmsg,   (char*)&rpc_call);
            throw xdr::XDRDecoderError{"XDRDecoder: cann't read reply data"};
        }
  
        if(rpc_reply.ru.RM_rmb.rp_stat == reply_stat::MSG_ACCEPTED &&
           rpc_reply.ru.RM_rmb.ru.RP_ar.ar_stat == accept_stat::SUCCESS)
        {
            // fill reply results
            if(!proc_t_of(res)(r.xdr(),&res))
            {
                xdr_free((xdrproc_t)proc_t_of(res), (char*)&res);
                xdr_free((xdrproc_t)xdr_replymsg,   (char*)&rpc_reply);
                xdr_free((xdrproc_t)proc_t_of(arg), (char*)&arg);
                xdr_free((xdrproc_t)xdr_callmsg,    (char*)&rpc_call);
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
                 xdr_free((xdrproc_t)xdr_replymsg,   (char*)&rpc_reply);
                 xdr_free((xdrproc_t)proc_t_of(arg), (char*)&arg      );
                 xdr_free((xdrproc_t)xdr_callmsg,    (char*)&rpc_call );
    }

    // pointers to procedure specific argument and result
    ArgType* parg;
    ResType* pres;

private:

    ArgType arg;
    ResType res;
};


namespace NFS3
{
using NFSPROC3RPCGEN_NULL        = NFSProcedure <rpcgen::NULL3args,        rpcgen::NULL3res>;
using NFSPROC3RPCGEN_GETATTR     = NFSProcedure <rpcgen::GETATTR3args,     rpcgen::GETATTR3res>;
using NFSPROC3RPCGEN_SETATTR     = NFSProcedure <rpcgen::SETATTR3args,     rpcgen::SETATTR3res>;
using NFSPROC3RPCGEN_LOOKUP      = NFSProcedure <rpcgen::LOOKUP3args,      rpcgen::LOOKUP3res>;
using NFSPROC3RPCGEN_ACCESS      = NFSProcedure <rpcgen::ACCESS3args,      rpcgen::ACCESS3res>;
using NFSPROC3RPCGEN_READLINK    = NFSProcedure <rpcgen::READLINK3args,    rpcgen::READLINK3res>;
using NFSPROC3RPCGEN_READ        = NFSProcedure <rpcgen::READ3args,        rpcgen::READ3res>;
using NFSPROC3RPCGEN_WRITE       = NFSProcedure <rpcgen::WRITE3args,       rpcgen::WRITE3res>;
using NFSPROC3RPCGEN_CREATE      = NFSProcedure <rpcgen::CREATE3args,      rpcgen::CREATE3res>;
using NFSPROC3RPCGEN_MKDIR       = NFSProcedure <rpcgen::MKDIR3args,       rpcgen::MKDIR3res>;
using NFSPROC3RPCGEN_SYMLINK     = NFSProcedure <rpcgen::SYMLINK3args,     rpcgen::SYMLINK3res>;
using NFSPROC3RPCGEN_MKNOD       = NFSProcedure <rpcgen::MKNOD3args,       rpcgen::MKNOD3res>;
using NFSPROC3RPCGEN_REMOVE      = NFSProcedure <rpcgen::REMOVE3args,      rpcgen::REMOVE3res>;
using NFSPROC3RPCGEN_RMDIR       = NFSProcedure <rpcgen::RMDIR3args,       rpcgen::RMDIR3res>;
using NFSPROC3RPCGEN_RENAME      = NFSProcedure <rpcgen::RENAME3args,      rpcgen::RENAME3res>;
using NFSPROC3RPCGEN_LINK        = NFSProcedure <rpcgen::LINK3args,        rpcgen::LINK3res>;
using NFSPROC3RPCGEN_READDIR     = NFSProcedure <rpcgen::READDIR3args,     rpcgen::READDIR3res>;
using NFSPROC3RPCGEN_READDIRPLUS = NFSProcedure <rpcgen::READDIRPLUS3args, rpcgen::READDIRPLUS3res>;
using NFSPROC3RPCGEN_FSSTAT      = NFSProcedure <rpcgen::FSSTAT3args,      rpcgen::FSSTAT3res>;
using NFSPROC3RPCGEN_FSINFO      = NFSProcedure <rpcgen::FSINFO3args,      rpcgen::FSINFO3res>;
using NFSPROC3RPCGEN_PATHCONF    = NFSProcedure <rpcgen::PATHCONF3args,    rpcgen::PATHCONF3res>;
using NFSPROC3RPCGEN_COMMIT      = NFSProcedure <rpcgen::COMMIT3args,      rpcgen::COMMIT3res>;
}

namespace NFS4
{
using NFSPROC4RPCGEN_NULL        = NFSProcedure <rpcgen::NULL4args,     rpcgen::NULL4res>;
using NFSPROC4RPCGEN_COMPOUND    = NFSProcedure <rpcgen::COMPOUND4args, rpcgen::COMPOUND4res>;
}

} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PROCEDURE_H
//------------------------------------------------------------------------------
