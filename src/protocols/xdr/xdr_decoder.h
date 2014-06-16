//------------------------------------------------------------------------------
// Author: Alexey Costroma
// Description: Reader for data presented in XDR format.
// Copyright (c) 2014 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef XDR_DECODER_H
#define XDR_DECODER_H
//------------------------------------------------------------------------------
#include <utility>
//------------------------------------------------------------------------------
#include "utils/filtered_data.h"
#include "protocols/xdr/xdr_reader.h"
#include "api/nfs3_types_rpcgen.h"
//------------------------------------------------------------------------------
using NST::utils::FilteredData;
using NST::utils::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace xdr
{

using namespace NST::API;


class XDRDecoder: public xdr::XDRReader
{
public:
    XDRDecoder(FilteredDataQueue::Ptr&& p)
        : XDRReader{p->data, p->dlen}
        , ptr{std::move(p)}
    {
        xdrmem_create(&xdr, (char*)p->data, p->dlen, XDR_DECODE);
    }
    ~XDRDecoder()
    {
        xdr_destroy (&xdr);
        // TODO: ?
        //xdr_free ((xdrproc_t) xdr_access3res, (char*)&myaccess3res);
    }

    inline const FilteredData& data() const { return *ptr; }
    XDR xdr;

private:
    FilteredDataQueue::Ptr ptr;
};

} // namespace xdr
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//XDR_DECODER_H
//------------------------------------------------------------------------------

