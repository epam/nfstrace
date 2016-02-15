//------------------------------------------------------------------------------
// Author: Alexey Costroma
// Description: Reader for data presented in XDR format.
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
#ifndef XDR_DECODER_H
#define XDR_DECODER_H
//------------------------------------------------------------------------------
#include <utility>
#include <rpc/rpc.h>
//------------------------------------------------------------------------------
#include "api/nfs3_types_rpcgen.h"
#include "utils/filtered_data.h"
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
class XDRDecoderError : public std::runtime_error
{
public:
    explicit XDRDecoderError(const std::string& msg)
        : std::runtime_error{msg}
    {
    }
};

class XDRDecoder
{
public:
    XDRDecoder(FilteredDataQueue::Ptr&& p)
        : ptr{std::move(p)}
    {
        xdrmem_create(&txdr, (char*)ptr->data, ptr->dlen, XDR_DECODE);
    }
    ~XDRDecoder()
    {
        xdr_destroy(&txdr);
    }

    XDR*                xdr() { return &txdr; }
    const FilteredData& data() const { return *ptr; }
private:
    XDR                    txdr;
    FilteredDataQueue::Ptr ptr;
};

} // namespace xdr
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif // XDR_DECODER_H
//------------------------------------------------------------------------------
