//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Composite of XDRReader + related memory with RPC message
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_READER_H
#define RPC_READER_H
//------------------------------------------------------------------------------
#include "../../auxiliary/filtered_data.h"
#include "../xdr/xdr_reader.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredData;
using NST::auxiliary::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace RPC
{

class RPCReader: public XDR::XDRReader
{
public:

    RPCReader(FilteredDataQueue::Ptr& p) : XDRReader(p->data, p->dlen), ptr(p)
    {
    }
    ~RPCReader()
    {
    }

    inline const FilteredData& data() const { return ptr; }

private:
    FilteredDataQueue::Ptr ptr;
};

} // namespace RPC
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_READER_H
//------------------------------------------------------------------------------
