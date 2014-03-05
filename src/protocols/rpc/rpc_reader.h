//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Composite of XDRReader + related memory with RPC message
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RPC_READER_H
#define RPC_READER_H
//------------------------------------------------------------------------------
#include <utility>

#include "utils/filtered_data.h"
#include "protocols/xdr/xdr_reader.h"
//------------------------------------------------------------------------------
using NST::utils::FilteredData;
using NST::utils::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace rpc
{

class RPCReader: public xdr::XDRReader
{
public:
    RPCReader(FilteredDataQueue::Ptr&& p)
        : XDRReader{p->data, p->dlen}
        , ptr{std::move(p)}
    {
    }
    ~RPCReader()
    {
    }

    inline const FilteredData& data() const { return *ptr; }

private:
    FilteredDataQueue::Ptr ptr;
};

} // namespace rpc
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//RPC_READER_H
//------------------------------------------------------------------------------
