//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Composite of XDRReader + related memory with RPC message
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
