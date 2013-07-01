//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Definition of XDR structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef XDR_STRUCT_H
#define XDR_STRUCT_H
//------------------------------------------------------------------------------
#include <cstring> // size_t
#include <vector>
#include <iostream>

#include <stdint.h> // uintxx_t
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace XDR
{

const size_t align = 4;

struct OpaqueDyn // Move to xdr
{
private:
    typedef std::vector<uint8_t> Opaque;
public:
    std::vector<uint8_t> data;    // Size of 'size'

    friend std::ostream& operator<<(std::ostream& out, const OpaqueDyn& opaque)
    {
        Opaque::const_iterator i = opaque.data.begin();
        Opaque::const_iterator end = opaque.data.end();
        for(;i != end; ++i)
        {
            out << std::hex << static_cast<uint32_t>(*i);
        }
        return out;
    }
};

template<uint32_t size>
struct OpaqueStat // Move to xdr
{
    uint8_t data[size];

    friend std::ostream& operator<<(std::ostream& out, const OpaqueStat<size>& opaque)
    {
        for(uint32_t i = 0; i != size; ++i)
        {
            out << std::hex << static_cast<uint32_t>(opaque.data[i]);
        }
        return out;
    }
};

} // namespace XDR
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//XDR_STRUCT_H
//------------------------------------------------------------------------------
