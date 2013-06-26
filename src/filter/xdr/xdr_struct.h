//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Definition of XDR structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef XDR_STRUCT_H
#define XDR_STRUCT_H
//------------------------------------------------------------------------------
#include <cstring> // size_t
#include <stdint.h> // uintxx_t
#include <vector>
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
    std::vector<uint8_t> data;    // Size of 'size'
};

template<uint32_t size>
struct OpaqueStat // Move to xdr
{
    uint8_t data[size];
};

}
}
}
#endif//XDR_STRUCT_H
