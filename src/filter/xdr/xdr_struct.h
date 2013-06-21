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

namespace NST
{
namespace filter
{
namespace XDR
{

typedef unsigned char uchar_t;

const size_t align = 4;

struct OpaqueDyn // Move to xdr
{
    std::vector<uchar_t> data;    // Size of 'size'
};

//template<size_t size>
template<uint32_t size>
struct OpaqueStat // Move to xdr
{
    uchar_t data[size];
};

}
}
}
#endif//XDR_STRUCT_H
