//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Definition of XDR structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef XDR_TYPES_H
#define XDR_TYPES_H
//------------------------------------------------------------------------------
#include <cstdint>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

struct Opaque
{
    inline void set(const uint8_t* p, uint32_t n)
    {
        ptr = p;
        len = n;
    }

    inline uint8_t operator[](size_t i) const { return ptr[i]; }
    inline const uint8_t* data() const { return ptr; }
    inline uint32_t size() const { return len; }

    const uint8_t* ptr;
    uint32_t       len;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//XDR_TYPES_H
//------------------------------------------------------------------------------
