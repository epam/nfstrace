//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Definition of XDR structures.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef XDR_STRUCT_H
#define XDR_STRUCT_H
//------------------------------------------------------------------------------
#include <cstring> // size_t
#include <iostream>
#include <vector>

#include <stdint.h> // uintxx_t
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace XDR
{

const size_t align = 4;

struct Opaque
{
    friend std::ostream& operator<<(std::ostream& out, const Opaque& opaque)
    {
        static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        for(uint32_t j = 0; j < opaque.len; j++)
        {
            uint8_t value = opaque.ptr[j];
            out << hex[value & 0xF];
            value >>= 4;
            out << hex[value & 0xF];
        }
        return out;
    }

    inline void set(const uint8_t* p, uint32_t n)
    {
        ptr = p;
        len = n;
    }

    inline std::string get_string() const { return std::string((char*)data(), size()); }

    inline uint8_t operator[](size_t i) const { return ptr[i]; }
    inline const uint8_t* data() const { return ptr; }
    inline const uint32_t size() const { return len; }

private:
    const uint8_t* ptr;
    uint32_t       len;
};

} // namespace XDR
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//XDR_STRUCT_H
//------------------------------------------------------------------------------
