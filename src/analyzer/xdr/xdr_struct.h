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

struct OpaqueDyn
{
private:
    typedef std::vector<uint8_t> Opaque;
public:
    std::vector<uint8_t> data;    // XDR specific size

    friend std::ostream& operator<<(std::ostream& out, const OpaqueDyn& opaque)
    {
        Opaque::const_iterator i = opaque.data.begin();
        Opaque::const_iterator end = opaque.data.end();
        for(;i != end; ++i)
        {
            out << static_cast<uint32_t>(*i);
        }
        return out;
    }
    std::string to_string() const
    {
        std::stringstream ss;
        
        Opaque::const_iterator i = data.begin();
        Opaque::const_iterator end = data.end();
        for(;i != end; ++i)
        {
            ss << static_cast<char>(*i);
        }
        return ss.str();
    }
};

template<uint32_t size>
struct OpaqueStat
{
    OpaqueStat() : data(size)
    {
    }

    std::vector<uint8_t> data;
    friend std::ostream& operator<<(std::ostream& out, const OpaqueStat<size>& opaque)
    {
        for(uint32_t i = 0; i != size; ++i)
        {
            out << static_cast<uint32_t>(opaque.data[i]);
        }
        return out;
    }
    std::string to_string() const
    {
        std::stringstream ss;
        
        for(uint32_t i = 0; i != size; ++i)
        {
            ss << static_cast<char>(data[i]);
        }
        return ss.str();
    }
};

} // namespace XDR
} // namespace analyzer 
} // namespace NST
//------------------------------------------------------------------------------
#endif//XDR_STRUCT_H
//------------------------------------------------------------------------------
