//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Reader for data presented in XDR format.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef XDR_READER_H
#define XDR_READER_H
//------------------------------------------------------------------------------
#include <stdexcept>
#include <arpa/inet.h> // ntohl()
#if defined(__linux__)
#  include <endian.h> // be64toh()
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#endif

#include "api/xdr_types.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace xdr
{


using namespace NST::API;


const size_t XDR_ALIGN = 4;

class XDRError : public std::runtime_error
{
public:
    explicit XDRError(const std::string& msg) : std::runtime_error{msg} { }
};

class XDRReader
{
public:
    XDRReader(const uint8_t* ptr, size_t len)
    : beg {ptr}
    , it  {ptr}
    , last{ptr + len}
    {
    }

    inline size_t         size() const { return last-it; }
    inline const uint8_t* data() const { return it;      }
    inline size_t       offset() const { return it-beg;  }

    inline void reset(const uint8_t* ptr, size_t len)
    {
        beg = ptr;
        it = ptr;
        last = ptr+len;
    }

    inline void read_unchecked(int32_t& v)
    {
        v = (int32_t)ntohl(*(uint32_t*)it);
        it += sizeof(v);
    }

    inline void read_unchecked(uint32_t& v)
    {
        v = ntohl(*(uint32_t*)it);
        it += sizeof(v);
    }

    inline void read_unchecked(uint64_t& v)
    {
        v = be64toh(*(uint64_t*)it);
        it += sizeof(v);
    }

    inline XDRReader& operator>>(uint32_t& obj)
    {
        const size_t size = sizeof(obj);
        arrange_check(size);

        obj = ntohl(*(uint32_t*)it);
        it += size;
        return *this;
    }

    inline XDRReader& operator>>(uint64_t& obj)
    {
        const size_t size = sizeof(obj);
        arrange_check(size);

        obj = be64toh(*(uint64_t*)it);
        it += size;
        return *this;
    }

    void read_fixed_len(Opaque& obj, const uint32_t len)
    {
        arrange_check(len);
        obj.set(it, len);
        it += calc_offset(len);
    }

    void read_variable_len(Opaque& obj)
    {
        uint32_t len = 0;
        operator>>(len);

        read_fixed_len(obj, len);
    }

    inline void arrange_check(uint32_t size) const
    {
        if(it+size > last)
        {
            throw XDRError{"XDRReader::read action cannot be done"};
        }
    }

protected:
    inline static uint32_t calc_offset(uint32_t size)
    {
        uint32_t mod = size % XDR_ALIGN;
        return (mod) ? size - mod + XDR_ALIGN : size;
    }

    const uint8_t* beg;
    const uint8_t* it;
    const uint8_t* last;
};

inline const std::string to_string(const Opaque& opaque)
{
    return std::string((char*)opaque.ptr, opaque.len);
}

inline std::ostream& operator <<(std::ostream& out, const Opaque& opaque)
{
    out << std::hex;
    out.fill('0');
    for(uint32_t i = 0; i < opaque.len; i++)
    {
        out.width(2);
        out << (uint32_t) opaque.ptr[i];
    }
    out.fill(' ');
    return out << std::dec;
}

} // namespace xdr
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//XDR_READER_H
//------------------------------------------------------------------------------

