//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Reader for data presented in XDR format.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef XDR_READER_H
#define XDR_READER_H
//------------------------------------------------------------------------------
#include <stdexcept>
#include <string>

#include <arpa/inet.h> // ntohl()
#if defined(__linux__)
#  include <endian.h> // be64toh()
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#endif

#include "xdr_struct.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace XDR
{

class XDRReader
{
public:
    XDRReader() : it(NULL), last(NULL)
    {
    }
    XDRReader(uint8_t* beg, size_t num) : it(beg), last(beg + num)
    {
    }
    ~XDRReader()
    {
    }

    XDRReader& operator>>(uint16_t& obj)
    {
        const size_t size = sizeof(obj);
        arrange_check(size);

        obj = ntohl(*(uint16_t*)it);
        it += size;
        return *this;
    }

    XDRReader& operator>>(uint32_t& obj)
    {
        const size_t size = sizeof(obj);
        arrange_check(size);

        obj = ntohl(*(uint32_t*)it);
        it += size;
        return *this;
    }

    XDRReader& operator>>(uint64_t& obj)
    {
        const size_t size = sizeof(obj);
        arrange_check(size);

        obj = be64toh(*(uint64_t*)it);
        it += size;
        return *this;
    }

    XDRReader& operator>>(std::string& obj)
    {
        uint32_t len = 0;
        operator>>(len);
        arrange_check(len);

        obj.reserve(len);
        obj.assign((std::string::value_type*)it, len);
        it += calc_offset(len);

        return *this;
    }

    XDRReader& operator>>(OpaqueDyn& obj)
    {
        uint32_t size = 0;
        operator>>(size);
        arrange_check(size);

        obj.data.assign(it, it+size);
        it += calc_offset(size);
        return *this;
    }

    template<uint32_t size>
    XDRReader& operator>>(OpaqueStat<size>& obj)
    {
        arrange_check(size);

        memcpy(&obj, it, size);
        it += calc_offset(size);
        return *this;
    }
    
private:
    inline void arrange_check(size_t size)
    {
        if(it+size > last)
        {
            throw std::out_of_range("XDRReader::read action cannot be done");
        }
    }

    inline uint32_t calc_offset(uint32_t size)
    {
        uint32_t mod = size % align;
        return (mod) ? size - mod + align : size;
    }

private:
    const uint8_t* it;
    const uint8_t* last;
};

} // namespace XDR
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//XDR_READER_H
//------------------------------------------------------------------------------

