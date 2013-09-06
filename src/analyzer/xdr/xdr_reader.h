//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Reader for data presented in XDR format.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef XDR_READER_H
#define XDR_READER_H
//------------------------------------------------------------------------------
#include <arpa/inet.h> // ntohl()
#if defined(__linux__)
#  include <endian.h> // be64toh()
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#endif

#include "../../auxiliary/exception.h"
#include "xdr_structs.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Exception;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace XDR
{

class XDRError : public Exception
{
public:
    explicit XDRError(const std::string& msg) : Exception(msg)
    {
    }
    virtual const XDRError* dynamic_clone() const { return new XDRError(*this); }
    virtual void            dynamic_throw() const { throw *this; }
};

class XDRReader
{
public:
    XDRReader(const uint8_t* ptr, size_t len) : beg(ptr), it(ptr), last(ptr + len)
    {
    }

    inline const size_t   size() const { return last-it; }
    inline const uint8_t* data() const { return it;      }

    inline uint32_t get_offset() const
    {
        return it - beg;
    }

    inline void reset(const uint8_t* ptr, size_t len)
    {
        beg = ptr;
        it = ptr;
        last = ptr+len;
    }

    inline void read_unchecked(uint32_t& v)
    {
        v = ntohl(*(uint32_t*)it);
        it += sizeof(v);
    }

    inline void read(uint32_t& v)
    {
        arrange_check(sizeof(v));
        read_unchecked(v);
    }

    inline void read_unchecked(uint64_t& v)
    {
        v = be64toh(*(uint64_t*)it);
        it += sizeof(v);
    }

    inline void read(uint64_t& v)
    {
        arrange_check(sizeof(v));
        read_unchecked(v);
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
        arrange_check(len);

        obj.set(it, len);

        it += calc_offset(len);
    }

    inline void arrange_check(uint32_t size) const
    {
        if(it+size > last)
        {
            throw XDRError("XDRReader::read action cannot be done");
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

} // namespace XDR
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//XDR_READER_H
//------------------------------------------------------------------------------

