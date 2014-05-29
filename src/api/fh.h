//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: FH is a representation nfs_fh3, which is prepared for use in tables and trees. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FH_H
#define FH_H
//------------------------------------------------------------------------------
#include <cstring>  //memcpy()
#include <ostream>  //std::ostream
#include <iomanip>
#include <cstdint>

#include "nfs3_types.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

struct FH
{
    struct FH_Eq
    {
        bool operator()(const FH& a, const FH& b) const;
    };
    struct FH_Hash
    {
        int operator()(const FH& fh) const;
    };

    inline FH(const nfs_fh3& obj)
    {
        len = obj.data.len;
        memcpy(data, obj.data.ptr, len);
    }
    inline FH(const FH& obj)
    {
        len = obj.len;
        memcpy(data, obj.data, len);
    }
    std::string to_string() const;

    friend std::ostream& operator<<(std::ostream& out, const FH& obj);

    uint32_t len;
    uint8_t data[NFS3_FHSIZE];

private:
    static inline char to_char(uint8_t hex)
    {
        if(hex < 0xA)
            return hex + '0';
        else
            return hex + 'a' - 0xA;
    }
};

extern "C"
std::ostream& print_nfs_fh3(std::ostream& out, const FH& fh);

inline int FH::FH_Hash::operator()(const FH& fh) const
{
    int hash = 0;
    for(uint32_t i = 0; i < fh.len; ++i)
        hash += fh.data[i];
    return hash;
}

inline bool FH::FH_Eq::operator()(const FH& a, const FH& b) const
{
    if(a.len != b.len)
        return false;

    for(uint32_t i = 0; i < a.len; ++i)
        if(a.data[i] != b.data[i])
            return false;
    return true;
}

inline std::string FH::to_string() const
{
    std::string str;
    str.reserve(NFS3_FHSIZE * 2 + 1); // One byte holds two symbols.
    for(uint32_t i = 0; i < len; ++i)
    {
        str += to_char((data[i] >> 4) & 0xf);
        str += to_char(data[i] & 0xf);
    }
    return str;
}

inline std::ostream& operator<<(std::ostream& out, const FH& fh)
{
    return print_nfs_fh3(out, fh);
}

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif //FH_H
//------------------------------------------------------------------------------
