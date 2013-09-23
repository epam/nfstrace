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
#include <stdint.h>

#include "plugin_api_struct.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
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
    uint8_t data[64];

private:
    static inline char to_char(uint8_t hex)
    {
        if(hex < 0xA)
            return hex + '0';
        else
            return hex + 'a' - 0xA;
    }
};
//------------------------------------------------------------------------------
#endif//FH_H
//------------------------------------------------------------------------------
