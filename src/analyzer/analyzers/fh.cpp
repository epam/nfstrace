//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: FH is a representation nfs_fh3, which is prepared for use in tables and trees. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iomanip>

#include "fh.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{
namespace analyzers
{

int FH::FH_Hash::operator()(const FH& fh) const
{
    int hash = 0;
    for(uint32_t i = 0; i < fh.len; ++i)
        hash += fh.data[i];
    return hash;
}

bool FH::FH_Eq::operator()(const FH& a, const FH& b) const
{
    if(a.len != b.len)
        return false;

    for(uint32_t i = 0; i < a.len; ++i)
        if(a.data[i] != b.data[i])
            return false;
    return true;
}

std::string FH::to_string() const
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

std::ostream& operator<<(std::ostream& out, const FH& obj)
{
    const std::ios::fmtflags   f = out.flags(std::ios::hex);
    const char                 c = out.fill('0');

    for(uint32_t i = 0; i < obj.len; ++i)
    {
        out.width(2);
        out << (uint32_t) obj.data[i];
    }

    out.flags(f);
    out.fill(c);

    return out;
}

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
