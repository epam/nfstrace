//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: FH is a representation nfs_fh3, which is prepared for use in tables and trees. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
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
    {
        hash += fh.data[i];
    }
    return hash;
}

bool FH::FH_Eq::operator()(const FH& a, const FH& b) const
{
    if(a.len != b.len)
        return false;

    for(uint32_t i = 0; i < a.len; ++i)
    {
        if(a.data[i] != b.data[i])
            return false;
    }
    return true;
}

std::ostream& operator<<(std::ostream& out, const FH& obj)
{
    for(uint32_t i = 0; i < obj.len; ++i)
    {
        out << (uint32_t) obj.data[i];
    }
    return out;
}

} // namespace analyzers
} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
