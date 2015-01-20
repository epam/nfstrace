//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Abstract impementation of filtrator class
// TODO: THIS CODE MUST BE TOTALLY REFACTORED!
// Copyright (c) 2014 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef IFILTRATOR_H
#define IFILTRATOR_H
//------------------------------------------------------------------------------
//#include "filtration/packet.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

class FiltratorImpl
{
    FiltratorImpl(FiltratorImpl&&)                 = delete;
    FiltratorImpl(const FiltratorImpl&)            = delete;
    FiltratorImpl& operator=(const FiltratorImpl&) = delete;
public:
    FiltratorImpl() {}

    using IsRightHeader = bool(const uint8_t* header);

    template<size_t header_len, IsRightHeader isRightHeader,typename Writer, typename Filtrator>
    inline static bool inProgressImpl(PacketInfo& info, Writer& collection, Filtrator* filtrator)
    {
        if (!collection) // collection isn't allocated
        {
            collection.allocate(); // allocate new collection from writer
        }
        const size_t data_size = collection.data_size();

        if (data_size + info.dlen > header_len)
        {
            static uint8_t buffer[header_len];
            const uint8_t* header = info.data;

            if (data_size > 0)
            {
                // Coping happends only once per TCP-session
                memcpy(buffer, collection.data(), data_size);
                memcpy(buffer + data_size, info.data, header_len - data_size);
                header = buffer;
            }

            // It is right header
            if (isRightHeader(header))
            {
                return true;
            }

            filtrator->reset();
        }
        else
        {
            collection.push(info, info.dlen);
        }

        return false;
    }

};

} // filtration

} // NST
//------------------------------------------------------------------------------
#endif // IFILTRATOR_H
//------------------------------------------------------------------------------
