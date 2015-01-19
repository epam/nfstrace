//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Composite filtrator tests
// Copyright (c) 2013-2014 EPAM Systems
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
#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "controller/running_status.h"
#include "filtration/filtration_processor.h"
#include "filtration/cifs_filtrator.h"
#include "filtration/filtrators.h"
#include "filtration/packet.h"
//------------------------------------------------------------------------------
using namespace NST::filtration;
using ::testing::Return;
using ::testing::AtLeast;
using ::testing::_;
//------------------------------------------------------------------------------
namespace {

class Writer
{
public:

    class Collection
    {
        std::vector<uint8_t> packet;
        Collection *pImpl = nullptr;
    public:
        void set(Writer& w, NST::utils::NetworkSession* /*session_ptr*/)
        {
            pImpl = &w.collection;
        }

        virtual void reset()
        {
            packet.clear();
        }

        virtual void push(PacketInfo& info, size_t size)
        {
            std::copy(info.data, info.data + size, std::back_inserter(packet));
        }

        virtual void skip_first(size_t)
        {
        }

        virtual void complete(PacketInfo& info)
        {
            if (pImpl)
            {
                pImpl->complete(info);
            }
        }

        operator bool()
        {
            return true;
        }

        virtual const uint8_t * data()
        {
            return packet.data();
        }

        virtual size_t data_size()
        {
            return packet.size();
        }

        virtual size_t capacity()
        {
            return 1000000;
        }

        virtual void allocate()
        {
        }
    };
    class CollectionMock : public Collection
    {
    public:
        MOCK_METHOD0(reset, void());
        MOCK_METHOD2(push, void(PacketInfo&, size_t));
        MOCK_METHOD0(data, const uint8_t *());
        MOCK_METHOD0(data_size, size_t());
        MOCK_METHOD1(complete, void(PacketInfo&));

    };

    CollectionMock collection;
};

}

TEST(Filtration, pushCIFSbyTCPStream)
{
    // Prepare data
    struct pcap_pkthdr header;
    header.caplen = header.len = 132;
    const uint8_t packet[] = {0x00, 0x00, 0x00, 0x80,
                              0xfe, 0x53, 0x4d, 0x42,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00
                             };
    PacketInfo info(&header, packet, 0);
    Writer mock;
    // Set conditions
    EXPECT_CALL(mock.collection, complete(_))
        .Times(AtLeast(1));

    Filtrators<Writer> f;
    f.set_writer(nullptr, &mock, 0);
    // Check
    f.push(info);
}

TEST(Filtration, pushCIFSbyTCPStreamPartByPart)
{
    // Prepare data
    struct pcap_pkthdr header1;
    header1.caplen = header1.len = 3;
    const uint8_t packet[] = {0x00, 0x00, 0x00, 0x80,
                              0xfe, 0x53, 0x4d, 0x42,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00
                             };
    PacketInfo info1(&header1, packet, 0);

    struct pcap_pkthdr header2;
    header2.caplen = header2.len = sizeof(packet) - header1.len;
    PacketInfo info2(&header2, packet + header1.len, 0);
    Writer mock;

    // Set conditions
    EXPECT_CALL(mock.collection, complete(_))
        .Times(AtLeast(1));

    Filtrators<Writer> f;
    f.set_writer(nullptr, &mock, 0);
    // Check
    f.push(info1);
    f.push(info2);
}

TEST(Filtration, pushRPCbyTCPStream)
{
    // Prepare data
    struct pcap_pkthdr header;
    header.caplen = header.len = 132;
    const uint8_t packet[] = {0x80, 0x00, 0x00, 0x80,
                              0xec, 0x8a, 0x42, 0xcb,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x02,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00
                             };
    PacketInfo info(&header, packet, 0);
    Writer mock;
    // Set conditions
    EXPECT_CALL(mock.collection, complete(_))
        .Times(AtLeast(1));

    Filtrators<Writer> f;
    f.set_writer(nullptr, &mock, 0);
    // Check
    f.push(info);
}

TEST(Filtration, pushRPCbyTCPStreamPartByPart)
{
    // Prepare data
    struct pcap_pkthdr header1;
    header1.caplen = header1.len = 3;
    const uint8_t packet[] = {0x80, 0x00, 0x00, 0x80,
                              0xec, 0x8a, 0x42, 0xcb,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x02,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00,

                              0x00, 0x00, 0x00, 0x00
                             };
    PacketInfo info1(&header1, packet, 0);

    struct pcap_pkthdr header2;
    header2.caplen = header2.len = sizeof(packet) - header1.len;
    PacketInfo info2(&header2, packet + header1.len, 0);
    Writer mock;

    // Set conditions
    EXPECT_CALL(mock.collection, complete(_))
        .Times(AtLeast(1));

    Filtrators<Writer> f;
    f.set_writer(nullptr, &mock, 0);
    // Check
    f.push(info1);
    f.push(info2);
}

//------------------------------------------------------------------------------

