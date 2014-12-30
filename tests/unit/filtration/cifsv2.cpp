//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: CIFS v2 tests
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
//------------------------------------------------------------------------------
class Writer
{
public:

    class Collection
    {
        Collection *pImpl = nullptr;
    public:
        void set(Writer& w, NST::utils::NetworkSession* /*session_ptr*/)
        {
            pImpl = &w.collection;
        }

        virtual void reset()
        {
            if (pImpl)
            {
                pImpl->reset();
            }
        }

    };
    class CollectionMock : public Collection
    {
    public:
        MOCK_METHOD0(reset, void());

    };

    CollectionMock collection;
};

TEST(Filtration, CIFSFiltrator)
{
    Writer mock;
    EXPECT_CALL(mock.collection, reset())
        .Times(1);

    CIFSFiltrator<Writer> f;
    f.set_writer(nullptr, &mock, 0);
    f.reset();
}

TEST(Filtration, filtrators)
{
    Writer mock;
    EXPECT_CALL(mock.collection, reset())
        .Times(2);

    Filtrators<Writer> f;
    f.set_writer(nullptr, &mock, 0);
    f.reset();
}

//------------------------------------------------------------------------------
