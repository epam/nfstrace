//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Parsers tests
// Copyright (c) 2015 EPAM Systems
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

#include <arpa/inet.h>

#include "analysis/analyzers.h"
#include "analysis/cifs_parser.h"
#include "api/cifs_types.h"
#include "api/cifs_pc_to_net.h"
//------------------------------------------------------------------------------
using namespace NST::filtration;
using namespace NST::analysis;
using namespace NST::controller;
using namespace NST::utils;

using ::testing::Return;
using ::testing::AtLeast;
using ::testing::_;
//------------------------------------------------------------------------------

namespace
{

class PluginMock : public IAnalyzer
{
public:
    // ISMBv2 interface
    MOCK_METHOD3(readSMBv2, void(const SMBv2::ReadCommand *, const NST::API::SMBv2::ReadRequest *, const NST::API::SMBv2::ReadResponse *));

    // IAnalyzer interface
    void flush_statistics() {}
};


PluginMock* pluginMock;// pointer to mock
}
//------------------------------------------------------------------------------
Analyzers::Analyzers(const controller::Parameters& /*params*/)
{
    this->modules.push_back(pluginMock);
}
//------------------------------------------------------------------------------
Parameters::Parameters(int /*argc*/, char** /*argv*/) {}

Parameters::~Parameters() {}

bool Parameters::show_help() const
{
    return false;
}

bool Parameters::show_enum() const
{
    return false;
}

const std::string& Parameters::program_name() const
{
    static std::string s("");
    return s;
}

RunningMode Parameters::running_mode() const
{
    return RunningMode::Analysis;
}

std::string Parameters::input_file() const
{
    return "";
}

const std::string Parameters::dropuser() const
{
    return "";
}

const std::string Parameters::log_path() const
{
    return "";
}

unsigned short Parameters::queue_capacity() const
{
    return 0;
}

bool Parameters::trace() const
{
    return false;
}
int Parameters::verbose_level() const
{
    return 0;
}

const NST::filtration::pcap::CaptureReader::Params Parameters::capture_params() const
{
    return NST::filtration::pcap::CaptureReader::Params();
}

const NST::filtration::Dumping::Params Parameters::dumping_params() const
{
    return NST::filtration::Dumping::Params();
}

const std::vector<AParams>& Parameters::analysis_modules() const
{
    static std::vector<AParams> Parameters;
    return Parameters;
}

unsigned short Parameters::rpcmsg_limit()
{
    return 0;
}
//------------------------------------------------------------------------------
const std::string Plugin::usage_of(const std::string& /*path*/)
{
    return "";
}

DynamicLoad::DynamicLoad(const std::string &/*file*/) {}

DynamicLoad::~DynamicLoad() {}

template<typename plugin_get_entry_points_func>
void load_address_of(const std::string& /*name*/, plugin_get_entry_points_func& /*address*/)
{}

Plugin::Plugin(const std::string& path) : DynamicLoad(path) {}

PluginInstance::PluginInstance(const std::string& path, const std::string& /*args*/) : Plugin(path) {}

PluginInstance::~PluginInstance() {}

//------------------------------------------------------------------------------
TEST(Parser, CIFSAsyncParser)
{
    pluginMock = new PluginMock;

    NST::controller::Parameters params(0, nullptr);
    Analyzers analyzers(params);

    NST::utils::FilteredDataQueue queue(1, 1);
    NST::utils::FilteredData* data = queue.allocate();
    NetworkSession s;
    data->session = &s;
    queue.push(data);
    NST::utils::FilteredDataQueue::List list(queue);
    NST::utils::FilteredDataQueue::Ptr el = list.get_current();

    CIFSv2::MessageHeader header;
    header.head_code =  NST::API::SMBv2::pc_to_net<uint32_t>(0x424d53fe);// Protocol's marker
    header.cmd_code = CIFSv2::Commands::READ;
    header.flags = static_cast<uint32_t>(CIFSv2::Flags::ASYNC_COMMAND);

    el->data = reinterpret_cast<uint8_t*>(&header);
    el->dlen = sizeof(header);

    CIFSParser parser(analyzers);

    // Set conditions
    EXPECT_CALL(*pluginMock, readSMBv2(_, _, _))
    .Times(1);

    // Do
    parser.parse_data(el);

    delete pluginMock;
}
//------------------------------------------------------------------------------

