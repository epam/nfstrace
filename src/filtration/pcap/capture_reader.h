//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class for capturing network packets and pass them to filtration.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CAPTURE_READER_H
#define CAPTURE_READER_H
//------------------------------------------------------------------------------
#include <ostream>

#include "filtration/pcap/base_reader.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

class CaptureReader : public BaseReader
{
public:
    enum class Direction : int
    {
        INOUT,
        IN,
        OUT,
    };

    struct Params
    {
        std::string interface  { };
        std::string filter     { };
        int         snaplen    {0};
        int         timeout_ms {0};
        int         buffer_size{0};
        bool        promisc    {true};
        Direction   direction  {Direction::INOUT};
    };

    CaptureReader(const Params& params);
    ~CaptureReader() = default;

    void print_statistic(std::ostream& out) const override;
};

std::ostream& operator<<(std::ostream&, const CaptureReader::Params&);

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//CAPTURE_READER_H
//------------------------------------------------------------------------------
