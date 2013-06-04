//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Enumerates list of network devices, based on pcap_findalldevs()
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <pcap/pcap.h>

#include "network_interfaces.h"
#include "pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

NetworkInterfaces::NetworkInterfaces():interfaces(NULL)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&interfaces, errbuf) == -1)
    {
        throw PcapError("pcap_findalldevs", errbuf);
    }
}

NetworkInterfaces::~NetworkInterfaces()
{
    pcap_freealldevs(interfaces);
}

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
