//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Show network interfaces available in libpcap.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include "../../src/filter/pcap/network_interfaces.h"
#include "../../src/filter/pcap/pcap_error.h"
//------------------------------------------------------------------------------
using NST::filter::pcap::NetworkInterfaces;
using NST::filter::pcap::PcapError;
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
int main(int argc, char **argv)
{
    std::cout << "Note: Reading list of network interface may require that you have special privileges." << std::endl;
    try
    {
        NetworkInterfaces interfaces;
        NetworkInterfaces::iterator it = interfaces.first();

        for(unsigned int i=1; it; i++)
        {
            std::cout << i << '.' << it.name();
            const char* dscr = it.dscr();
            if(dscr)
            {
                std::cout << " (" << dscr << ')';
            }
            if(it.is_loopback())
            {
                std::cout << " (loopback)";
            }

            std::cout << std::endl;
            it.next();
        }
    }
    catch(const PcapError& e)
    {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    return 0;
}
//------------------------------------------------------------------------------
