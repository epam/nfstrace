//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Show network interfaces available in libpcap.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include "filtration/pcap/network_interfaces.h"
#include "filtration/pcap/pcap_error.h"
//------------------------------------------------------------------------------
using NST::filtration::pcap::NetworkInterfaces;
using NST::filtration::pcap::PcapError;
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
int main()
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
