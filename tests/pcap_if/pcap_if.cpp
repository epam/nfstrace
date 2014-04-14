//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Show network interfaces available in libpcap.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>

#include "filtration/pcap/network_interfaces.h"
#include "filtration/pcap/pcap_error.h"
//------------------------------------------------------------------------------
using namespace NST::filtration::pcap;
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
int main()
{
    std::cout << "Note: Reading list of network interfaces may "
                  "require that you have special privileges." << std::endl;
    try
    {
        NetworkInterfaces interfaces;
        for(auto i : interfaces)
        {
            std::cout << i << '\n';
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
