//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Show network interfaces available in libpcap.
// Copyright (c) 2013 EPAM Systems
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
#include <iostream>

#include "filtration/pcap/network_interfaces.h"
#include "filtration/pcap/pcap_error.h"
//------------------------------------------------------------------------------
using namespace NST::filtration::pcap;
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
            for(auto a : i) std::cout << '\t' << a << '\n';
        } 
        std::cout << "\n[default]: " <<  interfaces.default_device() << "\n\n";
    }
    catch(const PcapError& e)
    {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    return 0;
}
//------------------------------------------------------------------------------
