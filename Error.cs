using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Network_sniffer
{
    public class Error
    {
        public static void print_error(int error_code)
        {
            switch(error_code)
            {
                case 1:
                    Console.Error.WriteLine("Wrong argument entered");
                    break;
                case 3:
                    Console.Error.WriteLine("Entered port without using --tcp|-t or --udp|-u");
                    break;
                case 5:
                    Console.Error.WriteLine("Wrong or no interface name entered");
                    break;
                case 99:
                    Console.Error.WriteLine("Internal Error");
                    break;
            }
            Console.Error.WriteLine("USAGE: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] [--ndp] {-n num}");
            Environment.Exit(error_code);
        }
    }
}