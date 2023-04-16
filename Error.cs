using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Network_sniffer
{
    /// <summary>
    /// Class for handling errors
    /// </summary>
    public class Error
    {
        /// <summary>
        /// Method print error message, usage and exit program with error code
        /// </summary>
        /// <param name="error_code">Number which will be printed as error code</param>
        public static void print_error(int error_code)
        {
            switch(error_code)
            {
                case 1:
                    Console.Error.WriteLine("Wrong argument entered");
                    break;
                case 2:
                    Console.Error.WriteLine("Bad or no port number after -p");
                    break;
                case 3:
                    Console.Error.WriteLine("Entered port without using --tcp|-t or --udp|-u");
                    break;
                case 4:
                    Console.Error.WriteLine("Bad or no number after -n");
                    break;
                case 5:
                    Console.Error.WriteLine("Wrong or no interface name entered");
                    break;
                case 6:
                    Console.Error.WriteLine("Interface wasn't opened. Maybe you are not launching program with root permission?");
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