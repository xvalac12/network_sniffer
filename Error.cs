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
                case 99:
                    Console.Error.WriteLine("Internal Error");
                    break;
            }
            Environment.Exit(error_code);
        }
    }
}