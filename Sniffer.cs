using System;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Network_sniffer
{
    class Sniffer
    {
        static void Main(string[] args)
        {
            CaptureDeviceList network_interfaces = CaptureDeviceList.Instance;

            Console.WriteLine("");
            foreach(var network_interface in network_interfaces)
            {
                Console.WriteLine(network_interface.Name);
            }
            Console.WriteLine("");

            var used_interface = network_interfaces[0];

            used_interface.OnPacketArrival += (sender, packet) =>
            {
                Console.WriteLine("timestamp:");
                Console.WriteLine("src MAC:");
                Console.WriteLine("dst MAC:");
                Console.WriteLine("frame lenght:");
                Console.WriteLine("src IP:");
                Console.WriteLine("dst IP:");
                Console.WriteLine("src port:");
                Console.WriteLine("dst port:");
            };

        }
    }
}
