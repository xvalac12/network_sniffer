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
            foreach(ICaptureDevice network_interface in network_interfaces)
            {
                Console.WriteLine(network_interface.Name);
            }
            Console.WriteLine("");









        }
    }
}
