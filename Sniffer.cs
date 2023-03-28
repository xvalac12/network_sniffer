using System;
using System.Net;
using System.Linq;
using System.Text;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

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

            int counter = 0;

            var used_interface = network_interfaces[0];
            used_interface.Open(DeviceModes.Promiscuous);

            used_interface.OnPacketArrival += (sender, packet) =>
            { 
                var handledPacket = Packet.ParsePacket(packet.GetPacket().LinkLayerType, packet.GetPacket().Data);

                var tcpPacket = handledPacket.Extract<PacketDotNet.UdpPacket>();
                if (tcpPacket != null)
                {
                    var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                    var date = packet.Header.Timeval.Date;

                    Console.WriteLine($"timestamp: {date:yyyy-MM-dd'T'HH:mm:ss.fffzzz}");
                    Console.WriteLine("src MAC: " + packet.Device.MacAddress);
                    Console.WriteLine("dst MAC: ");
                    Console.WriteLine("frame lenght: " + packet.Data.Length);
                    Console.WriteLine("src IP: " + ipPacket.SourceAddress);
                    Console.WriteLine("dst IP: " + ipPacket.DestinationAddress);
                    Console.WriteLine("src port: " + tcpPacket.SourcePort);
                    Console.WriteLine("dst port: " + tcpPacket.DestinationPort);
                    Console.WriteLine("");

                    counter++;
                    if (counter > 3)
                    {
                        used_interface.StopCapture();
                        used_interface.Close();
                        Environment.Exit(1);
                    }
                } 
                
            };

            Console.CancelKeyPress += delegate(object? sender, ConsoleCancelEventArgs e)  // https://learn.microsoft.com/en-us/dotnet/api/system.console.cancelkeypress?view=net-7.0
            {
                used_interface.StopCapture();
                used_interface.Close();
                Environment.Exit(0);
            };

            used_interface.StartCapture();
            while(true)
            {

            }
            
        }
    }
}
