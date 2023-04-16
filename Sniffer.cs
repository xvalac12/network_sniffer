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
            int packet_counter = 0;
            string? name_of_interface = null;
            int? port = null;
            string? protocol_filter = null;
            string? port_filter = null;
            int packets = 1;

            for (var cnt = 0; cnt > args.Length; cnt++)
            {
                switch (args[cnt])
                {
                    case "-i":
                    case "--interface":
                        name_of_interface = args[++cnt];
                        break;
                    case "-p":
                        port = int.Parse(args[++cnt]);
                        break;
                    case "-t":
                    case "--tcp":
                        protocol_filter = protocol_filter + " and tcp";
                        break;
                    case "-u":
                    case "--udp":
                        protocol_filter = protocol_filter + " and udp";
                        break;
                    case "--icmpv4":
                        protocol_filter = protocol_filter + " and icmpv4";
                        break;
                    case "--icmpv6":
                        protocol_filter = protocol_filter + " and icmpv6";
                        break;
                    case "--arp":
                        protocol_filter = protocol_filter + " and arp";
                        break;
                    case "--ndp":
                        protocol_filter = protocol_filter + " and ndp";
                        break; 
                    case "--igmp":
                        protocol_filter = protocol_filter + " and igmp";
                        break; 
                    case "--mld":
                        protocol_filter = protocol_filter + " and mld";
                        break;                      
                    case "-n":
                        packets = int.Parse(args[cnt]);
                        break;
                    default:
                        Console.WriteLine($"Bad argument: {args[cnt]}");
                        Environment.Exit(1);
                        break;
                }
            }

            CaptureDeviceList network_interfaces = CaptureDeviceList.Instance;

            ILiveDevice? used_interface = null;
            Console.WriteLine("");
            foreach(var network_interface in network_interfaces)
            {
                Console.WriteLine(network_interface.Name);
                if (network_interface.Name == name_of_interface)
                {
                    used_interface = network_interface;
                }
            }
            Console.WriteLine("");

            if (used_interface == null)
            {
                Environment.Exit(2);
            }
                
            used_interface.Filter = protocol_filter;
            used_interface.Open(DeviceModes.Promiscuous);

            used_interface.OnPacketArrival += (sender, packet) =>
            { 
                var handledPacket = Packet.ParsePacket(packet.GetPacket().LinkLayerType, packet.GetPacket().Data);

                var tcpPacket = handledPacket.Extract<PacketDotNet.UdpPacket>();
                if (tcpPacket != null)
                {
                    var ip_packet = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                    var date = packet.Header.Timeval.Date;

                    Console.WriteLine($"timestamp: {date:yyyy-MM-dd'T'HH:mm:ss.fffzzz}");
                    Console.WriteLine("src MAC: " + packet.Device.MacAddress);
                    Console.WriteLine("dst MAC: ");
                    Console.WriteLine("frame lenght: " + packet.Data.Length + " bytes");
                    Console.WriteLine("src IP: " + ip_packet.SourceAddress);
                    Console.WriteLine("dst IP: " + ip_packet.DestinationAddress);
                    Console.WriteLine("src port: " + tcpPacket.SourcePort);
                    Console.WriteLine("dst port: " + tcpPacket.DestinationPort);
                    Console.WriteLine("");

                    if (++packet_counter > packets)
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
