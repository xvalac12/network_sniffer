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

        static (string, string?, int, bool) argument_handling(string[] args)
        {
            string [] filter_arr = new string[args.Length - 2];
            int filter_cnt = 0;
            bool print_flag = true;
            string ndp = "icmp6[icmp6type] = icmp6-neighborsolicit or icmp6[icmp6type] = icmp6-routersolicit or icmp6[icmp6type] = icmp6-routeradvert or icmp6[icmp6type] = icmp6-neighboradvert or icmp6[icmp6type] = icmp6-redirect";
            string? name_of_interface = null;
            int? port = null;
            int num_of_packets = 1;

            for (var args_cnt = 0; args_cnt < args.Length; args_cnt++)
            {
                switch (args[args_cnt])
                {
                    case "-i":
                    case "--interface":
                        if (args.Length == 1)
                        {
                            print_flag = true;
                            break;
                        }
                        try
                        {
                            name_of_interface = args[++args_cnt];
                            print_flag = false;
                        }
                        catch
                        {
                            Error.print_error(5);
                        }
                        break;
                    case "-p":
                        try
                        {
                            port = int.Parse(args[++args_cnt]);
                        }
                        catch
                        {
                            Error.print_error(2);
                        }
                        if (port < 0 || port > 65535)
                        {
                            Error.print_error(2);
                        }
                        break;
                    case "-t":
                    case "--tcp":
                        filter_arr[filter_cnt] = "tcp";
                        filter_cnt++;
                        break;
                    case "-u":
                    case "--udp":
                        filter_arr[filter_cnt] = "udp";
                        filter_cnt++;
                        break;
                    case "--icmpv4":
                        filter_arr[filter_cnt] = "icmp";
                        filter_cnt++;
                        break;
                    case "--icmpv6":
                        filter_arr[filter_cnt] = "icmpv6";
                        filter_cnt++;
                        break;
                    case "--arp":
                        filter_arr[filter_cnt] = "arp";
                        filter_cnt++;
                        break;
                    case "--ndp":
                        filter_arr[filter_cnt] = ndp;
                        filter_cnt++;
                        break; 
                    case "--igmp":
                        filter_arr[filter_cnt] = "igmp";
                        filter_cnt++;
                        break; 
                    case "--mld":
                        filter_arr[filter_cnt] = "mld";
                        filter_cnt++;
                        break;                     
                    case "-n":
                        try
                        {
                            num_of_packets = int.Parse(args[++args_cnt]);
                        }
                        catch
                        {
                            Error.print_error(4);
                        }
                        
                        break;
                    default:
                        Error.print_error(1);
                        break;
                }
            }
            try
            {
                filter_arr = filter_arr.Where(x => !string.IsNullOrEmpty(x)).ToArray();
            }
            catch
            {
                Error.print_error(99);
            }
            
            if (port != null)
            {
                filter_arr = port_handling(filter_arr, port);
            }

            // Input between every element of filter or
            string filter = string.Join(" or ", filter_arr);

            return (filter, name_of_interface, num_of_packets, print_flag);
        }
        static string[] port_handling(string [] filter_arr, int? port)
        {
            var aux_flag = true;
            for (int cnt = 0; cnt < filter_arr.Length; cnt++)
            {
                if (filter_arr[cnt] == "udp")
                {
                    filter_arr[cnt]  = "(udp and port " + port +")";
                    aux_flag = false;
                }
                else if (filter_arr[cnt]  == "tcp")
                {
                    filter_arr[cnt]  = "(tcp and port " + port +")";
                    aux_flag = false;
                }   
            }
            if (aux_flag)
            {
                Error.print_error(3);
            } 
            return filter_arr;
        }

        static void Main(string[] args)
        {
            string protocol_filter;
            string? name_of_interface;
            int num_of_packets;
            bool print_flag;
            ILiveDevice? used_interface = null;
            CaptureDeviceList network_interfaces = CaptureDeviceList.Instance;
            (protocol_filter, name_of_interface, num_of_packets, print_flag) = argument_handling(args);

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
            int packet_counter = 0;

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

                    if (++packet_counter > num_of_packets)
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
