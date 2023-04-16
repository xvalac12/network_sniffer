using System;
using System.Net;
using System.Linq;
using System.Text;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

namespace Network_sniffer
{
    /// <summary>
    /// Main class of application
    /// </summary>
    class Sniffer
    {
        /// <summary>
        /// Function for handling command line arguments
        /// </summary>
        /// <param name="args"></param>
        /// <returns>Values for filtering and handling packets</returns>
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

        /// <summary>
        /// Funtion print name of all avaible interfaces and exit application.
        /// </summary>
        /// <param name="network_interfaces">List with info about all avaible interfaces</param>
        static void print_all_interfaces(CaptureDeviceList network_interfaces)
        {
                Console.WriteLine("");
                foreach(var network_interface in network_interfaces)
                {
                    Console.WriteLine(network_interface.Name);
                }
                Console.WriteLine("");
                Environment.Exit(0);
        }

        /// <summary>
        /// Function which will add port to udp and tcp protocol. 
        /// If none of these is present, call error calling.
        /// </summary>
        /// <param name="filter_arr">Array with protocols for filtering</param>
        /// <param name="port">Port which will be used for TCP or UDP packet cpaturing</param>
        /// <returns>String with filter for packet capturing</returns>
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

        /// <summary>
        /// Method will print hexdump of captured packet
        /// </summary>
        /// <param name="handledPacket">Data of packet for printing hex</param>
        static void print_hex(Packet handledPacket)
        {
            string[] packet_hexdump = handledPacket.PrintHex().Split('\n');
            for (int i = 3; i < packet_hexdump.Length-1; i++)
            {
                var hexdump_line = packet_hexdump[i].Substring(6);
        
                hexdump_line = hexdump_line.Remove(4, 1);
                hexdump_line = hexdump_line.Remove(28, 1);
                hexdump_line = hexdump_line.Remove(52, 1);
                hexdump_line = hexdump_line.Remove(53, 1);
                            
                Console.WriteLine("0x" + hexdump_line);    
            }
        }
        
        /// <summary>
        /// Method for extracting data from packet, for information about packet print.
        /// It counts number od handled packet as well 
        /// </summary>
        /// <param name="sender">Object</param>
        /// <param name="packet">Captured packet</param>
        /// <param name="packet_counter">Current captured packet</param>
        /// <param name="num_of_packets">Number of packets to be captured</param>
        /// <param name="used_interface">Info about sniffed interface</param>
        private static void packet_handling(object sender, PacketCapture packet, int packet_cnt, int num_of_packets, ILiveDevice used_interface)
        {
            var handled_packet = Packet.ParsePacket(packet.GetPacket().LinkLayerType, packet.GetPacket().Data);
            var eth_packet = handled_packet.Extract<PacketDotNet.EthernetPacket>();
            var ip_packet = handled_packet.Extract<PacketDotNet.IPPacket>();
            var tcpPacket = handled_packet.Extract<PacketDotNet.TcpPacket>();                
            var udpPacket = handled_packet.Extract<PacketDotNet.UdpPacket>();

            if (eth_packet != null)
            {
                var date = packet.Header.Timeval.Date;  
                var source_MAC = "src MAC: " + eth_packet.SourceHardwareAddress;
                var destination_MAC = "dst MAC: " + eth_packet.DestinationHardwareAddress;

                for (int cnt = 19; cnt >= 11; cnt = cnt - 2)
                {
                    source_MAC = source_MAC.Insert(cnt, ":");
                    destination_MAC = destination_MAC.Insert(cnt, ":");
                }

                Console.WriteLine($"timestamp: {date:yyyy-MM-dd'T'HH:mm:ss.fffzzz}");
                Console.WriteLine(source_MAC );
                Console.WriteLine(destination_MAC);
                Console.WriteLine("frame lenght: " + packet.Data.Length + " bytes");

                if (ip_packet != null)
                {   
                    Console.WriteLine("src IP: " + ip_packet.SourceAddress);
                    Console.WriteLine("dst IP: " + ip_packet.DestinationAddress);
                }

                if (tcpPacket != null || udpPacket != null)
                {
                    if (tcpPacket != null)
                    {
                        Console.WriteLine("src port: " + tcpPacket.SourcePort);
                        Console.WriteLine("dst port: " + tcpPacket.DestinationPort);
                    }
                    else
                    {
                        Console.WriteLine("src port: " + udpPacket.SourcePort);
                        Console.WriteLine("dst port: " + udpPacket.DestinationPort);       
                    }
                }   
                Console.WriteLine("");

                print_hex(handled_packet);
                Console.WriteLine("");
                if (++packet_cnt >= num_of_packets)
                {
                    used_interface.StopCapture();
                    used_interface.Close();
                    Environment.Exit(0);
                } 
            }
        }

        /// <summary>
        /// Main method of application.
        /// </summary>
        /// <param name="args">Command line arguments</param>
        static void Main(string[] args)
        {
            string protocol_filter;
            string? name_of_interface;
            int num_of_packets;
            bool print_flag;
            int packet_cnt = 0;
            ILiveDevice? used_interface = null;
            CaptureDeviceList network_interfaces = CaptureDeviceList.Instance;
            (protocol_filter, name_of_interface, num_of_packets, print_flag) = argument_handling(args);

            if (print_flag == true) print_all_interfaces(network_interfaces);
            

            foreach(var network_interface in network_interfaces)
            {
                if (network_interface.Name == name_of_interface)
                {
                    used_interface = network_interface;
                }
            }
            
            if (used_interface == null)
            {
                Error.print_error(5);
                Environment.Exit(5);
            }
            try
            {
                used_interface.Open(DeviceModes.Promiscuous);
            }
            catch
            {
                Error.print_error(6);
            }
            try
            {
                used_interface.Filter = protocol_filter;
            }
            catch
            {
                Error.print_error(99);
            }

            used_interface.OnPacketArrival += (sender, packet) =>
            { 
                packet_handling(sender, packet, packet_cnt, num_of_packets, used_interface);
            };

            Console.CancelKeyPress += delegate(object? sender, ConsoleCancelEventArgs e)
            {
                used_interface.StopCapture();
                used_interface.Close();
                Environment.Exit(0);
            };

            used_interface.StartCapture();
            while(true){}         
        }
    }
}
