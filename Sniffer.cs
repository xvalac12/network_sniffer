using SharpPcap;
using PacketDotNet;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Numerics;


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
        /// <param name="args">Command line arguments from user</param>
        /// <returns>Values for filtering and handling packets</returns>
        static (string [], string?, int, bool) argument_handling(string[] args)
        {
            // check for duplicate in arguments
            if (args.Length != args.Distinct().Count())
            {
                Error.print_error(7);
            }

            // check for one argument entered
            if (args.Length == 1 && (args[0] != "-i" && args[0] != "--interface" ))
            {
                Error.print_error(1);
            } 

            string [] filter_arr = new string[10];
            int filter_cnt = 0;
            bool print_flag = true;
            // aux array in case of no protocol entered
            string [] aux_filter_arr = {"arp", "tcp", "udp", "icmpv6", "icmpv4", "igmp", "ndp", "mld"};
            string? name_of_interface = null;
            int? port = null;
            int num_of_packets = 1;

            // commandl line arguments parser
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
                        filter_arr[filter_cnt] = "icmpv4";
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
                        filter_arr[filter_cnt] = "ndp";
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
            //deleting blank elements from array
            try
            {
                filter_arr = filter_arr.Where(x => !string.IsNullOrEmpty(x)).ToArray();
            }
            catch
            {
                Error.print_error(99);
            }

            // check for duplicate command line arguments
            if (filter_arr.Length != filter_arr.Distinct().Count())
            {
                Error.print_error(7);
            }
            
            if (port != null)
            {
                filter_arr = port_handling(filter_arr, port);
            }

            // if no protocol is entered
            if (filter_arr.Length == 0)
            {
                return (aux_filter_arr, name_of_interface, num_of_packets, print_flag);
            }

            return (filter_arr, name_of_interface, num_of_packets, print_flag);
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
        /// <returns>String array with filter for packet capturing</returns>
        static string[] port_handling(string [] filter_arr, int? port)
        {
            var aux_flag = true;
            for (int filter_cnt = 0; filter_cnt < filter_arr.Length; filter_cnt++)
            {
                if (filter_arr[filter_cnt] == "udp")
                {
                    filter_arr[filter_cnt]  = "udp" + port;
                    aux_flag = false;
                }
                else if (filter_arr[filter_cnt]  == "tcp")
                {
                    filter_arr[filter_cnt]  = "tcp" + port;
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
            int line_num = 0;
            string[] packet_hexdump = handledPacket.PrintHex().Split('\n');
            for (int i = 3; i < packet_hexdump.Length-1; i++)
            {
                var hexdump_line = packet_hexdump[i].Substring(10);
                
                hexdump_line = hexdump_line.Remove(0, 1);
                hexdump_line = hexdump_line.Remove(24, 1);
                hexdump_line = hexdump_line.Remove(48, 1);
                hexdump_line = hexdump_line.Remove(49, 1);

                // changed line num to hex format
                var hex_line = line_num.ToString("x4");
                Console.WriteLine("0x" + hex_line + hexdump_line);
                line_num = line_num + 16;   
            }
        }
        
        /// <summary>
        /// Method used for filtering if captured packet is in the filter
        /// </summary>
        /// <param name="handled_packet">Captured packet</param>
        /// <param name="filter_arr">Protocol filter from user</param>
        /// <returns>True if captured packet is in filter, otherwise false</returns>
        static bool protocol_filter(Packet handled_packet, string [] filter_arr)
        {
            bool correct_catch = false;
            int? port = null;
            var ip_packet = handled_packet.Extract<PacketDotNet.IPPacket>();

            for (int filter_cnt = 0; filter_cnt < filter_arr.Length; filter_cnt++)
            {
                // Regex check if there is udp or tcp with port
                if (Regex.Match(filter_arr[filter_cnt], @"^(udp|tcp)(\d){1,5}$").Success)
                {
                    port = int.Parse(filter_arr[filter_cnt].Substring(3));
                    filter_arr[filter_cnt] = filter_arr[filter_cnt].Remove(3);
                }

                if(ip_packet == null && filter_arr [filter_cnt] == "arp")
                {
                    if(handled_packet.Extract<ArpPacket>() != null) correct_catch = true;
                }
                else if(ip_packet != null)
                {
                    switch (filter_arr [filter_cnt])
                    {
                        case "tcp":
                            var tcp_packet = ip_packet.Extract<TcpPacket>();
                            if(tcp_packet != null)
                            {
                                if (port == null)
                                {
                                    correct_catch = true;
                                }
                                else if (tcp_packet.SourcePort == port || tcp_packet.DestinationPort == port)
                                {
                                    correct_catch = true;
                                }
                            } 
                            break;
                        case "udp":
                            var udp_packet = ip_packet.Extract<TcpPacket>();
                            if(udp_packet != null)
                            {
                                if (port == null)
                                {
                                    correct_catch = true;
                                }
                                else if (udp_packet.SourcePort == port || udp_packet.DestinationPort == port)
                                {
                                    correct_catch = true;
                                }
                            } 
                            break;
                        case "icmpv4":
                            if(ip_packet.Extract<IcmpV4Packet>() != null) correct_catch = true;
                            break;
                        case "icmpv6":
                            if(ip_packet.Extract<IcmpV6Packet>() != null)
                            {
                                switch(ip_packet.Extract<IcmpV6Packet>().Type)
                                {
                                    case IcmpV6Type.EchoRequest:            //128
                                    case IcmpV6Type.EchoReply:              //129 
                                        correct_catch = true;
                                        break;
                                    default:
                                        break;
                                }
                            }
                            break;
                        case "mld":
                            if(ip_packet.Extract<IcmpV6Packet>() != null)
                            {
                                switch(ip_packet.Extract<IcmpV6Packet>().Type)
                                {
                                    case IcmpV6Type.MulticastListenerQuery:                 //130
                                    case IcmpV6Type.MulticastListenerReport:                //131
                                    case IcmpV6Type.MulticastListenerDone:                  //132
                                    case IcmpV6Type.Version2MulticastListenerReport:        //144
                                        correct_catch = true;
                                        break;
                                    default:
                                        break;
                                }
                            }
                            break;
                        case "ndp":
                            if(ip_packet.Extract<IcmpV6Packet>() != null)
                            {
                                if(ip_packet.Extract<IcmpV6Packet>() != null)
                                {
                                    switch(ip_packet.Extract<IcmpV6Packet>().Type)
                                    {
                                        case IcmpV6Type.RouterSolicitation:                     //133
                                        case IcmpV6Type.RouterAdvertisement:                    //134
                                        case IcmpV6Type.NeighborSolicitation:                   //135
                                        case IcmpV6Type.NeighborAdvertisement:                  //136
                                        case IcmpV6Type.RedirectMessage:                        //137
                                        case IcmpV6Type.CertificationPathSolicitationMessage:   //148
                                        case IcmpV6Type.CertificationPathAdvertisementMessage:  //149
                                            correct_catch = true;
                                            break;
                                        default:
                                            break;
                                    }
                                }
                            }
                            break;  
                        case "igmp":
                            if(ip_packet.Extract<IgmpPacket>() != null) {correct_catch = true;}
                            break;
                    }
                }
                if (correct_catch) return true;
            }
            return false;   
        }

        /// <summary>
        /// Method for extracting data from packet, for information about packet print.
        /// It counts number od handled packet as well 
        /// </summary>
        /// <param name="sender">Object</param>
        /// <param name="packet">Captured packet</param>
        /// <param name="used_interface">Info about sniffed interface</param>
        /// <returns>True if packet was handled, false if not</returns>
        static bool packet_handling(object sender, PacketCapture packet, string [] filter_arr, ILiveDevice used_interface)
        {
            var handled_packet = Packet.ParsePacket(packet.GetPacket().LinkLayerType, packet.GetPacket().Data);
            var eth_packet = handled_packet.Extract<PacketDotNet.EthernetPacket>();
            var ip_packet = handled_packet.Extract<PacketDotNet.IPPacket>();
            var tcp_packet = handled_packet.Extract<PacketDotNet.TcpPacket>();                
            var udp_packet = handled_packet.Extract<PacketDotNet.UdpPacket>();

            // if packet has no ethernet part or filter was not entered 
            if (eth_packet != null && protocol_filter(handled_packet, filter_arr))
            {
                var date = packet.Header.Timeval.Date;  
                var source_MAC = "src MAC: " + eth_packet.SourceHardwareAddress;
                var destination_MAC = "dst MAC: " + eth_packet.DestinationHardwareAddress;

                // inserting : to MAC address
                for (int cnt = 19; cnt >= 11; cnt = cnt - 2)
                {
                    source_MAC = source_MAC.Insert(cnt, ":");
                    destination_MAC = destination_MAC.Insert(cnt, ":");
                }

                Console.WriteLine($"timestamp: {date:yyyy-MM-dd'T'HH:mm:ss.fffzzz}");
                Console.WriteLine(source_MAC );
                Console.WriteLine(destination_MAC);
                Console.WriteLine("frame lenght: " + packet.Data.Length + " bytes");

                // if packet != ARP
                if (ip_packet != null)
                {   
                    Console.WriteLine("src IP: " + ip_packet.SourceAddress);
                    Console.WriteLine("dst IP: " + ip_packet.DestinationAddress);
                }

                if (tcp_packet != null || udp_packet != null)
                {
                    if (tcp_packet != null)
                    {
                        Console.WriteLine("src port: " + tcp_packet.SourcePort);
                        Console.WriteLine("dst port: " + tcp_packet.DestinationPort);
                    }
                    else
                    {
                        Console.WriteLine("src port: " + udp_packet.SourcePort);
                        Console.WriteLine("dst port: " + udp_packet.DestinationPort);       
                    }
                }   
                Console.WriteLine("");

                print_hex(handled_packet);
                Console.WriteLine("");
                return true;
            }
            return false;
        }

        /// <summary>
        /// Main method of application.
        /// </summary>
        /// <param name="args">Command line arguments</param>
        static void Main(string[] args)
        {
            string [] string_arr;
            string? name_of_interface;
            int num_of_packets;
            bool print_flag;
            int packet_cnt = 0;
            ILiveDevice? used_interface = null;
            CaptureDeviceList network_interfaces = CaptureDeviceList.Instance;
            (string_arr, name_of_interface, num_of_packets, print_flag) = argument_handling(args);

            if (print_flag == true) print_all_interfaces(network_interfaces);
            
            foreach (var network_interface in network_interfaces)
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

            used_interface.OnPacketArrival += (sender, packet) =>
            { 
                if (packet_handling(sender, packet, string_arr, used_interface))
                {
                    if (++packet_cnt >= num_of_packets)
                    {
                        used_interface.StopCapture();
                        used_interface.Close();
                        Environment.Exit(0);
                    } 
                }         
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
