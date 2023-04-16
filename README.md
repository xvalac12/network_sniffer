 # IPK Project 2: Network sniffer
## Description of the implementation
The application is implemented in the C# programming language with the **.NET 6.0** framework using libraries from the **base SDK** (NET SDK).  The compilation is done using a **Makefile** (*dotnet clean, build and publish*) and the `make` command (`make OS=win-x64` for windows). It run with `./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}`, where **interface** is interface to sniff, **port** is an integer indicating the port which we want to sniff (only with UDP and TCP protocols). It has been tested to run on Windows 11, Ubuntu 22.04 and NIX operating system. The client consists of 2 classes: `Sniffer`, `Error`. Note that this application requires root privileges to capture network traffic.

### Requirements
To use this application, you will need the following:

 - C# compiler with .NET 6.0 Framework
 - SharpPcap library
 - PacketDotNet library

## Sniffer class

The Sniffer class contains the main class of the application.
The `argument_handling()` method is responsible for parsing the command-line arguments and returning the necessary values for packet filtering and handling. The method returns a tuple containing the filter string, the name of the interface, the number of packets to capture, and a boolean flag indicating whether to print the list of available network interfaces.

The `print_all_interfaces()` method prints the name of all available network interfaces and exits the application.

The `port_handling()` method adds the specified port number to the UDP or TCP protocol filter, depending on which one is present. If none of them is present, the method raises an error.

Finally, the application captures packets using the `CaptureDevice` class from the `SharpPcap` library and analyzes them using the Packet class from the PacketDotNet library. After that, application initializes the network interface and starts capturing packets. For each captured packet, it prints the packet information, including source and destination MAC addresses, source and destination IP addresses, hexdump of packet.

## Error class
This class is responsible for handling errors that may occur during the execution of the application. Method `print_error()` takes an integer error code as its parameter and prints the appropriate error message to the standard error stream. After printing the error message, it also prints the usage information for the Network_sniffer program and exits the program with the specified error code.

|Error Code	| Error Message                                                                        |
|-----------|--------------------------------------------------------------------------------------|
| 1	      | Wrong argument entered                                                               |
| 2	      | Bad or no port number after -p                                                       |
| 3	      | Entered port without using --tcp                                                     |
| 4	      | Bad or no number after -n                                                            |
| 5	      | Wrong or no interface name entered                                                   |
| 6	      | Interface wasn't opened. Maybe you are not launching program with root permission?   |
| 7	      | You can't enter arguments more times                                                 |
| 99	      | Internal Error                                                                       |


## Structure of packets

### TCP packet structure
| Field | Length | Description |
|----|---|--|
| Source Port | 2 bytes | The port number on the sender's device |
| Destination Port | 2 bytes | The port number on the recipient's device |
| Sequence Number | 4 bytes | Used to keep track of the order of data packets sent between the sender and recipient
| Acknowledgment Number | 4 bytes | Used to acknowledge receipt of data packets by the recipient
| Data Offset | 4 bytes | Size of the TCP header
| Reserved | 6 bytes | These bits are reserved for future use
| Flags | 6 bytes | This field contains several flags that control the behavior
| Window Size | 2 bytes | The number of bytes the sender is willing to receive before it expects an ACK
| Checksum | 2 bytes | This is used to detect errors
| Urgent Pointer | 2 bytes | This is used to indicate the location of urgent data
| Options | variable | Additional TCP options

### UDP Packet
| Field | Length | Description |
|----|---|--|
| Source Port | 2 bytes | The port number on the sender's device |
| Destination Port | 2 bytes | The port number on the recipient's device |
| Length | 2 bytes | The length of the entire UDP packet
| Checksum | 2 bytes | This is used to detect errors

### ICMP Packet
| Field | Length | Description |
|----|---|--|
| Type | 1 byte | The port number on the sender's device
| Code | 1 byte | The port number on the recipient's device
| Checksum | 2 bytes |The length of the entire UDP packet

### ARP Packet
| Field  | Size | Description                                    |
|--------|-------------|------------------------------------------------|
| Hardware Type | 2 bytes | Specifies the type of NIC hardware being used |
| Protocol Type | 2 bytes | Specifies the type of protocol addresses in upper protocol|
| Hardware length | 1 byte | Specifies the length of the hardware address |
| Protocol length | 1 byte | Specifies the length of the protocol address |
| Operation | 2 bytes | Specifies the type of ARP packet, such as request or reply |
| Source HW Address | 6 bytes | Specifies the sender's hardware address |
| Source Prot. Address | 4 bytes| Specifies the sender's protocol address |
| Target HW Address | 6 bytes | Specifies the target's hardware address |
| Target Prot. Address | 4 bytes | Specifies the target's protocol address |

## Testing
Testing was performed on three operating systems: Windows 11 (win-x64), Nix OS and Ubuntu 22.04 (linux-x64). On the left is output of application, on the right is comparison with wireshark application.

### Ubuntu 22.04
![Ubuntu 22.04 arp](tests/arp_ubuntu.png)
![Ubuntu 22.04 icmpv4](tests/icmpv4_ubuntu.png)
![Ubuntu 22.04 icmpv6](tests/icmpv6_ubuntu.png)
![Ubuntu 22.04 tcp with port](tests/tcp_with_port_ubuntu.png)
![Ubuntu 22.04 tpc without port](tests/tcp_without_port_ubuntu.png)
![Ubuntu 22.04 udp](tests/udp_ubuntu.png)
![Ubuntu 22.04 igmp](tests/igmp_ubuntu.png)

### NIX
![NIX igmp](tests/igmp_nix.png)
![NIX icmpv6](tests/imcpv6_nix.png)
![NIX udp](tests/udp_nix.png)
![NIX tcp](tests/tcp_nix.png)
![NIX ndp](tests/ndp_nix.png)

## Bibliography

 - Contributors to Wikimedia projects. [Duplex (Telecommunications) - Wikipedia.](https://en.wikipedia.org/wiki/Duplex_(telecommunications)) _Wikipedia, the Free Encyclopedia_, Wikimedia Foundation, Inc., 25 June 2005,.
 - [TCP vs UDP: What’s the Difference?](https://www.javatpoint.com/tcp-vs-udp) - _Javatpoint_. Accessed 21 Mar. 2023.
 - [NESFIT/IPK-Projekty - IPK-Projekty - FIT - VUT Brno - Git.](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master) _FIT - VUT Brno - Git_ . Accessed 21 Mar. 2023.

http://www.cs.newpaltz.edu/~easwaran/CCN/Week13/ARP.pdf
