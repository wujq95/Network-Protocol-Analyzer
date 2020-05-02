# Network Protocol Analyzer

## Introduction
This is a network protocol analyzer based on WinpCap and JPcap. A	 network protocol analyzer is an important tool for maintaining network security. It can capture the data packets in the network and decode the data packets according to the encapsulation rules of the data packets to obtain the information carried by the data packets. Network administrators can use network protocol analyzers to find and repair network problems, monitor traffic conditions, and maintain network security. 

## Configuration
Programming Language：Java

Operating System：Windows

Tools：WinPcap、JPcap

## WinPcap
WinPcap is a function library for the Windows system. It helps users access the underlying network layers. WinPcap is a free industry-standard tool. It allows applications to directly capture and transmit data packets in the network. Many network applications are developed based on WinPcap.

## JPcap
Java has good support for the network data transmission of the upper layer, but it does not provide enough effective help for processing network layer protocols and other protocols that are below the network layer. JPcap is an effective supplement to this. JPcap is in Java and uses WinPcap and raw sockets to operate and encode the underlying layer protocols. JPcap supports many different protocols, such as Ethernet protocol, IP protocol, and TCP protocol. The use of it is easy, which greatly simplifies the coding difficulty of capturing and analyzing data packets in the network.

## Software Functions
### Capture conditions setting
The software can set the capture conditions before the start of packets capture, users can set the network card used, the maximum length of the packet to capture, whether it is the promiscuous mode, and capture timeout condition.

### Data packets capture
The software can manually start and stop the data packet capture. During the capture process, the main information of the data packets can be displayed on the interface.

### Data packets analysis
he software can display data packets from the data link layer to the application layer, and show the information carried by protocols of different layers on the interface. The protocols that can be analyzed currently include Ethernet、IP、 ARP、 ICMP、 TCP、 UDP、DNS、 HTTP、 HTTPS、 FTP、 Telnet、 POP、 SMTP.

### Data packets save and open
The software can save the captured data packages locally and open locally saved data packets. After opening the locally saved data packets, the analysis and statistics of the data packets can still be performed.

### Data packet statistics
The software provides the bar chart, the pie chart, and the table to help users perform statistical analysis on types, numbers, and proportions of all data packets.

### Auxiliary information provision
The software can also provide users with host information and network card information. Users can obtain  the host name, IP address, and MAC address and other important information.

## Reference
[JPcap](http://jpcap.sourceforge.net/javadoc/index.html)
