package network.analy;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.TreeSet;

import javax.swing.tree.DefaultMutableTreeNode;

import jpcap.packet.ARPPacket;
import jpcap.packet.DatalinkPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.Packet;
import jpcap.packet.IPPacket;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import jpcap.packet.IPv6Option;

public class PackageAnalyse {
	private Packet pduPackage;
	private Set<Object> anyResult = new LinkedHashSet<Object>();
	public static StringBuffer sb = new StringBuffer();

	public PackageAnalyse(Packet pduPackage) {
		super();
		this.pduPackage = pduPackage;
	}

	public void analy() {
		analyEpkg();
	}

	private void analyEpkg() {
		DatalinkPacket dlinkPkg = pduPackage.datalink;
		EthernetPacket epkg = (EthernetPacket) dlinkPkg;
		TreeNode srcMacNode = new TreeNode("Source Address:" + byteToHex(epkg.src_mac), true);
		TreeNode desMacNode = new TreeNode("Destination Address:" + byteToHex(epkg.dst_mac), true);
		TreeNode typeNode = new TreeNode("Protocol Type:" + epkg.frametype, true);
		anyResult.add(srcMacNode);
		anyResult.add(desMacNode);
		anyResult.add(typeNode);
		String protoType = "";
		if (pduPackage instanceof IPPacket) {
			protoType = "IP";
		} else if (pduPackage instanceof ARPPacket) {
			protoType = "ARP";
		}
		TreeNode dataNode = new TreeNode(protoType + " Protocol", false);
		anyResult.add(dataNode);
		analyNet(dataNode);
	}

	private void analyNet(TreeNode parentNode) {
		if (pduPackage instanceof IPPacket) {
			IPPacket ipPkg = (IPPacket) pduPackage;
			DatalinkPacket dlinkPkg = ipPkg.datalink;
			Set<Object> children = parentNode.getChildren();
			if (dlinkPkg instanceof EthernetPacket) {
				EthernetPacket epkg = (EthernetPacket) dlinkPkg;
			}
			if (ipPkg.version == 4) {
				int rf = (ipPkg.r_flag == true) ? 1 : 0;
				int df = (ipPkg.r_flag == true) ? 1 : 0;
				int tf = (ipPkg.r_flag == true) ? 1 : 0;
				TreeNode ipSrcNode = new TreeNode("Source Address:" + ipPkg.src_ip.getHostAddress(), true);
				TreeNode ipdesNode = new TreeNode("Destination Address:" + ipPkg.dst_ip.getHostAddress(), true);
				TreeNode ipVerNode = new TreeNode("Version: IPv" + ipPkg.version, true);
				TreeNode headerLenNode = new TreeNode("IHL:" + ipPkg.header.length, true);
				TreeNode TypeOfService = new TreeNode("DSCP:" + ipPkg.rsv_tos, true);
				TreeNode Length = new TreeNode("Total Length:" + ipPkg.length, true);
				TreeNode Identification = new TreeNode("Identification:" + ipPkg.ident, true);
				TreeNode Flags = new TreeNode("Flags:" + rf + df + tf, true);
				TreeNode Offset = new TreeNode("Fragment Offset:" + ipPkg.offset, true);
				TreeNode TimeLimit = new TreeNode("TTL:" + ipPkg.hop_limit, true);
				TreeNode ipProNode = new TreeNode("Protocol Type:" + ipPkg.protocol, true);
				TreeNode Option = new TreeNode("Options:" + ipPkg.option, true);
				TreeNode hederContNOde = new TreeNode("Header Content:" + byteToHex(ipPkg.header), true);
				TreeNode dataLenNode = new TreeNode("Data Length:" + ipPkg.data.length, true);
				TreeNode Data = new TreeNode("Data Content:" + byteToHex(ipPkg.data), true);
				String protoType = "";
				if (ipPkg.protocol == IPPacket.IPPROTO_TCP) {
					protoType = "TCP";
				} else if (ipPkg.protocol == IPPacket.IPPROTO_UDP) {
					protoType = "UDP";
				} else if (ipPkg.protocol == IPPacket.IPPROTO_ICMP) {
					protoType = "ICMP";
				} else if (ipPkg.protocol == 2) {
					protoType = "IGMP";
				} else if (ipPkg.protocol == 41) {
					protoType = "IPv6";
				} else {
					protoType = "Other Protocols";
				}
				TreeNode dataNode = new TreeNode(protoType + " Protocol", false);
				children.add(ipSrcNode);
				children.add(ipdesNode);
				children.add(ipVerNode);
				children.add(headerLenNode);
				children.add(hederContNOde);
				children.add(TypeOfService);
				children.add(Length);
				children.add(Identification);
				children.add(Flags);
				children.add(Offset);
				children.add(TimeLimit);
				children.add(ipProNode);
				children.add(dataLenNode);
				children.add(Data);
				if (ipPkg.t_flag) {
					TreeNode fragOffNoe = new TreeNode("Fragment Offset:" + ipPkg.offset, true);
				}
				children.add(dataNode);
				analyTrans(dataNode);
			} else if (ipPkg.version == 6) {
				byte[] ipv6byte = pduPackage.data;
				TreeNode ipSrcNode = new TreeNode("Source Port:" + ipPkg.src_ip.getHostAddress(), true);
				TreeNode ipdesNode = new TreeNode("Destination Port:" + ipPkg.dst_ip.getHostAddress(), true);
				TreeNode ipVerNode = new TreeNode("Version: IPv" + ipPkg.version, true);
				TreeNode headerLenNode = new TreeNode("Header Length:" + ipPkg.header.length, true);
				TreeNode hederContNOde = new TreeNode("Header Content:" + byteToHex(ipPkg.header), true);
				TreeNode Cls = new TreeNode("Traffic Class:" + ipPkg.priority, true);
				TreeNode FlowLabel = new TreeNode("Flow Label:" + ipPkg.flow_label, true);
				TreeNode PayLoadLength = new TreeNode("Payload Length:" + ipPkg.length, true);
				TreeNode ipProNode = new TreeNode("Protocol Type:" + ipPkg.protocol, true);
				TreeNode NexHeader = new TreeNode("Next Header:" + this.getIpv6NextHeader(ipPkg.protocol), true);
				TreeNode hopLimNode = new TreeNode("Hop Limit:" + ipPkg.hop_limit, true);
				TreeNode dataLenNode = new TreeNode("Data Length:" + ipPkg.data.length, true);
				TreeNode Data = new TreeNode("Data Content:" + byteToHex(ipPkg.data), true);
				String protoType = "";
				if (ipPkg.protocol == IPPacket.IPPROTO_TCP) {
					protoType = "TCP";
				} else if (ipPkg.protocol == IPPacket.IPPROTO_UDP) {
					protoType = "UDP";
				} else if (ipPkg.protocol == IPPacket.IPPROTO_ICMP) {
					protoType = "ICMP";
				} else if (ipPkg.protocol == 0) {
					protoType = "IPv6 hop by hop";
				} else if (ipPkg.protocol == 58) {
					protoType = "IPv6-ICMP";
				} else if (ipPkg.protocol == 59) {
					protoType = "IPv6-NoNxt";
				} else if (ipPkg.protocol == 60) {
					protoType = "IPv6-Opts";
				} else if (ipPkg.protocol == 41) {
					protoType = "IPv6";
				} else {
					protoType = "Other Protocols";
				}

				TreeNode Type0 = new TreeNode("Protocol:" + protoType, false);
				TreeNode dataNode = new TreeNode(protoType + " Protocol", false);
				children.add(ipSrcNode);
				children.add(ipdesNode);
				children.add(ipVerNode);
				children.add(headerLenNode);
				children.add(hederContNOde);
				children.add(Cls);
				children.add(FlowLabel);
				children.add(PayLoadLength);
				children.add(ipProNode);
				children.add(NexHeader);
				children.add(hopLimNode);
				children.add(dataLenNode);
				children.add(Data);
				if (ipPkg.t_flag) {
					TreeNode fragOffNoe = new TreeNode("Fragment Offset:" + ipPkg.offset, true);
				}
				children.add(dataNode);
				analyTrans(dataNode);
			}
		} else if (pduPackage instanceof ARPPacket) {
			ARPPacket arpPkg = (ARPPacket) pduPackage;
			Set<Object> childern = parentNode.getChildren();
			TreeNode arpHardtype = new TreeNode("Hardware Type:" + arpPkg.hardtype, true);
			TreeNode arpPrototype = new TreeNode("Protocol Type:" + arpPkg.prototype, true);
			TreeNode hlen = new TreeNode("Hardware Address Length:" + arpPkg.hlen, true);
			TreeNode plen = new TreeNode("Protocol Address Length:" + arpPkg.plen, true);
			TreeNode operation = new TreeNode("Operation:" + arpPkg.operation, true);
			TreeNode sender_hardaddr = new TreeNode("Sender Hardware Address:" + arpPkg.getSenderHardwareAddress(),
					true);
			TreeNode sender_protoaddr = new TreeNode("Sender Protocol Address:" + arpPkg.getSenderProtocolAddress(),
					true);
			TreeNode target_hardaddr = new TreeNode("Target Hardware Address:" + arpPkg.getTargetHardwareAddress(),
					true);
			TreeNode target_protoaddr = new TreeNode("Target Protocol Address:" + arpPkg.getTargetProtocolAddress(),
					true);
			childern.add(arpHardtype);
			childern.add(arpPrototype);
			childern.add(hlen);
			childern.add(plen);
			childern.add(operation);
			childern.add(sender_hardaddr);
			childern.add(sender_protoaddr);
			childern.add(target_hardaddr);
			childern.add(target_protoaddr);
		}
	}

	private void analyArp(TreeNode parentNode) {
		ARPPacket arpPkg = (ARPPacket) pduPackage;
		Set<Object> childern = parentNode.getChildren();
		TreeNode arpHardtype = new TreeNode("Hardware Type:" + arpPkg.hardtype, true);
		TreeNode arpPrototype = new TreeNode("Protocol Type:" + arpPkg.prototype, true);
		TreeNode hlen = new TreeNode("Hardware Address Length:" + arpPkg.hlen, true);
		TreeNode plen = new TreeNode("Protocol Address Length:" + arpPkg.plen, true);
		TreeNode operation = new TreeNode("Operation:" + arpPkg.operation, true);
		TreeNode sender_hardaddr = new TreeNode("Sender Hardware Address:" + arpPkg.getSenderHardwareAddress(), true);
		TreeNode sender_protoaddr = new TreeNode("Sender Protocol Address:" + arpPkg.getSenderProtocolAddress(), true);
		TreeNode target_hardaddr = new TreeNode("Target Hardware Address:" + arpPkg.getTargetHardwareAddress(), true);
		TreeNode target_protoaddr = new TreeNode("Target Protocol Address:" + arpPkg.getTargetProtocolAddress(), true);
		childern.add(arpHardtype);
		childern.add(arpPrototype);
		childern.add(hlen);
		childern.add(plen);
		childern.add(operation);
		childern.add(sender_hardaddr);
		childern.add(sender_protoaddr);
		childern.add(target_hardaddr);
		childern.add(target_protoaddr);
	}

	private void analyTrans(TreeNode parentNode) {
		IPPacket ipPkg = (IPPacket) pduPackage;
		Set<Object> childern = parentNode.getChildren();
		if (ipPkg.protocol == IPPacket.IPPROTO_TCP) {
			TCPPacket tcpPkg = (TCPPacket) ipPkg;
			int urg = (tcpPkg.urg == true) ? 1 : 0;
			int ack = (tcpPkg.ack == true) ? 1 : 0;
			int psh = (tcpPkg.psh == true) ? 1 : 0;
			int rst = (tcpPkg.rst == true) ? 1 : 0;
			int syn = (tcpPkg.syn == true) ? 1 : 0;
			int fin = (tcpPkg.fin == true) ? 1 : 0;

			TreeNode srcPortNode = new TreeNode("Source Port:" + tcpPkg.src_port, true);
			TreeNode desPortNode = new TreeNode("Destination Port:" + tcpPkg.dst_port, true);
			TreeNode squeNode = new TreeNode("Sequence Number:" + tcpPkg.sequence, true);
			TreeNode ackNumNode = new TreeNode("Acknowledgment Number:" + tcpPkg.ack_num, true);
			TreeNode LabeL = new TreeNode("Checksum :" + urg + ack + psh + rst + syn + fin, true);
			TreeNode winNode = new TreeNode("Window Size:" + tcpPkg.window, true);
			TreeNode urgentPtNode = new TreeNode("Urgent Pointer :" + tcpPkg.urgent_pointer, true);
			childern.add(srcPortNode);
			childern.add(desPortNode);
			childern.add(squeNode);
			childern.add(ackNumNode);
			childern.add(LabeL);
			childern.add(winNode);
			childern.add(urgentPtNode);
			String protoType = "";
			if (tcpPkg.src_port == 80 || tcpPkg.dst_port == 80) {
				protoType = "HTTP Protocol";
			} else if (tcpPkg.src_port == 110 || tcpPkg.dst_port == 110) {
				protoType = "POP Protocol";
			} else if (tcpPkg.src_port == 25 || tcpPkg.dst_port == 25) {
				protoType = "SMTP Protocol";
			} else if (tcpPkg.src_port == 23 || tcpPkg.dst_port == 23) {
				protoType = "Telnet Protocol";
			} else if (tcpPkg.src_port == 21 || tcpPkg.dst_port == 21 || tcpPkg.src_port == 20
					|| tcpPkg.dst_port == 20) {
				protoType = "FTP Protocol";
			} else if (tcpPkg.src_port == 443 || tcpPkg.dst_port == 443) {
				protoType = "HTTPS Protocol";
			} else if (tcpPkg.src_port == 993 || tcpPkg.dst_port == 993) {
				protoType = "IMAP Protocol";
			} else if (tcpPkg.src_port == 143 || tcpPkg.dst_port == 143) {
				protoType = "IMAP Protocol";
			} else {
				protoType = "Other Protocols";
			}
			TreeNode conData = new TreeNode(protoType, false);
			childern.add(conData);
			analyTcp(conData);
		} else if (ipPkg.protocol == IPPacket.IPPROTO_UDP) {
			UDPPacket udpPkg = (UDPPacket) ipPkg;
			TreeNode srcPortNode = new TreeNode("Source Port:" + udpPkg.src_port, true);
			TreeNode desPortNode = new TreeNode("Destination Port:" + udpPkg.dst_port, true);
			TreeNode DataLen = new TreeNode("UDP Length:" + +udpPkg.length, true);
			childern.add(srcPortNode);
			childern.add(desPortNode);
			childern.add(DataLen);
			String protoType = "";
			if (udpPkg.src_port == 53 || udpPkg.dst_port == 53) { // ∑÷ŒˆDNS–≠“È
				protoType = "DNS Protocol";
			} else if (udpPkg.src_port == 69 || udpPkg.dst_port == 69) {
				protoType = "TFTP Protocol";
			} else {
				protoType = "Other Protocols";
			}
			TreeNode conData = new TreeNode(protoType, false);
			childern.add(conData);
			analyUdp(conData);
		} else if (ipPkg.protocol == IPPacket.IPPROTO_ICMP) {
			ICMPPacket icmpPkg = (ICMPPacket) ipPkg;
			TreeNode type = new TreeNode("Type:" + icmpPkg.type, true);
			TreeNode code = new TreeNode("Code:" + icmpPkg.code, true);
			TreeNode checksum = new TreeNode("Checksum:" + icmpPkg.checksum, true);
			TreeNode id = new TreeNode("ID:" + icmpPkg.id, true);
			TreeNode seq = new TreeNode("Sequence Number:" + icmpPkg.seq, true);
			childern.add(type);
			childern.add(code);
			childern.add(checksum);
			childern.add(id);
			childern.add(seq);
		}
	}

	private void analyTcp(TreeNode parentNode) {
		IPPacket ipPkg = (IPPacket) pduPackage;
		Set<Object> childern = parentNode.getChildren();
		TCPPacket tcpPkg = (TCPPacket) ipPkg;
		if (tcpPkg.src_port == 80 || tcpPkg.dst_port == 80) {
			byte[] data = tcpPkg.data;
			if (data.length == 0) {
				TreeNode str = new TreeNode("No Content", true);
				childern.add(str);
			} else {
				if (tcpPkg.src_port == 80) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}

				if (tcpPkg.dst_port == 80) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
			}
		} else if (tcpPkg.src_port == 110 || tcpPkg.dst_port == 110) {
			byte[] data = tcpPkg.data;
			if (data.length == 0) {
				TreeNode str = new TreeNode("No Content", true);
				childern.add(str);
			} else {
				if (tcpPkg.src_port == 110) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
				if (tcpPkg.dst_port == 110) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
			}
		} else if (tcpPkg.src_port == 25 || tcpPkg.dst_port == 25) {
			byte[] data = tcpPkg.data;
			if (data.length == 0) {
				TreeNode str = new TreeNode("No Content", true);
				childern.add(str);
			} else {
				if (tcpPkg.src_port == 25) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
				if (tcpPkg.dst_port == 25) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
			}
		} else if (tcpPkg.src_port == 23 || tcpPkg.dst_port == 23) {
			byte[] data = tcpPkg.data;
			System.out.println(data.length);
			if (data.length == 0) {
				TreeNode str = new TreeNode("No content", true);
				childern.add(str);
			} else {
				if (tcpPkg.src_port == 23) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
				if (tcpPkg.dst_port == 23) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
			}
		} else if (tcpPkg.src_port == 143 || tcpPkg.dst_port == 143) {
			byte[] data = tcpPkg.data;
			if (data.length == 0) {
				TreeNode str = new TreeNode("No Content", true);
				childern.add(str);
			} else {
				if (tcpPkg.src_port == 143) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
				if (tcpPkg.dst_port == 143) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
			}
		} else if (tcpPkg.src_port == 993 || tcpPkg.dst_port == 993) {
			byte[] data = tcpPkg.data;
			if (data.length == 0) {
				TreeNode str = new TreeNode("No Content", true);
				childern.add(str);
			} else {
				if (tcpPkg.src_port == 993) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
				if (tcpPkg.dst_port == 993) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
			}
		} else if (tcpPkg.src_port == 21 || tcpPkg.dst_port == 21 || tcpPkg.src_port == 20 || tcpPkg.dst_port == 20) {
			byte[] data = tcpPkg.data;
			if (data.length == 0) {
				TreeNode str = new TreeNode("No Content", true);
				childern.add(str);
			} else {
				if (tcpPkg.src_port == 21 || tcpPkg.src_port == 20) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
				if (tcpPkg.dst_port == 21 || tcpPkg.dst_port == 20) {
					try {
						String str5 = new String(data, "ASCII");

						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
			}
		}
	}

	private void analyUdp(TreeNode parentNode) {
		IPPacket ipPkg = (IPPacket) pduPackage;
		Set<Object> childern = parentNode.getChildren();
		UDPPacket udpPkg = (UDPPacket) ipPkg;
		if (udpPkg.src_port == 53 || udpPkg.dst_port == 53) {
			byte[] data = udpPkg.data;
			if (data.length == 0) {
				TreeNode str = new TreeNode("No Content", true);
				childern.add(str);
			} else {
				if (udpPkg.src_port == 53) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
				if (udpPkg.dst_port == 53) {
					try {
						String str5 = new String(data, "ASCII");
						BufferedReader br = new BufferedReader(
								new InputStreamReader(new ByteArrayInputStream(str5.getBytes(Charset.forName("utf8"))),
										Charset.forName("utf8")));
						String line;
						StringBuffer strbuf = new StringBuffer();
						while ((line = br.readLine()) != null) {
							if (!line.trim().equals("")) {
								TreeNode str = new TreeNode(line, true);
								childern.add(str);
							}
						}
					} catch (Exception e) {
						// TODO: handle exception
					}
				}
			}
		}
	}

	private String byteToHex(byte[] data) {
		String hexStr = "0123456789ABCDEF";
		StringBuffer strBuf = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			strBuf.append(hexStr.charAt((data[i] & 0xF0) >> 4));
			strBuf.append(hexStr.charAt((data[i] & 0x0F)));
		}
		return strBuf.toString();
	}

	public Set<Object> getAnyResult() {
		return anyResult;
	}

	private DefaultMutableTreeNode getIpv6NextHeader(short nextheader) {
		DefaultMutableTreeNode nextHeaderNode;
		switch (nextheader) {
		case IPPacket.IPPROTO_TCP:
			nextHeaderNode = new DefaultMutableTreeNode("TCP");
			break;
		case IPPacket.IPPROTO_UDP:
			nextHeaderNode = new DefaultMutableTreeNode("UDP");
			break;
		case IPPacket.IPPROTO_HOPOPT:
			nextHeaderNode = new DefaultMutableTreeNode("IPv6 hop-by-hop");
			break;
		case IPPacket.IPPROTO_IPv6_Frag:
			nextHeaderNode = new DefaultMutableTreeNode("fragment header for IPv6");
			break;
		case IPPacket.IPPROTO_IPv6_ICMP:
			nextHeaderNode = new DefaultMutableTreeNode("IPv6 ICMP");
			break;
		case IPPacket.IPPROTO_IPv6_NoNxt:
			nextHeaderNode = new DefaultMutableTreeNode("no next header for IPv6");
			break;
		case IPPacket.IPPROTO_IPv6_Opts:
			nextHeaderNode = new DefaultMutableTreeNode("destination option for IPv6");
			break;
		case IPPacket.IPPROTO_IPv6_Route:
			nextHeaderNode = new DefaultMutableTreeNode("routing header for IPv6");
			break;
		default:
			nextHeaderNode = new DefaultMutableTreeNode("Unknown IPV6 Header");
		}
		return nextHeaderNode;
	}

}
