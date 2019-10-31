package network.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import network.graph.BarChart;
import network.graph.GraphNumber;
import network.graph.PieChart;
import network.graph.TableChart;
import jpcap.packet.ARPPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

import network.controller.Capture;
import network.ui.MainFrame;
import network.analy.IPAnalyTreeDig;
import network.analy.ARPAnalyTreeDig;
import network.host.HostListDialog;
import network.host.NetCardList;;

public class MainFrame extends JFrame implements ActionListener {

	public int ipnum = 0;
	public int arpnum = 0;
	public int tcpnum = 0;
	public int udpnum = 0;
	public int icmpnum = 0;
	public int httpnum = 0;
	public int dnsnum = 0;
	public int ftpnum = 0;
	public int popnum = 0;
	public int smtpnum = 0;
	public int telnetnum = 0;
	public int httpsnum = 0;
	public int imapnum = 0;
	public int othernum = 0;
	public int selectRowNum;

	DefaultTableModel tabModel = new DefaultTableModel();
	Vector<Object> rows = new Vector<Object>();
	Vector<Object> columns = new Vector<Object>();
	Capture captor = new Capture();
	JTable tabledisplay = new JTable(tabModel);
	JScrollPane scrollPane;
	List<Object> pakgeList = new ArrayList<Object>();

	public MainFrame() {

		setBackground(Color.YELLOW);
		setTitle("Network Protocol Analyzer");

		this.getContentPane().setLayout(new BorderLayout());
		
		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);

		JMenu fileMenu = new JMenu("File");
		fileMenu.setIcon(new ImageIcon(MainFrame.class.getResource("/img/filemenu.jpg")));
		menuBar.add(fileMenu);

		JMenu captureMenu = new JMenu("Capture");
		captureMenu.setIcon(new ImageIcon(MainFrame.class.getResource("/img/filecapture.jpg")));
		menuBar.add(captureMenu);

		JMenu toolMenu = new JMenu("Tool");
		toolMenu.setIcon(new ImageIcon(MainFrame.class.getResource("/img/tool.jpg")));
		menuBar.add(toolMenu);

		JMenu graphMenu = new JMenu("Analysis");
		graphMenu.setIcon(new ImageIcon(MainFrame.class.getResource("/img/analy.jpg")));
		menuBar.add(graphMenu);

		JPopupMenu popup = new JPopupMenu("Edit");

		JMenuItem fileOpen = new JMenuItem("Open");
		JMenuItem fileSave = new JMenuItem("Save");
		JMenuItem fileExit = new JMenuItem("Exit");
		JMenuItem startCapture = new JMenuItem("Start");
		JMenuItem stopCapture = new JMenuItem("Stop");
		JMenuItem hostList = new JMenuItem("Host");
		JMenuItem NetCardList = new JMenuItem("NetCard");
		JMenuItem japcapApi = new JMenuItem("JPCAP API");
		JMenuItem tableGraph = new JMenuItem("Table");
		JMenuItem barGraph = new JMenuItem("Bar Graph");
		JMenuItem pieGraph = new JMenuItem("Pie Graph");
		JMenuItem ayaly = new JMenuItem("Analyze");

		fileSave.setActionCommand("Save");
		fileSave.addActionListener(this);
		fileSave.setIcon(new ImageIcon(MainFrame.class.getResource("/img/save.jpg")));
		fileMenu.add(fileSave);

		fileOpen.setActionCommand("Open");
		fileOpen.addActionListener(this);
		fileOpen.setIcon(new ImageIcon(MainFrame.class.getResource("/img/open.jpg")));
		fileMenu.add(fileOpen);

		fileExit.setActionCommand("Exit");
		fileExit.addActionListener(this);
		fileExit.setIcon(new ImageIcon(MainFrame.class.getResource("/img/exit.png")));
		fileMenu.add(fileExit);

		startCapture.setActionCommand("Start");
		startCapture.addActionListener(this);
		startCapture.setIcon(new ImageIcon(MainFrame.class.getResource("/img/start.jpg")));
		captureMenu.add(startCapture);

		stopCapture.setActionCommand("Stop");
		stopCapture.addActionListener(this);
		stopCapture.setIcon(new ImageIcon(MainFrame.class.getResource("/img/stop.jpg")));
		captureMenu.add(stopCapture);

		hostList.setActionCommand("HostList");
		hostList.addActionListener(this);
		hostList.setIcon(new ImageIcon(MainFrame.class.getResource("/img/host.jpg")));
		toolMenu.add(hostList);

		NetCardList.setActionCommand("NetCardList");
		NetCardList.addActionListener(this);
		NetCardList.setIcon(new ImageIcon(MainFrame.class.getResource("/img/net.jpg")));
		toolMenu.add(NetCardList);

		japcapApi.addActionListener(this);
		japcapApi.setIcon(new ImageIcon(MainFrame.class.getResource("/img/jpcap.jpg")));
		toolMenu.add(japcapApi);

		tableGraph.setActionCommand("TableGraph");
		tableGraph.addActionListener(this);
		tableGraph.setIcon(new ImageIcon(MainFrame.class.getResource("/img/table.jpg")));
		graphMenu.add(tableGraph);

		barGraph.setActionCommand("BarGraph");
		barGraph.addActionListener(this);
		barGraph.setIcon(new ImageIcon(MainFrame.class.getResource("/img/bar.jpg")));
		graphMenu.add(barGraph);

		pieGraph.setActionCommand("PieGraph");
		pieGraph.addActionListener(this);
		pieGraph.setIcon(new ImageIcon(MainFrame.class.getResource("/img/pie.png")));
		graphMenu.add(pieGraph);

		ayaly.setActionCommand("analy");
		ayaly.addActionListener(this);
		popup.add(ayaly);

		columns.addElement("Packet Type");
		columns.addElement("Capture Time");
		columns.addElement("Source Address");
		columns.addElement("Destination Address");
		columns.addElement("Header Length");
		columns.addElement("Data Length");
		columns.addElement("Header Content");
		columns.addElement("Data Content");

		tabModel.setDataVector(rows, columns);

		tabledisplay.setBackground(Color.white);

		tabledisplay.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent e) {
				if (e.isPopupTrigger())
					popup.show(tabledisplay, e.getX(), e.getY());
				int row = tabledisplay.rowAtPoint(e.getPoint());
				selectRowNum = row;
			}

			public void mouseReleased(MouseEvent e) {
				mousePressed(e);
			}
		});

		scrollPane = new JScrollPane(tabledisplay);

		this.getContentPane().add(scrollPane, BorderLayout.CENTER);
		this.getContentPane().setBackground(Color.WHITE);

		setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				int show = JOptionPane.showConfirmDialog(null, "Confirm closed?", "Confirm Exit System",
						JOptionPane.YES_NO_OPTION);
				if (show == JOptionPane.YES_OPTION) {
					System.exit(0);
				} else {
					this.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
				}
			}

			private void setDefaultCloseOperation(int doNothingOnClose) {

			}
		});

	}

	@Override
	public void actionPerformed(ActionEvent e) {
		String cmd = e.getActionCommand();
		if (cmd.equals("Start")) {
			captor.capturePacketsFromDevice();
			captor.setJCCFrame(this);
		} else if (cmd.equals("Stop")) {
			captor.stopCapture();
		} else if (cmd.equals("Exit")) {
			int show = JOptionPane.showConfirmDialog(null, "Confirm closed?", "Confirm Exit System",
					JOptionPane.YES_NO_OPTION);
			if (show == JOptionPane.YES_OPTION) {
				System.exit(0);
			} else {
				this.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
			}
		} else if (cmd.equals("analy")) {
			Packet pkg = (Packet) pakgeList.get(selectRowNum);
			if (pkg instanceof IPPacket) {
				IPAnalyTreeDig ipAnalyTree = new IPAnalyTreeDig(pkg, this);
				ipAnalyTree.vInit();
				ipAnalyTree.addWindowListener(new WindowAdapter() {
					public void windowClosing(WindowEvent e) {
					}
				});
				ipAnalyTree.setVisible(true);
			} else if (pkg instanceof ARPPacket) {
				ARPAnalyTreeDig arpAnalyTree = new ARPAnalyTreeDig(pkg, this);
				arpAnalyTree.vInit();
				arpAnalyTree.addWindowListener(new WindowAdapter() {
					public void windowClosing(WindowEvent e) {
					}
				});
				arpAnalyTree.setVisible(true);
			} else if (pkg instanceof ICMPPacket) {
				System.out.println("ICMP packet");
			}
		} else if (cmd.equals("HostList")) {
			HostListDialog listHostDig = new HostListDialog();
			listHostDig.setVisible(true);
		} else if (cmd.equals("NetCardList")) {
			NetCardList NetCardList = new NetCardList();
			NetCardList.setVisible(true);
		} else if (cmd.equals("Open")) {
			JFileChooser chooser = new JFileChooser();
			int returnType = chooser.showOpenDialog(null);
			if (returnType == JFileChooser.APPROVE_OPTION) {
				File file = chooser.getSelectedFile();
				String fileName = file.getAbsolutePath();
				captor.openFile(fileName);
			}
		} else if (cmd.equals("Save")) {
			JFileChooser chooser = new JFileChooser();
			int returnType = chooser.showSaveDialog(null);
			if (returnType == JFileChooser.APPROVE_OPTION) {
				File file = chooser.getSelectedFile();
				String fileName = file.getAbsolutePath();
				captor.saveFile(fileName);
			}
		} else if (cmd.equals("TableGraph")) {
			GraphNumber.setIpNum(ipnum);
			GraphNumber.setArpNum(arpnum);
			GraphNumber.setTcpNum(tcpnum);
			GraphNumber.setUdpNum(udpnum);
			GraphNumber.setIcmpNum(icmpnum);
			GraphNumber.setOtherNum(othernum);
			GraphNumber.setDnsNum(dnsnum);
			GraphNumber.setHttpNum(httpnum);
			GraphNumber.setPopNum(popnum);
			GraphNumber.setSmtpNum(smtpnum);
			GraphNumber.setFtpNum(ftpnum);
			GraphNumber.setTelnetNum(telnetnum);
			GraphNumber.setHttpsNum(httpsnum);
			GraphNumber.setImapNum(imapnum);
			TableChart TableChart = new TableChart();
			TableChart.setVisible(true);
		} else if (cmd.equals("BarGraph")) {
			JFrame framec = new JFrame("Bar Graph");
			framec.setLayout(new GridLayout(1, 1, 10, 10));
			GraphNumber.setIpNum(ipnum);
			GraphNumber.setArpNum(arpnum);
			GraphNumber.setTcpNum(tcpnum);
			GraphNumber.setUdpNum(udpnum);
			GraphNumber.setIcmpNum(icmpnum);
			GraphNumber.setOtherNum(othernum);
			GraphNumber.setDnsNum(dnsnum);
			GraphNumber.setHttpNum(httpnum);
			GraphNumber.setPopNum(popnum);
			GraphNumber.setSmtpNum(smtpnum);
			GraphNumber.setFtpNum(ftpnum);
			GraphNumber.setTelnetNum(telnetnum);
			GraphNumber.setHttpsNum(httpsnum);
			GraphNumber.setImapNum(imapnum);
			BarChart barChart = new BarChart();
			framec.add(barChart.getChartPanel());
			framec.setBounds(50, 50, 800, 600);
			framec.setVisible(true);
		} else if (cmd.equals("PieGraph")) {
			JFrame framec = new JFrame("Pie Graph");
			framec.setLayout(new GridLayout(1, 1, 10, 10));
			GraphNumber.setIpNum(ipnum);
			GraphNumber.setArpNum(arpnum);
			GraphNumber.setTcpNum(tcpnum);
			GraphNumber.setUdpNum(udpnum);
			GraphNumber.setIcmpNum(icmpnum);
			GraphNumber.setOtherNum(othernum);
			GraphNumber.setDnsNum(dnsnum);
			GraphNumber.setHttpNum(httpnum);
			GraphNumber.setPopNum(popnum);
			GraphNumber.setSmtpNum(smtpnum);
			GraphNumber.setFtpNum(ftpnum);
			GraphNumber.setTelnetNum(telnetnum);
			GraphNumber.setHttpsNum(httpsnum);
			GraphNumber.setImapNum(imapnum);
			PieChart pieChart = new PieChart();
			framec.add(pieChart.getChartPanel());
			framec.setBounds(50, 50, 800, 600);
			framec.setVisible(true);
		} else if (cmd.equals("JPCAP API")) {
			String cmdk = "rundll32 url.dll,FileProtocolHandler http://jpcap.sourceforge.net/javadoc/index.html";
			try {
				Runtime.getRuntime().exec(cmdk);
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}
	}

	public void dealPacket(Packet packet) {
		try {
			pakgeList.add(packet);
			Vector<Object> r = new Vector<Object>();
			String strtmp;
			Timestamp timestamp = new Timestamp((packet.sec * 1000) + (packet.usec / 1000));
			if (packet instanceof IPPacket) {
				ipnum = ipnum + 1;
				if (((IPPacket) packet).protocol == IPPacket.IPPROTO_TCP) {
					TCPPacket tcpPkg = (TCPPacket) packet;
					tcpnum = tcpnum + 1;
					if (tcpPkg.src_port == 80 || tcpPkg.dst_port == 80) {
						r.addElement("HTTP");
						httpnum = httpnum + 1;
					} else if (tcpPkg.src_port == 110 || tcpPkg.dst_port == 110) {
						r.addElement("POP");
						popnum = popnum + 1;
					} else if (tcpPkg.src_port == 25 || tcpPkg.dst_port == 25) {
						r.addElement("SMTP");
						smtpnum = smtpnum + 1;
					} else if (tcpPkg.src_port == 23 || tcpPkg.dst_port == 23) {
						r.addElement("Telnet");
						telnetnum = telnetnum + 1;
					} else if (tcpPkg.src_port == 21 || tcpPkg.dst_port == 21 || tcpPkg.src_port == 20
							|| tcpPkg.dst_port == 20) {
						r.addElement("FTP");
						ftpnum = ftpnum + 1;
					} else if (tcpPkg.src_port == 443 || tcpPkg.dst_port == 443) {
						r.addElement("HTTPS");
						httpsnum = httpsnum + 1;
					} else if (tcpPkg.src_port == 993 || tcpPkg.dst_port == 993) {
						r.addElement("IMAP");
						imapnum = imapnum + 1;
					} else if (tcpPkg.src_port == 143 || tcpPkg.dst_port == 143) {
						r.addElement("IMAP");
						imapnum = imapnum + 1;
					} else {
						r.addElement("TCP");
					}
				} else if (((IPPacket) packet).protocol == IPPacket.IPPROTO_UDP) {
					udpnum = udpnum + 1;
					UDPPacket udpPkg = (UDPPacket) packet;
					if (udpPkg.src_port == 53 || udpPkg.dst_port == 53) {
						r.addElement("DNS");
						dnsnum = dnsnum + 1;
					} else if (udpPkg.src_port == 69 || udpPkg.dst_port == 69) {
						r.addElement("TFTP");
					} else {
						r.addElement("UDP");
					}
				} else if (((IPPacket) packet).protocol == IPPacket.IPPROTO_ICMP) {
					icmpnum = icmpnum + 1;
					r.addElement("ICMP");
				} else {
					r.addElement("IP");
					othernum = othernum + 1;
				}
				r.addElement(timestamp.toString());
				r.addElement(((IPPacket) packet).src_ip.toString());
				r.addElement(((IPPacket) packet).dst_ip.toString());
				r.addElement(packet.header.length);
				r.addElement(packet.data.length);
				r.addElement(byteToHex(packet.header));
				r.addElement(byteToHex(packet.data));
			} else if (packet instanceof ARPPacket) {
				arpnum = arpnum + 1;
				r.addElement("ARP");
				r.addElement(timestamp.toString());
				r.addElement(((ARPPacket) packet).getSenderProtocolAddress().toString());
				r.addElement(((ARPPacket) packet).getTargetProtocolAddress().toString());
				r.addElement(packet.header.length);
				r.addElement("");
				r.addElement(byteToHex(packet.header));
				r.addElement(byteToHex(packet.data));
			}

			strtmp = "";
			for (int i = 0; i < packet.header.length; i++) {
				strtmp += Byte.toString(packet.header[i]);
			}
			r.addElement(strtmp);

			strtmp = "";
			for (int i = 0; i < packet.data.length; i++) {
				strtmp += Byte.toString(packet.data[i]);
			}
			r.addElement(strtmp);

			rows.addElement(r);
			tabledisplay.addNotify();
		} catch (Exception e) {
			System.out.println("mistake_Frame");
		}
	}

	String byteToHex(byte[] data) {
		String hexStr = "0123456789ABCDEF";
		StringBuffer strBuf = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			strBuf.append(hexStr.charAt((data[i] & 0xF0) >> 4));
			strBuf.append(hexStr.charAt((data[i] & 0x0F)));
		}
		return strBuf.toString();
	}

}
