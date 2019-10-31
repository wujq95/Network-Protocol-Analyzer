package network.graph;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.Vector;

import javax.swing.JDialog;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

public class TableChart extends JDialog {

	public Vector<Object> rows, columns;
	public DefaultTableModel tabModel;
	private JTable table;

	public TableChart() {
		setTitle("Statistical Table");

		setBounds(110, 150, 800, 150);
		setLocation(280, 200);
		getContentPane().setBackground(Color.BLUE);

		rows = new Vector<Object>();
		columns = new Vector<Object>();

		columns.addElement("IP");
		columns.addElement("ARP");
		columns.addElement("TCP");
		columns.addElement("UDP");
		columns.addElement("ICMP");
		columns.addElement("Other");
		columns.addElement("DNS");
		columns.addElement("HTTP");
		columns.addElement("POP");
		columns.addElement("SMTP");
		columns.addElement("FTP");
		columns.addElement("Telnet");
		columns.addElement("IMAP");
		columns.addElement("HTTPS");

		tabModel = new DefaultTableModel();
		tabModel.setDataVector(rows, columns);
		table = new JTable(tabModel);

		DefaultTableCellRenderer render = new DefaultTableCellRenderer();
		render.setHorizontalAlignment(SwingConstants.CENTER);

		table.getColumn("IP").setCellRenderer(render);
		table.getColumn("ARP").setCellRenderer(render);
		table.getColumn("TCP").setCellRenderer(render);
		table.getColumn("UDP").setCellRenderer(render);
		table.getColumn("ICMP").setCellRenderer(render);
		table.getColumn("Other").setCellRenderer(render);
		table.getColumn("DNS").setCellRenderer(render);
		table.getColumn("HTTP").setCellRenderer(render);
		table.getColumn("POP").setCellRenderer(render);
		table.getColumn("SMTP").setCellRenderer(render);
		table.getColumn("FTP").setCellRenderer(render);
		table.getColumn("Telnet").setCellRenderer(render);
		table.getColumn("IMAP").setCellRenderer(render);
		table.getColumn("HTTPS").setCellRenderer(render);

		JScrollPane scrollPane = new JScrollPane(table);
		this.getContentPane().add(scrollPane, BorderLayout.CENTER);

		rows.removeAllElements();

		try {
			Vector<Object> r = new Vector<Object>();
			r.addElement(GraphNumber.ipNUM);
			r.addElement(GraphNumber.arpNUM);
			r.addElement(GraphNumber.tcpNUM);
			r.addElement(GraphNumber.udpNUM);
			r.addElement(GraphNumber.icmpNUM);
			r.addElement(GraphNumber.otherNUM);
			r.addElement(GraphNumber.dnsNUM);
			r.addElement(GraphNumber.httpNUM);
			r.addElement(GraphNumber.popNUM);
			r.addElement(GraphNumber.smtpNUM);
			r.addElement(GraphNumber.ftpNUM);
			r.addElement(GraphNumber.telnetNUM);
			r.addElement(GraphNumber.imapNUM);
			r.addElement(GraphNumber.httpsNUM);
			rows.addElement(r);
			table.addNotify();

		} catch (Exception e) {
			System.out.println("Error");
		}
	}
}
