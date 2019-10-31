package network.host;

import java.awt.BorderLayout;
import java.net.InetAddress;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

import javax.swing.JDialog;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

public class HostListDialog extends JDialog {
	HostList hostList = new HostList();
	Set<Host> hostSet = null;
	Iterator<Host> hostItr = null;
	Vector<Object> rows, columns;
	private JTable table;
	JPopupMenu popup;
	DefaultTableModel tabModel;

	public HostListDialog() {

		setTitle("Host List");

		setBounds(100, 100, 500, 250);
		setLocation(430, 170);

		rows = new Vector<Object>();
		columns = new Vector<Object>();

		columns.addElement("Host Name");
		columns.addElement("IP Adress");
		columns.addElement("MAC Adress");

		tabModel = new DefaultTableModel();
		tabModel.setDataVector(rows, columns);
		table = new JTable(tabModel);

		DefaultTableCellRenderer render = new DefaultTableCellRenderer();
		render.setHorizontalAlignment(SwingConstants.CENTER);
		table.getColumn("Host Name").setCellRenderer(render);
		table.getColumn("IP Adress").setCellRenderer(render);
		table.getColumn("MAC Adress").setCellRenderer(render);

		this.getContentPane().add(new JScrollPane(table), BorderLayout.CENTER);
		new Thread() {
			public void run() {
				try {
					hostList.searchHost();
				} catch (Exception e) {
					e.printStackTrace();
				}
				int index = 1;
				while (!hostList.getIpScanExector().isShutdown()) {
					index++;
					try {
						Thread.sleep(100);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
					rows.removeAllElements();

					hostSet = hostList.getHostSet();
					synchronized (hostSet) {
						hostItr = hostSet.iterator();
						while (hostItr.hasNext()) {
							Vector<Object> r = new Vector<Object>();
							Host host = hostItr.next();
							try {
								InetAddress intAdr = InetAddress.getByName(host.getIpAddress());
								host.setHardAdr(byteToHex(MacSearch.macSSearch(intAdr)));
							} catch (Exception e) {
								e.printStackTrace();
							}
							r.addElement(host.getHostName());
							r.addElement(host.getIpAddress());
							r.addElement(host.getHardAdr());
							rows.addElement(r);
							table.addNotify();
						}
						if (index >= 5) {
							hostList.getIpScanExector().shutdown();
						}
					}
				}
			}

		}.start();
	}

	private void pendMac() {
		int row = 0;
		Iterator<Host> itr = hostSet.iterator();
		while (itr == null)
			;
		while (itr.hasNext()) {
			Host host = (Host) itr.next();

			try {
				InetAddress intAdr = InetAddress.getByName(host.getIpAddress());
				host.setHardAdr(byteToHex(MacSearch.macSSearch(intAdr)));
			} catch (Exception e) {
				e.printStackTrace();
			}
			Vector<Object> newRow = new Vector<Object>();
			newRow.addElement(host.getHostName());
			newRow.addElement(host.getIpAddress());
			newRow.addElement(host.getHardAdr());
			rows.setElementAt(newRow, row);
			table.addNotify();
			row++;
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
}
