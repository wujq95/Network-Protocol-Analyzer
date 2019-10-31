package network.host;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

import javax.swing.JDialog;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class NetCardList extends JDialog {
	public NetworkInterface[] devices;
	public NetworkInterface device;
	public HostList hostList = new HostList();
	public Set<Host> hostSet = null;
	public Iterator<Host> hostItr = null;
	public Vector<Object> rows, columns;
	private JTable table;
	public JPopupMenu popup;
	public DefaultTableModel tabModel;
	public StringBuffer sb = new StringBuffer();

	public NetworkInterface[] getDevices() {
		devices = JpcapCaptor.getDeviceList();
		return devices;
	}

	public NetCardList() {
		setTitle("NetCard List");
		setBackground(Color.white);

		devices = JpcapCaptor.getDeviceList();

		setBounds(100, 100, 800, 300);
		setLocation(290, 170);

		rows = new Vector<Object>();
		columns = new Vector<Object>();

		columns.addElement("Device Interface");
		columns.addElement("Network Interface Name");
		columns.addElement("Network Interface Description");
		columns.addElement("DLL Name");
		columns.addElement("DLL Description");
		columns.addElement("Loopback Address");
		columns.addElement("MAC Address");

		tabModel = new DefaultTableModel();
		tabModel.setDataVector(rows, columns);
		table = new JTable(tabModel);

		DefaultTableCellRenderer render = new DefaultTableCellRenderer();
		render.setHorizontalAlignment(SwingConstants.CENTER);
		table.getColumn("Device Interface").setCellRenderer(render);
		table.getColumn("Network Interface Name").setCellRenderer(render);
		table.getColumn("Network Interface Description").setCellRenderer(render);
		table.getColumn("DLL Name").setCellRenderer(render);
		table.getColumn("DLL Description").setCellRenderer(render);
		table.getColumn("Loopback Address").setCellRenderer(render);
		table.getColumn("MAC Address").setCellRenderer(render);

		this.getContentPane().add(new JScrollPane(table), BorderLayout.CENTER);

		rows.removeAllElements();

		try {
			for (int i = 0; i < devices.length; i++) {
				sb.delete(0, sb.length());
				Vector<Object> r = new Vector<Object>();
				r.addElement("Device Interface" + (i + 1));
				r.addElement(devices[i].name);
				r.addElement(devices[i].description);
				r.addElement(devices[i].datalink_name);
				r.addElement(devices[i].datalink_description);
				r.addElement(devices[i].loopback);
				int flag = 0;
				for (byte b : devices[i].mac_address) {
					flag++;
					if (flag < devices[i].mac_address.length) {
						sb.append(Integer.toHexString(b & 0xff) + ":");
					} else {
						sb.append(Integer.toHexString(b & 0xff));
					}
				}
				String mac = new String();
				mac = sb.toString();
				r.addElement(mac);
				rows.addElement(r);
				table.addNotify();
			}
		} catch (Exception e) {
			System.out.println("NetCardListErr");
		}
	}
}
