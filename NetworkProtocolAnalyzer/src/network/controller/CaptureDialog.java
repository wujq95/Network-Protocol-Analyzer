package network.controller;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

@SuppressWarnings("serial")
public class CaptureDialog extends JDialog implements ActionListener {

	static JpcapCaptor jpcap = null;

	NetworkInterface[] devices;
	@SuppressWarnings("rawtypes")
	JComboBox adapterComboBox;
	JTextField filterField;
	@SuppressWarnings("rawtypes")
	JComboBox mode_Box;
	public String[] mode_Names = new String[] { "Promiscuous Mode                   ", "Standard Mode" };

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public CaptureDialog(JFrame parent) {

		super(parent, "Select the Network Card and Set the Parameters", true);

		setLocation(480, 200);

		devices = JpcapCaptor.getDeviceList();
		if (devices == null) {
			JOptionPane.showMessageDialog(parent, "No Network Card Found.");
			dispose();
			return;
		} else {
			String[] names = new String[devices.length];
			for (int i = 0; i < names.length; i++)
				names[i] = (devices[i].description == null ? devices[i].name : devices[i].description);
			adapterComboBox = new JComboBox<Object>(names);
		}
		JPanel adapterPane = new JPanel();
		adapterPane.add(adapterComboBox);
		adapterPane.setBorder(BorderFactory.createTitledBorder("Select Network Card"));
		adapterPane.setAlignmentX(Component.LEFT_ALIGNMENT);

		mode_Box = new JComboBox(mode_Names);
		mode_Box.setSelectedIndex(0);
		JPanel promiscPane = new JPanel();
		promiscPane.add(mode_Box);
		promiscPane.setBorder(BorderFactory.createTitledBorder("Select Capture Mode"));
		promiscPane.setAlignmentX(Component.LEFT_ALIGNMENT);

		filterField = new JTextField(20);
		JPanel filterPane = new JPanel();
		filterPane.add(new JLabel("Filter"));
		filterPane.add(filterField);
		filterPane.setBorder(BorderFactory.createTitledBorder("Capture Filter"));
		filterPane.setAlignmentX(Component.LEFT_ALIGNMENT);

		JPanel buttonPane = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JButton okButton = new JButton("OK");
		okButton.setActionCommand("OK");
		okButton.addActionListener(this);
		JButton cancelButton = new JButton("Cancel");
		cancelButton.setActionCommand("Cancel");
		cancelButton.addActionListener(this);
		buttonPane.add(okButton);
		buttonPane.add(cancelButton);
		buttonPane.setAlignmentX(Component.LEFT_ALIGNMENT);

		JPanel westPane = new JPanel();
		westPane.setLayout(new BoxLayout(westPane, BoxLayout.Y_AXIS));
		westPane.add(Box.createRigidArea(new Dimension(5, 5)));
		westPane.add(adapterPane);
		westPane.add(Box.createRigidArea(new Dimension(0, 2)));

		westPane.add(promiscPane);
		westPane.add(Box.createRigidArea(new Dimension(0, 2)));
		westPane.add(filterPane);
		westPane.add(Box.createRigidArea(new Dimension(0, 2)));
		westPane.add(buttonPane);
		westPane.add(Box.createRigidArea(new Dimension(0, 10)));

		getContentPane().setLayout(new BoxLayout(getContentPane(), BoxLayout.X_AXIS));
		getContentPane().setForeground(Color.WHITE);
		getContentPane().add(Box.createRigidArea(new Dimension(10, 10)));
		getContentPane().add(westPane);
		getContentPane().add(Box.createRigidArea(new Dimension(10, 10)));
		pack();
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		String mode_Item = (String) mode_Box.getSelectedItem();
		Boolean is_Mix = true;
		if (mode_Item.equals("Promiscuous Mode                   ")) {
			is_Mix = true;
		} else {
			is_Mix = false;
		}

		String cmd = e.getActionCommand();
		if (cmd.equals("OK")) {
			try {
				NetworkInterface[] net = JpcapCaptor.getDeviceList();
				jpcap = JpcapCaptor.openDevice(net[4], 1514, is_Mix, 20);
				// jpcap = JpcapCaptor.openDevice(net[adapterComboBox.getSelectedIndex()], 1514,
				// is_Mix, 20);
				if (filterField.getText() != null && filterField.getText().length() > 0) {
					jpcap.setFilter(filterField.getText(), true);
				}
			} catch (NumberFormatException evt) {
				JOptionPane.showMessageDialog(null, "Length must be positive");
			} catch (java.io.IOException evt) {
				JOptionPane.showMessageDialog(null, "syntax error");
				System.out.println(e.toString());
				jpcap = null;
			} finally {
				dispose();
			}
		} else if (cmd.equals("Cancel")) {
			dispose();
		}
	}

	public static JpcapCaptor getJpcap(JFrame parent) {
		new CaptureDialog(parent).setVisible(true);
		return jpcap;
	}
}
