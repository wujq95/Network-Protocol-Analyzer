package network.host;

import java.net.InetAddress;

import jpcap.*;

public class MacSearch {
	public static byte[] macSSearch(InetAddress ip) throws java.io.IOException {
		NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		NetworkInterface device = null;

		loop: for (NetworkInterface d : devices) {
			device = d;
			break loop;
		}
		return device.mac_address;
	}
}
