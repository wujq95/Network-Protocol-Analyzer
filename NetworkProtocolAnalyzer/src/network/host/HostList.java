package network.host;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class HostList {
	private Set<Host> hostSet = Collections.synchronizedSet(new HashSet<Host>());
	private int threadCount = 254;
	private ExecutorService ipScanExector = Executors.newFixedThreadPool(threadCount);

	public void searchHost() throws Exception {
		InetAddress localAdr = InetAddress.getLocalHost();
		String[] netAdrAry = localAdr.getHostAddress().split("\\.");
		StringBuffer netAdr = new StringBuffer();

		for (int j = 0; j < netAdrAry.length - 1; j++) {
			netAdr.append(netAdrAry[j] + ".");
		}
		for (int i = 1; i < 254; i++) {
			String ip = netAdr + String.valueOf(i);
			ipScanExector.execute(new ScanIpThread(ip, hostSet));
		}
	}

	class ScanIpThread extends Thread {

		private String ip;
		private Set<Host> hostSet;

		public ScanIpThread(String ip, Set<Host> hostSet) {
			super();
			this.ip = ip;
			this.hostSet = hostSet;
		}

		@Override
		public void run() {
			try {
				InetAddress inAdr = InetAddress.getByName(ip);
				String ipStr = inAdr.getHostAddress();
				String hostName = inAdr.getHostName();
				if (!hostName.equals(ipStr)) {
					Host host = new Host();
					host.setHostName(hostName);
					host.setIpAddress(ipStr);
					hostSet.add(host);
				} else {
					Host host = new Host();
					host.setHostName(hostName);
					host.setIpAddress(ipStr);
					hostSet.add(host);
				}
			} catch (UnknownHostException e) {
				e.printStackTrace();
			}
		}
	}

	public Set<Host> getHostSet() {
		return hostSet;
	}

	public void setHostSet(Set<Host> hostSet) {
		this.hostSet = hostSet;
	}

	public ExecutorService getIpScanExector() {
		return ipScanExector;
	}

	public void setIpScanExector(ExecutorService ipScanExector) {
		this.ipScanExector = ipScanExector;
	}

}
