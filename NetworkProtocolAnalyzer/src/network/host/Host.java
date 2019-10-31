package network.host;

public class Host {
	private String hostName;
	private String ipAddress;
	private String hardAdr;

	public String getHostName() {
		return hostName;
	}

	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	public String getIpAddress() {
		return ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	public String getHardAdr() {
		return hardAdr;
	}

	public void setHardAdr(String hardAdr) {
		this.hardAdr = hardAdr;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Host) {
			Host host = (Host) obj;
			if ((host.ipAddress.equals(ipAddress)) && (host.hostName.equals(hostName))
					&& (host.getHardAdr().equals(hardAdr))) {
				return true;
			}
		}
		return false;
	}
}