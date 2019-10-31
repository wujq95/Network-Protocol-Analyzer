package network.controller;

import network.controller.CaptureDialog;
import network.ui.MainFrame;
import network.ui.OpenFileFrame;

import java.io.IOException;
import java.util.LinkedList;

import javax.swing.JOptionPane;

import jpcap.*;
import jpcap.packet.Packet;

public class Capture {
	public JpcapCaptor jpcap = null;
	public MainFrame frame;
	public OpenFileFrame openFrame;
	public JpcapWriter writer;
	public LinkedList<Packet> packets = new LinkedList<Packet>();
	public JpcapCaptor jpcapcap;
	public Thread captureThread;

	public void setJCCFrame(MainFrame frame) {
		this.frame = frame;
	}

	public void setJCCFrame(OpenFileFrame openFrame) {
		this.openFrame = openFrame;
	}

	public void capturePacketsFromDevice() {
		if (jpcap != null)
			jpcap.close();
		jpcap = CaptureDialog.getJpcap(frame);

		if (jpcap != null) {
			startCaptureThread();
		}
	}

	private void startCaptureThread() {
		if (captureThread != null) {
			return;
		}
		
		captureThread = new Thread(new Runnable() {

			public void run() {
				jpcap.loopPacket(-1, handler);
			}
		});
		captureThread.setPriority(Thread.MIN_PRIORITY);
		captureThread.start();
	}

	protected PacketReceiver handler = new PacketReceiver() {
		public void receivePacket(Packet packet) {
			if (packet.len <= 68) {
				frame.dealPacket(packet);
				packets.add(packet);
			}
		}
	};

	class reader implements PacketReceiver {
		public void receivePacket(Packet packet) {
			frame.dealPacket(packet);
		}
	};

	public void stopCapture() {
		stopCaptureThread();
	}

	public void stopCaptureThread() {
		jpcap.breakLoop();
	}

	public void saveFile(String fileName) {
		if (jpcap == null) {
			JOptionPane.showMessageDialog(null, "NO-PACKETS!", "NO-PACKETS", JOptionPane.INFORMATION_MESSAGE);
		} else {
			try {
				writer = JpcapWriter.openDumpFile(jpcap, fileName);
				while (packets.size() != 0) {
					writer.writePacket(packets.removeFirst());
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	public void openFile(String fileName) {
		try {
			jpcap = JpcapCaptor.openFile(fileName);
			OpenFileFrame frameb = new OpenFileFrame();
			frameb.setSize(800, 400);
			frameb.setVisible(true);
			frameb.setLocation(300, 200);
			while (true) {
				Packet packet = jpcap.getPacket();
				if (packet == null || packet == Packet.EOF) {
					break;
				}
				frameb.dealPacket(packet);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (jpcap != null) {
				jpcap.close();
			}
		}
	}
}
