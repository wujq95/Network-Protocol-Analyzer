package network.controller;

import network.controller.Main;
import network.ui.MainFrame;;

public class Main{
	
	public static void main(String args[]) {
		Main.openNewWindow();
	}

	public static MainFrame openNewWindow() {
		MainFrame frame = new MainFrame();
		frame.setSize(1000, 600);
		frame.setVisible(true);
		frame.setLocation(180, 70);
		return frame;
	}

}
