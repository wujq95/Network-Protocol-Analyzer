package network.graph;

import java.awt.Font;
import java.text.DecimalFormat;
import java.text.NumberFormat;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;
import org.jfree.chart.plot.PiePlot;
import org.jfree.data.general.DefaultPieDataset;

public class PieChart {
	ChartPanel frame1;

	public PieChart() {
		DefaultPieDataset data = getDataSet();
		JFreeChart chart = ChartFactory.createPieChart3D("Network Protocols Pie Chart", data, true, false, false);
		// 设置百分比
		PiePlot pieplot = (PiePlot) chart.getPlot();
		DecimalFormat df = new DecimalFormat("0.00%");
		NumberFormat nf = NumberFormat.getNumberInstance();
		StandardPieSectionLabelGenerator sp1 = new StandardPieSectionLabelGenerator("{0}  {2}", nf, df);
		pieplot.setLabelGenerator(sp1);

		pieplot.setNoDataMessage("NO DATA");
		pieplot.setCircular(false);
		pieplot.setLabelGap(0.02D);
		pieplot.setIgnoreNullValues(true);
		pieplot.setIgnoreZeroValues(true);
		frame1 = new ChartPanel(chart, true);
		chart.getTitle().setFont(new Font("Times New Roman", Font.BOLD, 20));
		PiePlot piePlot = (PiePlot) chart.getPlot();
		piePlot.setLabelFont(new Font("Times New Roman", Font.BOLD, 10));
		chart.getLegend().setItemFont(new Font("Black", Font.BOLD, 10));
	}

	private static DefaultPieDataset getDataSet() {
		DefaultPieDataset dataset = new DefaultPieDataset();
		dataset.setValue("ARP", GraphNumber.arpNUM);
		dataset.setValue("TCP", GraphNumber.tcpNUM);
		dataset.setValue("UDP", GraphNumber.udpNUM);
		dataset.setValue("ICMP", GraphNumber.icmpNUM);
		dataset.setValue("Other", GraphNumber.otherNUM);
		return dataset;
	}

	public ChartPanel getChartPanel() {
		return frame1;
	}
}
