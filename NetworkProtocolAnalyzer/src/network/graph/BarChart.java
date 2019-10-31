package network.graph;

import java.awt.Font;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.CategoryAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;

public class BarChart {

	ChartPanel frame1;

	public BarChart() {
		CategoryDataset dataset = getDataSet();
		JFreeChart chart = ChartFactory.createBarChart("Network Protocols Bar Chart", 
				"Protocol Type", 
				"Number", 
				dataset, 
				PlotOrientation.VERTICAL, 
				true, 
				false, 
				false 
		);

		CategoryPlot plot = chart.getCategoryPlot();
		CategoryAxis domainAxis = plot.getDomainAxis(); 
		domainAxis.setLabelFont(new Font("Black", Font.BOLD, 14));
		domainAxis.setTickLabelFont(new Font("Times New Roman", Font.BOLD, 12)); 
		ValueAxis rangeAxis = plot.getRangeAxis();
		rangeAxis.setLabelFont(new Font("Black", Font.BOLD, 15));
		chart.getLegend().setItemFont(new Font("Black", Font.BOLD, 15));
		chart.getTitle().setFont(new Font("Times New Roman", Font.BOLD, 20));

		frame1 = new ChartPanel(chart, true);

	}

	public CategoryDataset getDataSet() {
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();
		dataset.addValue(GraphNumber.ipNUM, "IP", "IP");
		dataset.addValue(GraphNumber.arpNUM, "ARP", "ARP");
		dataset.addValue(GraphNumber.tcpNUM, "TCP", "TCP");
		dataset.addValue(GraphNumber.udpNUM, "UDP", "UDP");
		dataset.addValue(GraphNumber.icmpNUM, "ICMP", "ICMP");
		dataset.addValue(GraphNumber.otherNUM, "Other", "Other");
		return dataset;
	}

	public ChartPanel getChartPanel() {
		return frame1;
	}
}
