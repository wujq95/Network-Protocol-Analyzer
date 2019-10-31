package network.analy;

import java.awt.BorderLayout;
import java.awt.Frame;
import java.awt.HeadlessException;
import java.util.Iterator;
import java.util.Set;

import javax.swing.JDialog;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import jpcap.packet.Packet;

public class IPAnalyTreeDig extends JDialog {

	private static final long serialVersionUID = 1L;
	private Packet pduPackage;
	PackageAnalyse pkgAnaly;

	public IPAnalyTreeDig(Packet pduPackage, Frame paFrame) throws HeadlessException {
		super(paFrame);
		this.pduPackage = pduPackage;
		setSize(400, 600);
		setTitle("Detailed Analysis");
	}

	private JTree ipTree;
	DefaultTreeModel treeModel;

	public void vInit() {
		pkgAnaly = new PackageAnalyse(pduPackage);
		pkgAnaly.analy();
		Set treeNodeSet = pkgAnaly.getAnyResult();
		DefaultMutableTreeNode root;
		if (treeNodeSet.isEmpty())
			root = new DefaultMutableTreeNode("Analysis Failure");
		root = new DefaultMutableTreeNode("Ethernet Protocol");
		treeModel = new DefaultTreeModel(root);
		ipTree = new JTree(treeModel);
		buildTree(treeNodeSet, root);
		JScrollPane scrollPane = new JScrollPane(ipTree);
		this.getContentPane().add(scrollPane, BorderLayout.CENTER);
	}

	private void buildTree(Set dataSet, DefaultMutableTreeNode ppNode) {
		Iterator itr = dataSet.iterator();
		while (itr.hasNext()) {
			TreeNode treeNode = (TreeNode) itr.next();
			DefaultMutableTreeNode pnode = new DefaultMutableTreeNode(treeNode.getData());
			ppNode.add(pnode);
			if (!treeNode.isLeaf()) {
				buildTree(treeNode.getChildren(), pnode);
			}
		}
	}
}