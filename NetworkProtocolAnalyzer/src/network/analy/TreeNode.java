package network.analy;

import java.util.LinkedHashSet;
import java.util.Set;

public class TreeNode {
	private String data;
	private Set<Object> children = new LinkedHashSet<Object>();;
	private boolean isLeaf;

	public TreeNode(String data, boolean isLeaf) {
		super();
		this.data = data;
		this.isLeaf = isLeaf;
	}

	public boolean isLeaf() {
		return isLeaf;
	}

	public void setLeaf(boolean isLeaf) {
		this.isLeaf = isLeaf;
	}

	public String getData() {
		return data;
	}

	public void setData(String data) {
		this.data = data;
	}

	public Set<Object> getChildren() {
		return children;
	}

	public void setChildren(Set<Object> children) {
		this.children = children;
	}

}
