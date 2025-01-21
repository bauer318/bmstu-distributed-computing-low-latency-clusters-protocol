package bmstu.kibamba;

public class ClusterNodeParameter {
    private String nodeId;
    private int port;
    private String clusterIp;
    private byte role;

    public ClusterNodeParameter(String nodeId, int port, String clusterIp, byte role) {
        this.nodeId = nodeId;
        this.port = port;
        this.clusterIp = clusterIp;
        this.role = role;
    }

    public String getNodeId() {
        return nodeId;
    }

    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getClusterIp() {
        return clusterIp;
    }

    public void setClusterIp(String clusterIp) {
        this.clusterIp = clusterIp;
    }

    public byte getRole() {
        return role;
    }

    public void setRole(byte role) {
        this.role = role;
    }
}
