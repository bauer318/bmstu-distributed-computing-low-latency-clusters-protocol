package bmstu.kibamba;

public enum NodeRoleEnum {
    COORDINATOR((byte)0),
    WORKER((byte)1);
    private NodeRoleEnum(byte nodeRole){
        this.nodeRole =  nodeRole;
    }

    private final byte nodeRole;

    public byte  getNodeRole(){
        return nodeRole;
    }
}
