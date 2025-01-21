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

    public static NodeRoleEnum getByValue(byte value) {
        for (NodeRoleEnum role : NodeRoleEnum.values()) {
            if (role.nodeRole == value) {
                return role;
            }
        }
        throw new IllegalArgumentException("No NodeRoleEnum found for value: " + value);
    }
}
