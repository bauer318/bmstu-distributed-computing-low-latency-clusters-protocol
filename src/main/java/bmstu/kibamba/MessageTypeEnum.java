package bmstu.kibamba;

public enum MessageTypeEnum {
    TRUST_REQUEST((byte)0),
    TRUST_RESPONSE((byte)1),
    TRUST_RQ_ACK((byte)2),
    TRUST_RP_ACK((byte)3),
    TRUST_CON((byte)4),
    TASK((byte)5),
    RESPONSE((byte)6),
    HEARTBEAT_REQUEST((byte)7),
    HEARTBEAT_RESPONSE((byte)8),

    STATE_REQUEST((byte)9),
    STATE_RESPONSE((byte)10);
    
    MessageTypeEnum(byte messageType){
        this.messageType = messageType;
    }

    private final byte messageType;

    public byte getMessageType(){
        return messageType;
    }

    public static MessageTypeEnum getByValue(byte value) {
        for (MessageTypeEnum type : MessageTypeEnum.values()) {
            if (type.messageType == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("No MessageTypeEnum found for value: " + value);
    }
}
