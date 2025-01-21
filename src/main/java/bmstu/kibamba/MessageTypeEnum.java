package bmstu.kibamba;

public enum MessageTypeEnum {
    TRUST_REQUEST((byte)0),
    TRUST_RESPONSE((byte)1),
    ACK((byte)2),
    TASK((byte)3),
    HEARTBEAT_REQUEST((byte)7),
    HEARTBEAT_RESPONSE((byte)8),
    RESPONSE((byte)4),
    STATE_REQUEST((byte)5),
    STATE_RESPONSE((byte)6);
    
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
