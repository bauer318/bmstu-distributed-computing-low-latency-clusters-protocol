package bmstu.kibamba;

import java.io.Serial;
import java.io.Serializable;
import java.nio.ByteBuffer;

public class Packet implements Serializable {
    private final byte messageType;
    private final byte priority;
    private final byte nodeRole;
    private final short senderIdLength;
    private final byte[] senderId;
    private final short targetIdLength;
    private final byte[] targetId;
    private final byte[] signature;
    private short payloadLength;
    private byte[] payload;

    public Packet(byte messageType,
                  byte priority,
                  byte nodeRole,
                  byte[] senderId,
                  byte[] targetId,
                  byte[] signature,
                  byte[] payload) {
        this.messageType = messageType;
        this.priority = priority;
        this.nodeRole = nodeRole;
        this.senderIdLength = (short) senderId.length;
        this.senderId = senderId;
        this.targetIdLength = (short) targetId.length;
        this.targetId = targetId;
        this.signature = signature;
        if (payload != null) {
            this.payloadLength = (short) payload.length;
            this.payload = payload;
        }
    }

    @Serial
    private static final long serialVersionUID = 1L;

    private String bytesToString(byte[] bytes) {
        return new String(bytes);
    }

    @Override
    public String toString() {
        return "Packet[MessageType: " + messageType + " from " +
                bytesToString(senderId) + " to " + bytesToString(targetId)
                + ",priority " + priority + "]";
    }

    public byte[] toBytes() {
        int capacity = 9 + senderId.length
                + targetId.length;
        if (payload != null) {
            capacity += 2;
            capacity += payload.length;
        }

        if (signature != null) {
            capacity += signature.length;
        }

        ByteBuffer buffer = ByteBuffer.allocate(capacity);

        buffer.put(messageType);
        buffer.put(priority);
        buffer.put(nodeRole);
        buffer.putShort(senderIdLength);
        buffer.put(senderId);
        buffer.putShort(targetIdLength);
        buffer.put(targetId);
        if (signature != null) {
            buffer.put(signature);
        }

        if (payload != null) {
            buffer.putShort(payloadLength);
            buffer.put(payload);
        }


        return buffer.array();
    }

    public static Packet fromBytes(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        byte messageType = buffer.get();
        byte priority = buffer.get();
        byte nodeRole = buffer.get();
        short senderIdLength = buffer.getShort();
        byte[] senderId = new byte[senderIdLength];
        buffer.get(senderId);
        short targetIdLength = buffer.getShort();
        byte[] targetId = new byte[targetIdLength];
        buffer.get(targetId);
        short signatureLength = 46;
        byte[] signature = null;
        if (isSignedPacket(messageType)) {
            signature = new byte[signatureLength];
            buffer.get(signature);
        }

        byte[] payload = null;
        if (isContainsPayload(messageType)) {
            short payloadLength = buffer.getShort();
            payload = new byte[payloadLength];
            buffer.get(payload);
        }


        return new Packet(messageType,
                priority,
                nodeRole,
                senderId,
                targetId,
                signature,
                payload);

    }

    private static boolean isContainsPayload(byte messageType) {
        return messageType == MessageTypeEnum.TRUST_REQUEST.getMessageType()
                || messageType == MessageTypeEnum.TRUST_RESPONSE.getMessageType()
                || messageType == MessageTypeEnum.RESPONSE.getMessageType()
                || messageType == MessageTypeEnum.TASK.getMessageType()
                || messageType == MessageTypeEnum.STATE_RESPONSE.getMessageType()
                || messageType == MessageTypeEnum.TRUST_CON.getMessageType()
                || messageType == MessageTypeEnum.HEARTBEAT_REQUEST.getMessageType()
                || messageType == MessageTypeEnum.HEARTBEAT_RESPONSE.getMessageType();
    }

    private static boolean isSignedPacket(byte messageType) {
        return messageType != MessageTypeEnum.TRUST_RESPONSE.getMessageType()
                && messageType != MessageTypeEnum.TRUST_REQUEST.getMessageType()
                && messageType != MessageTypeEnum.TRUST_RP_ACK.getMessageType()
                && messageType != MessageTypeEnum.TRUST_RQ_ACK.getMessageType();
    }

    public byte getMessageType() {
        return messageType;
    }

    public byte getPriority() {
        return priority;
    }

    public byte getNodeRole() {
        return nodeRole;
    }

    public byte[] getSenderId() {
        return senderId;
    }

    public byte[] getTargetId() {
        return targetId;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getPayload() {
        return payload;
    }
}
