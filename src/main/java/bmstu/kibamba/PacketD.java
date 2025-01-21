package bmstu.kibamba;

import java.io.Serial;
import java.io.Serializable;

public class PacketD implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private  byte messageType;
    private  byte priority;
    private  byte nodeRole;
    private  byte[] senderId;
    private  byte[] targetId;
    private  byte[] signature;
    private  byte[] payload;

    public PacketD(byte messageType,
                   byte priority,
                   byte nodeRole,
                   byte[] senderId,
                   byte[] targetId,
                   byte[] signature,
                   byte[] payload) {
        this.messageType = messageType;
        this.priority = priority;
        this.nodeRole = nodeRole;
        this.senderId = senderId;
        this.targetId = targetId;
        this.signature = signature;
        this.payload = payload;
    }

    public byte getMessageType() {
        return messageType;
    }

    public void setMessageType(byte messageType) {
        this.messageType = messageType;
    }

    public byte getPriority() {
        return priority;
    }

    public void setPriority(byte priority) {
        this.priority = priority;
    }

    public byte getNodeRole() {
        return nodeRole;
    }

    public void setNodeRole(byte nodeRole) {
        this.nodeRole = nodeRole;
    }

    public byte[] getSenderId() {
        return senderId;
    }

    public void setSenderId(byte[] senderId) {
        this.senderId = senderId;
    }

    public byte[] getTargetId() {
        return targetId;
    }

    public void setTargetId(byte[] targetId) {
        this.targetId = targetId;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public byte[] getPayload() {
        return payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    private String bytesToString(byte[] bytes){
        return new String(bytes);
    }

    @Override
    public String toString(){
        return "Packet[MessageType: "+messageType+" from "+bytesToString(senderId)+" to "+bytesToString(targetId)
                +",priority "+priority+"]";
    }

}
