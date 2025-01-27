package bmstu.kibamba;

import java.io.Serial;
import java.io.Serializable;

public record Packet(byte messageType,
                     byte priority,
                     byte nodeRole,
                     byte[] senderId,
                     byte[] targetId,
                     byte[] signature,
                     byte[] payload) implements Serializable {
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

}
