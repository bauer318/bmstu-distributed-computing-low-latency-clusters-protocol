package bmstu.kibamba;

import java.io.Serial;
import java.io.Serializable;

/**
 * @param messageType TASK, HEARTBEAT, RESPONSE, ACK
 * @param targetId    "BROADCAST" or specific node
 * @param priority    Lower value = higher priority
 * @param role        Coordinator, Worker, Monitor
 * @param signature   For authentication
 */
public record ProtocolPacket(MessageTypeEnum messageType, String senderId, String targetId, int priority, String payload,
                             NodeRoleEnum role, String signature) implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    @Override
    public String toString() {
        return "ProtocolPacket[Type=" + messageType + ", Sender=" + senderId + ", Target=" + targetId + ", Priority="
                + priority + ", Role=" + role + "]";
    }
}
