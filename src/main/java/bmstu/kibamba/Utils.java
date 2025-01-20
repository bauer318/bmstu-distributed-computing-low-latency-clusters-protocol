package bmstu.kibamba;

import java.io.*;

public class Utils {
    public static byte[] serialize(Object obj) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(obj);
            return baos.toByteArray();
        }
    }

    public static ProtocolPacket deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try(ByteArrayInputStream arrayInputStream = new ByteArrayInputStream(data);
            ObjectInputStream objectInputStream = new ObjectInputStream(arrayInputStream)){
            return (ProtocolPacket) objectInputStream.readObject();
        }
    }

    public static ProtocolPacket createUnsignedPacket(
            MessageTypeEnum messageType,
            String targetId,
            int priority,
            String payload,
            String senderId,
            NodeRoleEnum senderRole)
             {
        return new ProtocolPacket(messageType, senderId, targetId, priority, payload,
                senderRole, null);
    }

    public static byte[] packetToBytes(ProtocolPacket packet) throws IOException {
        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(arrayOutputStream);
        objectOutputStream.writeObject(packet);
        return arrayOutputStream.toByteArray();
    }
}
