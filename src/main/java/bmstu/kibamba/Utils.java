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

    public static String resolvePacketTask(String packetTask){
        String[] packetTaskSplit = packetTask.split(",");
        String result = "r_"+packetTaskSplit[0];
        int firstOperand = Integer.parseInt(packetTaskSplit[1]);
        int secondOperand = Integer.parseInt(packetTaskSplit[2]);
        String operation = packetTaskSplit[3];
        int resultInt = switch (operation) {
            case ("+") -> firstOperand + secondOperand;
            case ("-") -> firstOperand - secondOperand;
            default -> 0;
        };
        result += ","+resultInt;
        return result;
    }

    public static int getPortByNodeId(String nodeId){
        return 5000+Integer.parseInt(nodeId.substring(nodeId.length()-1));
    }

}
