package bmstu.kibamba.bmstu.kibamba;

public class Demo {
    // Утилита для вывода байтов в hex
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
    public static void main(String[] args) {
        // Создание пакета
        byte version = 1;
        byte messageType = 1;
        short messageId = 123;
        byte[] payload = "Hello".getBytes();

        Packet packet = new Packet(version, messageType, messageId, payload);
        System.out.println("Packet created.");

        // Сериализация
        byte[] serializedPacket = packet.toBytes();
        System.out.println("Serialized Packet: " + bytesToHex(serializedPacket));

        // Десериализация
        Packet deserializedPacket = Packet.fromBytes(serializedPacket);
        System.out.println("Deserialized Packet:");
        System.out.println("Version: " + deserializedPacket.getVersion());
        System.out.println("Message Type: " + deserializedPacket.getMessageType());
        System.out.println("Message ID: " + deserializedPacket.getMessageId());
        System.out.println("Payload: " + new String(deserializedPacket.getPayload()));
    }

}
