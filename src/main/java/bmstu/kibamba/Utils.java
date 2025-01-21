package bmstu.kibamba;

import java.io.*;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;

public class Utils {
    public static byte[] serialize(Object obj) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(obj);
            return baos.toByteArray();
        }
    }

    public static Packet deserialize(byte[] data) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream arrayInputStream = new ByteArrayInputStream(data);
             ObjectInputStream objectInputStream = new ObjectInputStream(arrayInputStream)) {
            return (Packet) objectInputStream.readObject();
        }
    }

    public static Packet createUnsignedPacket(byte messageType,
                                              byte priority,
                                              byte senderRole,
                                              byte[] senderId,
                                              byte[] targetId,
                                              byte[] payload) {
        return new Packet(messageType, priority, senderRole, senderId, targetId, null, payload);
    }

    public static byte[] packetToBytes(Packet packet) throws IOException {
        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(arrayOutputStream);
        objectOutputStream.writeObject(packet);
        return arrayOutputStream.toByteArray();
    }


    public static String resolvePacketTask(String packetTask) {
        String[] packetTaskSplit = packetTask.split(",");
        String result = "r_" + packetTaskSplit[0];
        int firstOperand = Integer.parseInt(packetTaskSplit[1]);
        int secondOperand = Integer.parseInt(packetTaskSplit[2]);
        String operation = packetTaskSplit[3];
        int resultInt = switch (operation) {
            case ("+") -> firstOperand + secondOperand;
            case ("-") -> firstOperand - secondOperand;
            default -> 0;
        };
        result += "," + resultInt;
        return result;
    }

    public static String bytesToString(byte[] data) {
        return new String(data);
    }

    public static byte[] stringToBytes(String data) {
        return data.getBytes();
    }

    public static int getPortByNodeId(String nodeId) {
        return 5000 + Integer.parseInt(nodeId.substring(nodeId.length() - 1));
    }

    public static void simulateLongWorkByNode(String nodeId) {
        LocalTime beginAt = LocalTime.now();
        int taskTo = 1_000_000;
        int iter = 0;
        for (int i = 0; i < taskTo; i++) {
            var calculatedValue = Math.pow(i * Math.random(), 2);
            if (calculatedValue % 2 == 0) {
                i += 2;
            }
            iter++;
        }
        System.out.println("\t\t"+nodeId+" resolved the SIMULATED task with "+iter+" " +
                "iterations for " +beginAt.until(LocalTime.now(), ChronoUnit.SECONDS)+" seconds");
    }

}
