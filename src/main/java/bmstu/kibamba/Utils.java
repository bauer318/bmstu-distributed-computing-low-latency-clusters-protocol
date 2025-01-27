package bmstu.kibamba;

import java.io.*;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.util.Scanner;

public class Utils {
    public static byte[] serialize(Packet packet) throws IOException {
//        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
//             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
//            oos.writeObject(obj);
//            return baos.toByteArray();
//        }
        return packet.toBytes();
    }

    public static Packet deserialize(byte[] data) throws IOException, ClassNotFoundException {
//        try (ByteArrayInputStream arrayInputStream = new ByteArrayInputStream(data);
//             ObjectInputStream objectInputStream = new ObjectInputStream(arrayInputStream)) {
//            return (Packet) objectInputStream.readObject();
//        }
        return Packet.fromBytes(data);
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
//        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
//        ObjectOutputStream objectOutputStream = new ObjectOutputStream(arrayOutputStream);
//        objectOutputStream.writeObject(packet);
//        return arrayOutputStream.toByteArray();
        return packet.toBytes();
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

    public static String arrange(String incomingTask){
        return incomingTask.replaceAll("\\s","")
                .replaceAll("\\+"," + ")
                .replaceAll("-"," - ");
    }

    public static int changeNodePortIfPossible(NodeRoleEnum nodeRoleEnum, int port){
        return nodeRoleEnum == NodeRoleEnum.COORDINATOR ? 5001 : port;
    }

    public static void doTaskMenuIfCoordinatorNode(NodeRoleEnum nodeRoleEnum,
                                                   Scanner sc,
                                                   SecureClusterNode node){
        if (nodeRoleEnum == NodeRoleEnum.COORDINATOR) {
            boolean canStop = false;
            String task = "";
            while (!canStop) {
                System.out.println("0. Stop");
                System.out.println("1. Add task");
                System.out.println("2. Solve task");
                String choose = sc.nextLine();
                switch (choose) {
                    case "1" -> {
                        System.out.println("\tTask ");
                        task = sc.nextLine();
                    }
                    case "2" -> {
                        if (task != null && !task.isBlank()) {
                            System.out.println("Task "+arrange(task));
                            node.addTaskToResolve(arrange(task));
                        }
                    }
                    case "0" -> canStop = true;
                }
            }
        }
    }

    public static ClusterNodeParameter buildClusterNodeParameter(Scanner sc){
        String nodeId = null;
        int port = 0;
        String clusterIp = null;
        byte role = 2;
        int argsNumber = 0;
        String[] argsTitles = {"NodeId: ", "Port: ", "ClusterIP: ", "Role [0.Coordinator, 1.Worker]: "};
        System.out.println("Build the cluster node");
        while (argsNumber != 4) {
            System.out.print(argsTitles[argsNumber]);
            String input = sc.nextLine();
            if (!input.isBlank()) {
                switch (argsNumber) {
                    case 0 -> nodeId = input;
                    case 1 -> port = Integer.parseInt(input);
                    case 2 -> clusterIp = input;
                    case 3 -> role = Byte.parseByte(input);
                }
                argsNumber++;
            }
        }
        return new ClusterNodeParameter(nodeId,port,clusterIp,role);
    }

    public static boolean canBuildNode(String nodeId, int port, String clusterIp, byte role) {
        return !nodeId.isBlank() && port >= 5000 && !clusterIp.isBlank() && (role == 0 || role==1) ;
    }


}
