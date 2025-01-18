package bmstu.kibamba;

import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public class SecureClusterNode {
    private final String nodeId;
    private final InetAddress clusterAddress;
    private final int port;
    private final DatagramSocket socket;
    private final String role;
    private final KeyPair keyPair; // For authentication
    private final Map<String, PublicKey> trustedNodes = new ConcurrentHashMap<>(); // Authorized node public keys

    public SecureClusterNode(String nodeId, int port, String clusterIp, String role) throws Exception {
        this.nodeId = nodeId;
        this.port = port;
        this.role = role;
        this.clusterAddress = InetAddress.getByName(clusterIp);
        this.socket = new DatagramSocket(port);
        this.keyPair = generateKeyPair();

       // Add trusted nodes (mock example)
        assert keyPair != null;
        trustedNodes.put("Node-1", keyPair.getPublic());
        trustedNodes.put("Node-2", keyPair.getPublic());
    }

    public void start() {
        System.out.println("Secure Node " + nodeId + " started on port " + port + " cluster address "+clusterAddress);

        Executors.newSingleThreadExecutor().execute(this::listenForPackets);
    }

    private void listenForPackets() {
        byte[] buffer = new byte[2048];
        while (true) {
            try {
                DatagramPacket datagramPacket = new DatagramPacket(buffer, buffer.length);
                socket.receive(datagramPacket);

                ProtocolPacket receivedPacket = deserialize(datagramPacket.getData());
                if (verifyPacket(receivedPacket)) {
                    handlePacket(receivedPacket);
                } else {
                    System.out.println("Invalid packet signature from " + receivedPacket.senderId());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void handlePacket(ProtocolPacket packet) {
        System.out.println("Secure Node " + nodeId + " received valid packet: " + packet);
        if (isAuthorized(packet)) {
            System.out.println("Packet authorized: " + packet);
            // Perform task based on the packet type and role
        } else {
            System.out.println("Unauthorized action attempted by: " + packet.senderId());
        }
    }

    private boolean verifyPacket(ProtocolPacket packet) throws Exception {
        PublicKey senderKey = trustedNodes.get(packet.senderId());
        if (senderKey == null) return false;

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(senderKey);
        signature.update(packetToBytes(packet));
        return signature.verify(packet.signature());
    }

    private boolean isAuthorized(ProtocolPacket packet) {
        // Example RBAC: Only "Coordinator" can send TASK packets
        return !packet.messageType().equals("TASK") || packet.role().equals("Coordinator");
    }

    private ProtocolPacket createPacket(
            String messageType,
            String targetId,
            int priority,
            String payload)
            throws Exception {
        byte[] signature = signPacket(messageType, targetId, priority, payload);
        return new ProtocolPacket(messageType, nodeId, targetId, priority, payload, role, signature);
    }

    private byte[] signPacket(String messageType, String targetId, int priority, String payload) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(packetToBytes(new ProtocolPacket(messageType, nodeId, targetId, priority, payload,
                role, null)));
        return signature.sign();
    }

    private byte[] packetToBytes(ProtocolPacket packet) throws IOException {
        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(arrayOutputStream);
        objectOutputStream.writeObject(packet);
        return arrayOutputStream.toByteArray();
    }

    private ProtocolPacket deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream arrayInputStream = new ByteArrayInputStream(data);
        ObjectInputStream objectInputStream = new ObjectInputStream(arrayInputStream);
        return (ProtocolPacket) objectInputStream.readObject();
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    public void sendTestPackets() throws Exception {
        ProtocolPacket taskPacket = createPacket("TASK", "Node-2", 1, "Process data chunk A");
        sendPacket(taskPacket, clusterAddress, 5002);

        ProtocolPacket heartbeatPacket = createPacket("HEARTBEAT", "BROADCAST", 10, "Node-1 is alive");
        for (int port : Arrays.asList(5002, 5003, 5004)) {
            sendPacket(heartbeatPacket, clusterAddress, port);
        }
    }

    private void sendPacket(ProtocolPacket packet, InetAddress targetAddress, int targetPort) throws IOException {
        // Serialize the packet into bytes
        byte[] data = packetToBytes(packet);

        // Create a DatagramPacket for sending
        DatagramPacket datagramPacket = new DatagramPacket(data, data.length, targetAddress, targetPort);

        // Send the packet through the socket
        socket.send(datagramPacket);

        System.out.println("Packet sent to " + targetAddress + ":" + targetPort + " | Packet: " + packet);
    }

}
