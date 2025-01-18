package bmstu.kibamba;

import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public class SecureClusterNode {
    private final String nodeId;
    private final InetAddress clusterAddress;
    private final int port;
    private final DatagramSocket socket;
    private final String role;
    // For authentication
    private final KeyPair keyPair;
    // Authorized node public keys
    private final Map<String, PublicKey> trustedNodes = new ConcurrentHashMap<>();

    private static final String KEY_MATERIAL = "DSA";

    public SecureClusterNode(String nodeId, int port, String clusterIp, String role) throws Exception {
        this.nodeId = nodeId;
        this.port = port;
        this.role = role;
        this.clusterAddress = InetAddress.getByName(clusterIp);
        this.socket = new DatagramSocket(port);
        this.keyPair = generateKeyPair();
    }

    public void start() {
        System.out.println("Secure Node " + nodeId + " started on port " + port + " cluster address " + clusterAddress);
        if(!this.role.equals("Coordinator")){
            try {
                doHandShakeWithCoordinatorNode();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        Executors.newSingleThreadExecutor().execute(this::listenForPackets);
    }

    private void doHandShakeWithCoordinatorNode() throws Exception {
        //Assume that all nodes are on unique cluster and
        //the Coordinator's node port is 5001
        sendTrustRequest(this.clusterAddress,5001);
    }
    private void listenForPackets() {
        byte[] buffer = new byte[2048];
        while (true) {
            try {
                DatagramPacket datagramPacket = new DatagramPacket(buffer, buffer.length);
                socket.receive(datagramPacket);

                ProtocolPacket receivedPacket = deserialize(datagramPacket.getData());
                if (receivedPacket.messageType().equals("TRUST_REQUEST")) {
                    handleTrustRequest(receivedPacket, datagramPacket.getAddress(), datagramPacket.getPort());
                }else if(receivedPacket.messageType().equals("TRUST_RESPONSE")){
                    handleTrustResponse(receivedPacket, datagramPacket.getAddress(), datagramPacket.getPort());
                }
                else if (verifyPacket(receivedPacket)) {
                    handlePacket(receivedPacket);
                } else {
                    System.out.println("Invalid packet signature from " + receivedPacket.senderId());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void handleTrustRequest(ProtocolPacket packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        System.out.println("Received trust request from: " + packet.senderId());

        // Extract the sender's public key from the payload
        byte[] encodedKey = packet.payload().getBytes();
        PublicKey senderKey = deserializePublicKey(encodedKey);

        // Add the sender's key to the trustedNodes map
        trustedNodes.put(packet.senderId(), senderKey);
        System.out.println("Added " + packet.senderId() + " to trusted nodes.");

        //Respond the sender with the public key
        sendTrustResponse(senderAddress, senderPort);
    }

    private void handleTrustResponse(ProtocolPacket packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        System.out.println("Received trust response from: " + packet.senderId());

        byte[] encodedKey = packet.payload().getBytes();
        PublicKey senderKey = deserializePublicKey(encodedKey);

        // Add the sender's key to the trustedNodes map
        trustedNodes.put(packet.senderId(), senderKey);
        System.out.println("Added " + packet.senderId() + " to trusted nodes.");

        // Send acknowledgment
        ProtocolPacket responsePacket = createPacket("TRUST_ACK", packet.senderId(),
                0, "Trust established");
        sendPacket(responsePacket, senderAddress, senderPort);
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
        if (senderKey == null) {
            return false;
        }

        Signature signature = Signature.getInstance(KEY_MATERIAL);
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
        Signature signature = Signature.getInstance(KEY_MATERIAL);
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
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_MATERIAL);
        keyGen.initialize(1024);
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

    private void sendPacket(ProtocolPacket packet, InetAddress targetAddress, int targetPort)
            throws IOException {
        // Serialize the packet into bytes
        byte[] data = packetToBytes(packet);

        // Create a DatagramPacket for sending
        DatagramPacket datagramPacket = new DatagramPacket(data, data.length, targetAddress, targetPort);

        // Send the packet through the socket
        socket.send(datagramPacket);

        System.out.println("Packet sent to " + targetAddress + ":" + targetPort + " | Packet: " + packet);
    }

    public void sendTrustRequest(InetAddress targetAddress, int targetPort) throws Exception {
        String serializedPublicKey = serializePublicKey(keyPair.getPublic());
        ProtocolPacket trustRequest = new ProtocolPacket(
                "TRUST_REQUEST",
                nodeId,
                "BROADCAST",
                1,
                serializedPublicKey, // Store the serialized key as payload
                role,
                signPacket("TRUST_REQUEST", "BROADCAST", 1, serializedPublicKey)
        );
        sendPacket(trustRequest, targetAddress, targetPort);
    }

    private void sendTrustResponse(InetAddress targetAddress, int targetPort) throws Exception {
        String serializedPublicKey = serializePublicKey(keyPair.getPublic());
        ProtocolPacket trustRequest = new ProtocolPacket(
                "TRUST_RESPONSE",
                nodeId,
                "BROADCAST",
                1,
                serializedPublicKey,
                role,
                signPacket("TRUST_REQUEST", "BROADCAST", 1, serializedPublicKey)
        );
        sendPacket(trustRequest, targetAddress, targetPort);
    }

    public static String serializePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey deserializePublicKey(byte[] encodedKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_MATERIAL);
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }


}
