package bmstu.kibamba;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

import static bmstu.kibamba.Utils.*;

public class SecureClusterNode {
    private final String nodeId;
    private final InetAddress clusterAddress;
    private final int port;
    private final DatagramSocket socket;
    private final NodeRoleEnum role;
    // For authentication
    private final KeyPair keyPair;
    // Authorized node public keys
    private final Map<String, PublicKey> trustedNodes = new ConcurrentHashMap<>();

    private static final String KEY_MATERIAL = "DSA";

    public SecureClusterNode(String nodeId, int port, String clusterIp, NodeRoleEnum role) throws Exception {
        this.nodeId = nodeId;
        this.port = port;
        this.role = role;
        this.clusterAddress = InetAddress.getByName(clusterIp);
        this.socket = new DatagramSocket(port);
        this.keyPair = generateKeyPair();
    }

    public void start() {
        System.out.println("Secure Node " + nodeId + " started on port " + port + " cluster address " + clusterAddress);
        if(this.role!=NodeRoleEnum.COORDINATOR){
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
        //Buffer to receive incoming data
        byte[] buffer = new byte[4096];
        while (true) {
            try {
                DatagramPacket datagramPacket = new DatagramPacket(buffer, buffer.length);
                socket.receive(datagramPacket);

                ProtocolPacket receivedPacket = deserialize(datagramPacket.getData());
                if (receivedPacket.messageType()==MessageTypeEnum.TRUST_REQUEST) {
                    handleTrustRequest(receivedPacket, datagramPacket.getAddress(), datagramPacket.getPort());
                }else if(receivedPacket.messageType()==MessageTypeEnum.TRUST_RESPONSE){
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
        ProtocolPacket responsePacket =
                createUnsignedPacket(MessageTypeEnum.ACK, packet.senderId(), 0, "Trust established",
                        nodeId,role);
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

    private boolean isAuthorized(ProtocolPacket packet) {
        // Example RBAC: Only "Coordinator" can send TASK packets
        return packet.messageType()!=MessageTypeEnum.TASK ||
                packet.role()==NodeRoleEnum.COORDINATOR;
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_MATERIAL);
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();
    }

    public void sendTrustRequest(InetAddress targetAddress, int targetPort) throws Exception {
        String serializedPublicKey = serializePublicKey(keyPair.getPublic());
        ProtocolPacket trustRequest =
                createUnsignedPacket(MessageTypeEnum.TRUST_REQUEST,"BROADCAST",1,
                        serializedPublicKey,nodeId,role);
        sendPacket(trustRequest, targetAddress, targetPort);
    }

    private void sendTrustResponse(InetAddress targetAddress, int targetPort) throws Exception {
        String serializedPublicKey = serializePublicKey(keyPair.getPublic());
        ProtocolPacket trustRequest =
                createUnsignedPacket(
                MessageTypeEnum.TRUST_RESPONSE, "BROADCAST",1,serializedPublicKey,nodeId,role
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

    private String signPacket(MessageTypeEnum messageType, String targetId, int priority, String payload)
            throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(keyPair.getPrivate());
        ProtocolPacket packetToSing = createUnsignedPacket(messageType,targetId,priority,payload,nodeId,role);
        byte[] packetToBytes = packetToBytes(packetToSing);
        signature.update(packetToBytes);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private boolean verifyPacket(ProtocolPacket packet) throws Exception {
        PublicKey senderPublicKey = trustedNodes.get(packet.senderId());

        if (senderPublicKey == null) {
            return false;
        }

        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initVerify(senderPublicKey);
        ProtocolPacket packetWithoutSignature = new ProtocolPacket(packet.messageType(),
                packet.senderId(),packet.targetId(), packet.priority(), packet.payload(),
                packet.role(),null);
        byte[] packetToByte = packetToBytes(packetWithoutSignature);
        signature.update(packetToByte);
        String encodedPacketSignature = packet.signature();
        byte[] decodedPacketSignature = Base64.getDecoder().decode(encodedPacketSignature);
        return signature.verify(decodedPacketSignature);
    }

    private void sendPacket(ProtocolPacket packet, InetAddress targetAddress, int targetPort)
            throws Exception {
        //Sign the packet
        String signature = signPacket(packet.messageType(),
                packet.targetId(),packet.priority(),packet.payload());
        ProtocolPacket signedPacket = new ProtocolPacket(packet.messageType(),
                packet.senderId(),packet.targetId(),packet.priority(),packet.payload(),
                packet.role(),signature);

        // Serialize the packet into bytes
        byte[] signedPacketBytes = serialize(signedPacket);

        // Create a DatagramPacket for sending
        DatagramPacket datagramPacket = new DatagramPacket(signedPacketBytes, signedPacketBytes.length, targetAddress, targetPort);

        // Send the packet through the socket
        socket.send(datagramPacket);

        System.out.println("Packet sent to " + targetAddress + ":" + targetPort + " | Packet: " + packet);
    }
}
