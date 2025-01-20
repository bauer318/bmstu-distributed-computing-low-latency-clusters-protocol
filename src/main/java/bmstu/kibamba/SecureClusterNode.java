package bmstu.kibamba;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static bmstu.kibamba.NodeTaskWorker.*;
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
    private NodeStateEnum state;
    private LocalTime heartBeadSentAt;
    private static LocalTime taskResolutionBeginAt;

    private static final String KEY_MATERIAL = "DSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withDSA";
    private String taskToResolve;
    private static int taskSentToResolve;
    private static boolean atLeastOneTaskSentToResolve;


    public SecureClusterNode(String nodeId, int port, String clusterIp, NodeRoleEnum role) throws Exception {
        this.nodeId = nodeId;
        this.port = port;
        this.role = role;
        this.clusterAddress = InetAddress.getByName(clusterIp);
        this.socket = new DatagramSocket(port);
        this.keyPair = generateKeyPair();
        this.state = NodeStateEnum.FREE;
    }

    public void start() {
        System.out.println("Secure Node " + nodeId + " started on port " + port + " cluster address " + clusterAddress);
        if (this.role != NodeRoleEnum.COORDINATOR) {
            try {
                doHandShakeWithCoordinatorNode();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {
            doHeartBeatCheck();
        }
        Executors.newSingleThreadExecutor().execute(this::listenForPackets);
    }

    private void doHandShakeWithCoordinatorNode() throws Exception {
        //Assume that all nodes are on unique cluster and
        //the Coordinator's node port is 5001
        sendTrustRequest(this.clusterAddress, 5001);
    }

    private void listenForPackets() {
        //Buffer to receive incoming data
        byte[] buffer = new byte[4096];
        while (true) {
            try {
                DatagramPacket datagramPacket = new DatagramPacket(buffer, buffer.length);
                socket.receive(datagramPacket);

                ProtocolPacket receivedPacket = deserialize(datagramPacket.getData());
                if (receivedPacket.messageType() == MessageTypeEnum.TRUST_REQUEST) {
                    handleTrustRequest(receivedPacket, datagramPacket.getAddress(), datagramPacket.getPort());
                } else if (receivedPacket.messageType() == MessageTypeEnum.TRUST_RESPONSE) {
                    handleTrustResponse(receivedPacket, datagramPacket.getAddress(), datagramPacket.getPort());
                } else if (verifyPacket(receivedPacket)) {
                    handlePacket(receivedPacket);
                } else {
                    System.out.println("Invalid packet signature from " + receivedPacket.senderId());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void handleStateRequest(ProtocolPacket packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        System.out.println("Received STATE request from: " + packet.senderId());
        sendRequestResponse(senderAddress, senderPort, packet.senderId(), state.toString(), MessageTypeEnum.STATE_RESPONSE, 1);
        System.out.println("Respond the state " + state.toString() + " to " + packet.senderId());
    }

    private void handleStateResponse(ProtocolPacket packet) {
        System.out.println("Received STATE response from: " + packet.senderId());
        System.out.println(packet.senderId() + " STATE " + packet.payload());
    }

    private void handleTaskRequest(ProtocolPacket packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        System.out.println("Received TASK request from: " + packet.senderId());
        this.state = NodeStateEnum.BUSY;
        String resolvedTask = resolveTask(packet.payload());
        sendRequestResponse(senderAddress, senderPort, packet.senderId(), resolvedTask, MessageTypeEnum.RESPONSE, 0);
        this.state = NodeStateEnum.FREE;
        System.out.println("Resolved task " + resolvedTask + " sent to " + packet.senderId());
    }

    private void handleTaskResponse(ProtocolPacket packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        String taskResult = packet.payload();
        if (taskResult.startsWith("r_")) {
            String[] taskResultSplit = taskResult.split(",");
            taskToResolve = taskToResolve.replace(taskResultSplit[0], taskResultSplit[1]);
            taskSentToResolve--;
        }
        if (allSentTaskResolved()) {
            if (isTaskResolved(taskToResolve)) {
                System.out.println("Task RESOLVED after "
                        + taskResolutionBeginAt.until(LocalTime.now(), ChronoUnit.SECONDS) + " seconds");
                System.out.println("Result " + taskToResolve);
            } else {
                distributeTask(taskToResolve);
            }
        }
    }

    private boolean isTaskResolved(String task) {
        return !task.contains("r_") && !task.contains(",")
                && task.split(" ").length <= 1;
    }

    public void addTaskToResolve(String task) {
        try {
            distributeTask(task);
            taskResolutionBeginAt = LocalTime.now();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String resolveTask(String payload) {
        return resolvePacketTask(payload);
    }

    private void doHeartBeatCheck() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        Runnable task = () -> {
            System.out.println("Doing heart beat check task at: " + LocalTime.now());
            for (String trustNodeId : trustedNodes.keySet()) {
                try {
                    sendHearBeatRequest(this.clusterAddress, getPortByNodeId(trustNodeId), trustNodeId);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
        scheduler.scheduleAtFixedRate(task, 0, 15, TimeUnit.MINUTES);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down scheduler...");
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    System.out.println("Forcing scheduler shutdown...");
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                System.err.println("Scheduler interrupted: " + e.getMessage());
                scheduler.shutdownNow();
            }
        }));
    }

    private void distributeTask(String task) throws Exception {
        String[] dividedTask = divideTask(task, trustedNodes.size());
        int it = 0;
        taskSentToResolve = 0;
        atLeastOneTaskSentToResolve = false;
        if (trustedNodes.size() != 0) {
            for (String trustNodeId : trustedNodes.keySet()) {
                String taskSent = dividedTask[it];

                sendRequestResponse(this.clusterAddress, getPortByNodeId(trustNodeId), trustNodeId,
                        taskSent, MessageTypeEnum.TASK, 0);

                it++;
                taskSentToResolve++;
            }
            atLeastOneTaskSentToResolve = taskSentToResolve != 0;
        }
        taskToResolve = globalTask;
    }

    private boolean allSentTaskResolved() {
        return atLeastOneTaskSentToResolve && taskSentToResolve == 0;
    }

    private void handleHeartBeatRequest(ProtocolPacket packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        System.out.println("Received HEAR BEAT request from: " + packet.senderId());
        heartBeadSentAt = LocalTime.parse(packet.payload());
        LocalTime heartBeadRespondAt = LocalTime.now();
        sendRequestResponse(senderAddress, senderPort, packet.senderId(),
                String.valueOf(heartBeadSentAt.until(heartBeadRespondAt, ChronoUnit.SECONDS)),
                MessageTypeEnum.HEARTBEAT_RESPONSE,
                0);
    }

    private void handleHeartBeatResponse(ProtocolPacket packet, int senderPort) {
        System.out.println("Received HEAR BEAT request from: " + packet.senderId());
        int diffTime = Integer.parseInt(packet.payload());
        if (diffTime > 15) {
            System.out.println("Remove the node " + senderPort);
            trustedNodes.remove(packet.senderId());
        }
    }

    private void sendHearBeatRequest(InetAddress targetAddress, int targetPort, String targetNodeId) throws Exception {
        System.out.println("Send HEART BEAT request to " + targetNodeId);
        heartBeadSentAt = LocalTime.now();
        sendRequestResponse(targetAddress, targetPort, targetNodeId, heartBeadSentAt.toString(),
                MessageTypeEnum.HEARTBEAT_REQUEST, 0);
    }

    private void sendStateResponse(InetAddress targetAddress, int targetPort, String targetNodeId) throws Exception {
        ProtocolPacket stateResponse =
                createUnsignedPacket(MessageTypeEnum.STATE_RESPONSE, targetNodeId, 1,
                        state.toString(), nodeId, role);
        sendPacket(stateResponse, targetAddress, targetPort);
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
        //sendTrustResponse(senderAddress, senderPort);
        String serializedPublicKey = serializePublicKey(keyPair.getPublic());
        sendRequestResponse(senderAddress, senderPort, packet.senderId(), serializedPublicKey, MessageTypeEnum.TRUST_RESPONSE, 1);
    }

    private void sendTrustResponse(InetAddress targetAddress, int targetPort) throws Exception {
        String serializedPublicKey = serializePublicKey(keyPair.getPublic());
        ProtocolPacket trustRequest =
                createUnsignedPacket(
                        MessageTypeEnum.TRUST_RESPONSE, "BROADCAST", 1, serializedPublicKey, nodeId, role
                );
        sendPacket(trustRequest, targetAddress, targetPort);
    }

    public void sendTrustRequest(InetAddress targetAddress, int targetPort) throws Exception {
        String serializedPublicKey = serializePublicKey(keyPair.getPublic());
        ProtocolPacket trustRequest =
                createUnsignedPacket(MessageTypeEnum.TRUST_REQUEST, "BROADCAST", 1,
                        serializedPublicKey, nodeId, role);
        sendPacket(trustRequest, targetAddress, targetPort);
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
                        nodeId, role);
        sendPacket(responsePacket, senderAddress, senderPort);
    }

    private void handlePacket(ProtocolPacket packet) throws Exception {
        System.out.println("Secure Node " + nodeId + " received valid packet: " + packet);
        if (isAuthorized(packet)) {
            System.out.println("Packet authorized: " + packet);
            switch (packet.messageType()) {
                case TASK -> {
                    if (role == NodeRoleEnum.WORKER) {
                        handleTaskRequest(packet, clusterAddress, getPortByNodeId(packet.senderId()));
                    }
                }
                case RESPONSE -> {
                    if (role == NodeRoleEnum.COORDINATOR) {
                        handleTaskResponse(packet, clusterAddress, getPortByNodeId(packet.senderId()));
                    }
                }
                case HEARTBEAT_REQUEST ->
                        handleHeartBeatRequest(packet, clusterAddress, getPortByNodeId(packet.senderId()));
                case HEARTBEAT_RESPONSE -> handleHeartBeatResponse(packet, getPortByNodeId(packet.senderId()));
                case STATE_REQUEST -> handleStateRequest(packet, clusterAddress, getPortByNodeId(packet.senderId()));
                case STATE_RESPONSE -> handleStateResponse(packet);
            }
        } else {
            System.out.println("Unauthorized action attempted by: " + packet.senderId());
        }
    }

    private boolean isAuthorized(ProtocolPacket packet) {
        // Example RBAC: Only "Coordinator" can send TASK packets
        return packet.messageType() != MessageTypeEnum.TASK ||
                packet.role() == NodeRoleEnum.COORDINATOR;
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_MATERIAL);
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();
    }

    private void sendRequestResponse(InetAddress targetAddress, int targetPort, String targetNodeId,
                                     String payload,
                                     MessageTypeEnum requestType, int priority) throws Exception {
        ProtocolPacket taskRequest =
                createUnsignedPacket(requestType, targetNodeId, priority,
                        payload, nodeId, role);
        sendPacket(taskRequest, targetAddress, targetPort);
    }

    private void sendTaskRequest(InetAddress targetAddress, int targetPort, String targetNodeId, String task)
            throws Exception {
        ProtocolPacket taskRequest =
                createUnsignedPacket(MessageTypeEnum.TASK, targetNodeId, 0,
                        task, nodeId, role);
        sendPacket(taskRequest, targetAddress, targetPort);
    }

    private void sendTaskResponse(InetAddress targetAddress, int targetPort, String targetNodeId, String taskResult)
            throws Exception {
        ProtocolPacket taskResponse =
                createUnsignedPacket(MessageTypeEnum.TASK, targetNodeId, 0,
                        taskResult, nodeId, role);
        sendPacket(taskResponse, targetAddress, targetPort);
    }

    private void sendStateRequest(InetAddress targetAddress, int targetPort, String targetNodeId) throws Exception {
        ProtocolPacket stateRequest =
                createUnsignedPacket(MessageTypeEnum.STATE_REQUEST, targetNodeId, 1,
                        null, nodeId, role);
        sendPacket(stateRequest, targetAddress, targetPort);
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
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(keyPair.getPrivate());
        ProtocolPacket packetToSing = createUnsignedPacket(messageType, targetId, priority, payload, nodeId, role);
        byte[] packetToBytes = packetToBytes(packetToSing);
        signature.update(packetToBytes);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private boolean verifyPacket(ProtocolPacket packet) throws Exception {
        PublicKey senderPublicKey = trustedNodes.get(packet.senderId());

        if (senderPublicKey == null) {
            return false;
        }

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(senderPublicKey);
        ProtocolPacket packetWithoutSignature = new ProtocolPacket(packet.messageType(),
                packet.senderId(), packet.targetId(), packet.priority(), packet.payload(),
                packet.role(), null);
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
                packet.targetId(), packet.priority(), packet.payload());
        ProtocolPacket signedPacket = new ProtocolPacket(packet.messageType(),
                packet.senderId(), packet.targetId(), packet.priority(), packet.payload(),
                packet.role(), signature);

        // Serialize the packet into bytes
        byte[] signedPacketBytes = serialize(signedPacket);

        // Create a DatagramPacket for sending
        DatagramPacket datagramPacket = new DatagramPacket(signedPacketBytes, signedPacketBytes.length, targetAddress, targetPort);

        // Send the packet through the socket
        socket.send(datagramPacket);

        System.out.println("Packet sent to " + targetAddress + ":" + targetPort + " | Packet: " + packet);
    }
}
