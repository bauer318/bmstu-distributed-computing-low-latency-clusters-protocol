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

import static bmstu.kibamba.MessageTypeEnum.*;
import static bmstu.kibamba.NodeTaskWorker.divideTask;
import static bmstu.kibamba.NodeTaskWorker.globalTask;
import static bmstu.kibamba.Utils.*;

public class SecureClusterNode {
    private static final String KEY_MATERIAL = "DSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withDSA";
    private static final String COORDINATOR_NODE_ID = "node-1";
    private static final int COORDINATOR_PORT = 5001;
    private final int ACK_ATTEMPTS_NUMBER = 5;
    private final String nodeId;
    private final InetAddress clusterAddress;
    private final int port;
    private final DatagramSocket socket;
    private final NodeRoleEnum role;
    // For authentication
    private final KeyPair keyPair;
    // Authorized node public keys
    private final Map<String, PublicKey> trustedNodes = new ConcurrentHashMap<>();
    private final Map<String, LocalTime> nodeHeartBeatSentTime = new ConcurrentHashMap<>();
    private final Map<String, LocalTime> nodeHeartBeatBackTime = new ConcurrentHashMap<>();
    private final Map<String, Integer> nodeACKTrustRequest = new ConcurrentHashMap<>();
    private final Map<String, Integer> nodeACKTrustResponse = new ConcurrentHashMap<>();
    private NodeStateEnum state;
    private LocalTime heartBeadSentAt;
    private static LocalTime taskResolutionBeginAt;
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
        doACKCheck();
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

    private void doACKCheck() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        Runnable task = () -> {
            if (nodeACKTrustRequest.size() > 0 || nodeACKTrustResponse.size() > 0) {
                System.out.println("Doing trust ack check: " + LocalTime.now());
            }
            checkACKResponses();
        };
        scheduleTask(scheduler, task, 25);
    }

    private void checkACKResponses() {
        for (String nodeId : nodeACKTrustRequest.keySet()) {
            try {
                doHandShakeWithCoordinatorNode();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        for (String nodeId : nodeACKTrustResponse.keySet()) {
            tryToResendTrustResponse(nodeId);
        }
    }

    private void tryToResendTrustResponse(String nodeId) {
        int currentValue = nodeACKTrustResponse.get(nodeId);
        int targetPort = getPortByNodeId(nodeId);
        if (currentValue <= ACK_ATTEMPTS_NUMBER) {
            try {
                System.out.println("resend trust response to " + nodeId);
                String serializedPublicKey = serializePublicKey(keyPair.getPublic());
                sendRequestResponse(
                        this.clusterAddress,
                        targetPort,
                        stringToBytes(nodeId),
                        stringToBytes(serializedPublicKey),
                        MessageTypeEnum.TRUST_RESPONSE,
                        (byte) 1);
                nodeACKTrustResponse.replace(nodeId, currentValue + 1);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void scheduleTask(ScheduledExecutorService scheduler, Runnable task, int period) {
        scheduler.scheduleAtFixedRate(task, 0, period, TimeUnit.SECONDS);
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

    private void doHandShakeWithCoordinatorNode() throws Exception {
        //Assume that all nodes are on unique cluster and
        //the Coordinator's node port is 5001 and node id is node-1
        if (nodeACKTrustRequest.containsKey(COORDINATOR_NODE_ID)) {
            int currentValue = nodeACKTrustRequest.get(COORDINATOR_NODE_ID);
            //Resend the trust request
            if (currentValue <= ACK_ATTEMPTS_NUMBER) {
                sendTrustRequest(this.clusterAddress, COORDINATOR_PORT);
                currentValue++;
                nodeACKTrustRequest.replace(COORDINATOR_NODE_ID, currentValue);
            } else {
                nodeACKTrustRequest.remove(COORDINATOR_NODE_ID);
            }
        } else {
            int firstSendValue = 1;
            sendTrustRequest(this.clusterAddress, COORDINATOR_PORT);
            nodeACKTrustRequest.put(COORDINATOR_NODE_ID, firstSendValue);
        }
    }

    private void listenForPackets() {
        //Buffer to receive incoming data
        int bufferSize = 65508;
        byte[] buffer = new byte[bufferSize];
        while (true) {
            try {
                DatagramPacket datagramPacket = new DatagramPacket(buffer, buffer.length);
                socket.receive(datagramPacket);

                Packet receivedPacketD = deserialize(datagramPacket.getData());

                if (receivedPacketD.getMessageType() == MessageTypeEnum.TRUST_REQUEST.getMessageType()) {
                    handleTrustRequest(receivedPacketD, datagramPacket.getAddress(), datagramPacket.getPort());
                } else if (receivedPacketD.getMessageType() == MessageTypeEnum.TRUST_RESPONSE.getMessageType()) {
                    handleTrustResponse(receivedPacketD, datagramPacket.getAddress(), datagramPacket.getPort());
                } else if (receivedPacketD.getMessageType() == TRUST_RQ_ACK.getMessageType()) {
                    handleTrustACKRequest(receivedPacketD);

                } else if (receivedPacketD.getMessageType() == TRUST_RP_ACK.getMessageType()) {
                    handleTrustACKResponse(receivedPacketD);
                } else if (verifyPacket(receivedPacketD)) {
                    handlePacket(receivedPacketD);
                } else {
                    System.out.println("!!!!!!! Invalid packet signature from " +
                            bytesToString(receivedPacketD.getSenderId()));
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void handleStateRequest(Packet packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        System.out.println("\tReceived STATE request from: " + bytesToString(packet.getSenderId()));
        sendRequestResponse(
                senderAddress,
                senderPort,
                packet.getSenderId(),
                stringToBytes(state.toString()),
                MessageTypeEnum.STATE_RESPONSE,
                (byte) 1);
        System.out.println("\tRespond the state " + state.toString() + " to "
                + bytesToString(packet.getSenderId()));
    }

    private void handleStateResponse(Packet packet) {
        System.out.println("Received STATE response from: " + bytesToString(packet.getSenderId()));
        System.out.println(bytesToString(packet.getSenderId()) + " STATE " + bytesToString(packet.getPayload()));
    }

    private void handleTaskRequest(Packet packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        System.out.println("\tReceived TASK request from: " + bytesToString(packet.getSenderId()));
        this.state = NodeStateEnum.BUSY;
        String resolvedTask = resolveTask(bytesToString(packet.getPayload()));
        sendRequestResponse(
                senderAddress,
                senderPort,
                packet.getSenderId(),
                stringToBytes(resolvedTask),
                MessageTypeEnum.RESPONSE,
                (byte) 0);
        simulateLongWorkByNode(nodeId);
        this.state = NodeStateEnum.FREE;
        System.out.println("\tResolved task " + resolvedTask + " sent to "
                + bytesToString(packet.getSenderId()));
    }

    private void handleTaskResponse(Packet packet)
            throws Exception {
        String taskResult = bytesToString(packet.getPayload());
        if (taskResult.startsWith("r_")) {
            String[] taskResultSplit = taskResult.split(",");
            assert taskToResolve != null;
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
            //System.out.println("Doing heart beat check task at: " + LocalTime.now());
            checkHeartBeatResponses();
            for (String trustNodeId : trustedNodes.keySet()) {
                try {
                    sendHearBeatRequest(this.clusterAddress, getPortByNodeId(trustNodeId), trustNodeId);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
        scheduleTask(scheduler, task, 20);
    }

    private void checkHeartBeatResponses() {
        for (String nodeId : nodeHeartBeatSentTime.keySet()) {
            if (nodeHeartBeatSentTime.get(nodeId).equals(nodeHeartBeatBackTime.get(nodeId))) {
                if (trustedNodes.containsKey(nodeId)) {
                    System.out.println("\t\tREMOVED the " + nodeId + " when checking the heart beat responses");
                    trustedNodes.remove(nodeId);
                }

            }
        }
        nodeHeartBeatSentTime.clear();
        nodeHeartBeatBackTime.clear();
    }

    private void distributeTask(String task) throws Exception {
        if (trustedNodes.size() != 0) {
            String[] dividedTask = divideTask(task, trustedNodes.size());
            int it = 0;
            taskSentToResolve = 0;
            atLeastOneTaskSentToResolve = false;
            for (String trustNodeId : trustedNodes.keySet()) {
                //TODO only for test
                if (it >= dividedTask.length) {
                    it = dividedTask.length - 1;
                }
                if (it < 0) {
                    it = 0;
                }
                String taskSent = dividedTask[it];

                sendRequestResponse(
                        this.clusterAddress,
                        getPortByNodeId(trustNodeId),
                        stringToBytes(trustNodeId),
                        stringToBytes(taskSent),
                        TASK,
                        (byte) 0);

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

    private void handleHeartBeatRequest(Packet packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        System.out.println("\tReceived HEART BEAT request from: " + bytesToString(packet.getSenderId()));
        heartBeadSentAt = LocalTime.parse(bytesToString(packet.getPayload()));
        LocalTime heartBeadRespondAt = LocalTime.now();
        sendRequestResponse(
                senderAddress,
                senderPort,
                packet.getSenderId(),
                stringToBytes(String.valueOf(heartBeadSentAt.until(heartBeadRespondAt, ChronoUnit.SECONDS))),
                HEARTBEAT_RESPONSE,
                (byte) 0);
    }

    private void handleHeartBeatResponse(Packet packet, int senderPort) {
        String senderNodeId = bytesToString(packet.getSenderId());
        System.out.println("Received HEAR BEAT response from: " + senderNodeId);
        int diffTime = Integer.parseInt(bytesToString(packet.getPayload()));
        nodeHeartBeatBackTime.replace(senderNodeId, LocalTime.now());
        if (diffTime > 15) {
            System.out.println("Remove the node " + senderPort);
            trustedNodes.remove(bytesToString(packet.getSenderId()));
        }
    }

    private void sendHearBeatRequest(InetAddress targetAddress, int targetPort, String targetNodeId)
            throws Exception {
        System.out.println("\tSend HEART BEAT request to " + targetNodeId);
        heartBeadSentAt = LocalTime.now();
        nodeHeartBeatSentTime.put(targetNodeId, heartBeadSentAt);
        nodeHeartBeatBackTime.put(targetNodeId, heartBeadSentAt);
        sendRequestResponse(
                targetAddress,
                targetPort,
                stringToBytes(targetNodeId),
                stringToBytes(heartBeadSentAt.toString()),
                HEARTBEAT_REQUEST,
                (byte) 0);
    }

    private void handleTrustRequest(Packet packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        String senderId = bytesToString(packet.getSenderId());
        System.out.println("\tReceived trust request from: " + senderId);
        //Confirm the reception of trust request
        sendRequestResponse(
                senderAddress,
                senderPort,
                packet.getSenderId(),
                null,
                TRUST_RQ_ACK,
                (byte) 0);

        // Extract the sender's public key from the payload
        byte[] encodedKey = packet.getPayload();
        PublicKey senderKey = deserializePublicKey(encodedKey);

        // Add the sender's key to the trustedNodes map
        trustedNodes.put(bytesToString(packet.getSenderId()), senderKey);
        System.out.println("\tAdded " + bytesToString(packet.getSenderId()) + " to trusted nodes.");

        //Respond the sender with the public key
        String serializedPublicKey = serializePublicKey(keyPair.getPublic());
        sendRequestResponse(
                senderAddress,
                senderPort,
                packet.getSenderId(),
                stringToBytes(serializedPublicKey),
                MessageTypeEnum.TRUST_RESPONSE,
                (byte) 1);
        int firstValue = 1;
        nodeACKTrustResponse.put(senderId, firstValue);
    }

    private void handleTrustACKRequest(Packet packet) {
        String senderId = bytesToString(packet.getSenderId());
        System.out.println("Receiver " + senderId + " confirm the reception of trust request");
        nodeACKTrustRequest.remove(senderId);
    }

    private void handleTrustACKResponse(Packet packet) {
        String senderId = bytesToString(packet.getSenderId());
        System.out.println("Receiver " + senderId + " confirm the reception of trust response");
        nodeACKTrustResponse.remove(senderId);
    }

    public void sendTrustRequest(InetAddress targetAddress, int targetPort) throws Exception {
        String serializedPublicKey = serializePublicKey(keyPair.getPublic());
        Packet trustRequest =
                createUnsignedPacket(
                        MessageTypeEnum.TRUST_REQUEST.getMessageType(),
                        (byte) 0,
                        role.getNodeRole(),
                        stringToBytes(nodeId),
                        stringToBytes("node-1"),
                        stringToBytes(serializedPublicKey));
        sendPacket(trustRequest, targetAddress, targetPort);
    }

    private void handleTrustResponse(Packet packet, InetAddress senderAddress, int senderPort)
            throws Exception {
        System.out.println("Received trust response from: " + bytesToString(packet.getSenderId()));

        byte[] encodedKey = packet.getPayload();
        PublicKey senderKey = deserializePublicKey(encodedKey);

        // Add the sender's key to the trustedNodes map
        trustedNodes.put(bytesToString(packet.getSenderId()), senderKey);
        System.out.println("Added " + bytesToString(packet.getSenderId()) + " to trusted nodes.");

        // Send acknowledgment
        sendRequestResponse(
                senderAddress,
                senderPort,
                packet.getSenderId(),
                null,
                TRUST_RP_ACK,
                (byte) 1);

        //Connexion established
        Packet responsePacket =
                createUnsignedPacket(
                        MessageTypeEnum.TRUST_CON.getMessageType(),
                        (byte) 0,
                        role.getNodeRole(),
                        stringToBytes(nodeId),
                        packet.getSenderId(),
                        stringToBytes("Trust established"));
        sendPacket(responsePacket, senderAddress, senderPort);
    }

    private void handlePacket(Packet packet) throws Exception {
        System.out.println("Secure Node " + nodeId + " received valid packet: " + packet);
        if (isAuthorized(packet)) {
            System.out.println("Packet authorized: " + packet);
            switch (MessageTypeEnum.getByValue(packet.getMessageType())) {
                case TASK -> {
                    if (role == NodeRoleEnum.WORKER) {
                        handleTaskRequest(
                                packet,
                                clusterAddress,
                                getPortByNodeId(bytesToString(packet.getSenderId())));
                    }
                }
                case RESPONSE -> {
                    if (role == NodeRoleEnum.COORDINATOR) {
                        handleTaskResponse(packet);
                    }
                }
                case HEARTBEAT_REQUEST -> handleHeartBeatRequest(
                        packet,
                        clusterAddress,
                        getPortByNodeId(bytesToString(packet.getSenderId())));
                case HEARTBEAT_RESPONSE -> handleHeartBeatResponse(
                        packet,
                        getPortByNodeId(bytesToString(packet.getSenderId())));
                case STATE_REQUEST -> handleStateRequest(packet, clusterAddress,
                        getPortByNodeId(bytesToString(packet.getSenderId())));
                case STATE_RESPONSE -> handleStateResponse(packet);
            }
        } else {
            System.out.println("Unauthorized action attempted by: " + bytesToString(packet.getSenderId()));
        }
    }

    private boolean isAuthorized(Packet packet) {
        // RBAC: Only "Coordinator" can send TASK packets
        return MessageTypeEnum.getByValue(packet.getMessageType()) != TASK ||
                packet.getNodeRole() == NodeRoleEnum.COORDINATOR.getNodeRole();
    }

    private KeyPair generateKeyPair() throws Exception {
        int keySize = 1024;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_MATERIAL);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    private void sendRequestResponse(InetAddress targetAddress,
                                     int targetPort,
                                     byte[] targetNodeId,
                                     byte[] payload,
                                     MessageTypeEnum requestType,
                                     byte priority) throws Exception {
        Packet taskRequest =
                createUnsignedPacket(
                        requestType.getMessageType(),
                        priority,
                        role.getNodeRole(),
                        stringToBytes(nodeId),
                        targetNodeId,
                        payload);
        sendPacket(taskRequest, targetAddress, targetPort);
    }

    public static String serializePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public static PublicKey deserializePublicKey(byte[] encodedKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_MATERIAL);
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }

    private String signPacket(byte messageType, byte[] targetId, byte priority, byte[] payload)
            throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(keyPair.getPrivate());
        Packet packetToSing =
                createUnsignedPacket(
                        messageType,
                        priority,
                        role.getNodeRole(),
                        stringToBytes(nodeId),
                        targetId,
                        payload);
        byte[] packetToBytes = packetToBytes(packetToSing);
        signature.update(packetToBytes);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private boolean verifyPacket(Packet packet) throws Exception {
        PublicKey senderPublicKey = trustedNodes.get(bytesToString(packet.getSenderId()));

        if (senderPublicKey == null) {
            return false;
        }

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(senderPublicKey);
        Packet packetWithoutSignature = new Packet(
                packet.getMessageType(),
                packet.getPriority(),
                packet.getNodeRole(),
                packet.getSenderId(),
                packet.getTargetId(),
                null,
                packet.getPayload());
        byte[] packetToByte = packetToBytes(packetWithoutSignature);
        signature.update(packetToByte);
        String encodedPacketSignature = bytesToString(packet.getSignature());
        byte[] decodedPacketSignature = Base64.getDecoder().decode(encodedPacketSignature);
        return signature.verify(decodedPacketSignature);
    }

    private void sendPacket(Packet packet, InetAddress targetAddress, int targetPort)
            throws Exception {
        //Sign the packet
        String signature = signPacket(packet.getMessageType(),
                packet.getTargetId(), packet.getPriority(), packet.getPayload());
        Packet signedPacket = new Packet(
                packet.getMessageType(),
                packet.getPriority(),
                packet.getNodeRole(),
                packet.getSenderId(),
                packet.getTargetId(),
                stringToBytes(signature),
                packet.getPayload()
        );

        // Serialize the packet into bytes
        byte[] signedPacketBytes = serialize(signedPacket);

        // Create a DatagramPacket for sending
        DatagramPacket datagramPacket = new DatagramPacket(signedPacketBytes, signedPacketBytes.length, targetAddress, targetPort);

        // Send the packet through the socket
        socket.send(datagramPacket);

        System.out.println("Packet sent to " + targetAddress + ":" + targetPort + " | Packet: " + packet);
    }
}
