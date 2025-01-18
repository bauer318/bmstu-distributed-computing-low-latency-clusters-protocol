package bmstu.kibamba;

import java.util.Scanner;

public class Runner {

    public static void main(String[] args) {
        String _nodeId = "node-1";
        int _port = 5001;
        String _clusterIp = "127.0.0.1";
        String _role = "Coordinator";
        try{
            SecureClusterNode node = new SecureClusterNode(_nodeId, _port, _clusterIp, _role);
            node.start();
            //node.sendTestPackets();
        }catch (Exception ex){
            ex.printStackTrace();
        }
        /*int argsNumber = 0;
        String[] argsTitles = {"NodeId: ", "Port: ", "ClusterIP: ", "Role one of [Coordinator, Worker, Monitor]: "};
        Scanner sc = new Scanner(System.in);
        String _nodeId = null;
        int _port = 0;
        String _clusterIp = null;
        String _role = null;
        System.out.println("Build the cluster node");
        while(argsNumber!=4){
            System.out.print(argsTitles[argsNumber]);
            String input = sc.nextLine();
            if(!input.isBlank()){
                switch (argsNumber) {
                    case 0 -> _nodeId = input;
                    case 1 -> _port = Integer.parseInt(input);
                    case 2 -> _clusterIp = input;
                    case 3 -> _role = input;
                }
                argsNumber++;
            }
        }

        if(canBuildNode(_nodeId, _port, _clusterIp, _role)){
            try{
                SecureClusterNode node = new SecureClusterNode(_nodeId, _port, _clusterIp, _role);
                node.start();
                node.sendTestPackets();
            }catch (Exception ex){
                ex.printStackTrace();
            }

        }
        sc.close();*/
//        if (args.length != 4) {
//            System.out.println("Usage: java SecureClusterNode <NodeID> <Port> <ClusterIP> <Role>");
//            return;
//        }
//        try {
//            // Parse arguments
//            String nodeId = args[0];
//            int port = Integer.parseInt(args[1]);
//            String clusterIp = args[2];
//            String role = args[3];
//
//            // Initialize the node
//            SecureClusterNode node = new SecureClusterNode(nodeId, port, clusterIp, role);
//
//            // Start the node
//            node.start();
//
//            // Send test packets (for testing purposes)
//            node.sendTestPackets();
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }

    private static boolean canBuildNode(String nodeId, int port, String clusterIp, String role){
        return !nodeId.isBlank() && port>=5000 && !clusterIp.isBlank() && !role.isBlank();
    }

}
