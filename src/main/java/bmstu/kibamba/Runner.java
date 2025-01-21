package bmstu.kibamba;

import java.util.Scanner;

import static bmstu.kibamba.Utils.*;

public class Runner {
    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);
        ClusterNodeParameter parameters = buildClusterNodeParameter(sc);
        if (canBuildNode(parameters.getNodeId(), parameters.getPort(),
                parameters.getClusterIp(), parameters.getRole())) {
            try {
                NodeRoleEnum nodeRoleEnum = NodeRoleEnum.getByValue(parameters.getRole());
                parameters.setPort(changeNodePortIfPossible(nodeRoleEnum, parameters.getPort()));
                SecureClusterNode node = new SecureClusterNode(
                        parameters.getNodeId(),
                        parameters.getPort(),
                        parameters.getClusterIp(),
                        nodeRoleEnum);
                node.start();
                doTaskMenuIfCoordinatorNode(nodeRoleEnum, sc, node);
            } catch (Exception ex) {
                ex.printStackTrace();
            }

        }
        sc.close();
    }
}
