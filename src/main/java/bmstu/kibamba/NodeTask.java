package bmstu.kibamba;

public class NodeTask {
    private final int leftTaskOrderId;
    private final int rightTaskOrderId;
    private final String taskOperation;

    public NodeTask(int leftNodeTaskOperand, int rightNodeTaskOperand, String nodeTaskOperation){
        this.leftTaskOrderId = leftNodeTaskOperand;
        this.rightTaskOrderId = rightNodeTaskOperand;
        this.taskOperation = nodeTaskOperation;
    }
    public int getLeftTaskOrderId() {
        return leftTaskOrderId;
    }

    public int getRightTaskOrderId() {
        return rightTaskOrderId;
    }

    public String getTaskOperation() {
        return taskOperation;
    }
}
