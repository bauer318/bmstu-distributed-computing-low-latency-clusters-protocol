package bmstu.kibamba;

import java.util.Objects;

public class NodeTask {
    private final int leftTaskOrderId;
    private int rightTaskOrderId;
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

    public void setRightTaskOrderId(int rightTaskOrderId) {
        this.rightTaskOrderId = rightTaskOrderId;
    }

    public String getTaskOperation() {
        return taskOperation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NodeTask that = (NodeTask) o;
        return leftTaskOrderId == that.leftTaskOrderId && rightTaskOrderId == that.rightTaskOrderId &&
                Objects.equals(taskOperation, that.taskOperation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(leftTaskOrderId, rightTaskOrderId, taskOperation);
    }
}
