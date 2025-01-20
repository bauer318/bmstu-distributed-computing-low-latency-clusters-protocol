package bmstu.kibamba;

import java.util.*;

public class NodeTaskWorker {
    private static final ArrayList<String> OPERATIONS = new ArrayList<>(List.of("+", "-", "="));
    public static final Map<Integer, NodeTask> NODE_TASKS = new HashMap<>();
    public static String[] taskSplit;
    public static String globalTask;

    private static int countTask(String[] taskArray) {
        int taskCount = 0;
        for (String taskElement : taskArray) {
            if (!OPERATIONS.contains(taskElement)) {
                taskCount++;
            }
        }
        return taskCount / 2;
    }

    public static String[] divideTask(String task, int nodeCount) {
        NODE_TASKS.clear();
        taskSplit = task.split(" ");
        int taskCount = Math.min(countTask(taskSplit), nodeCount);
        buildTaskAggregations(taskCount, taskSplit);
        String[] dividedTasks = buildDividedTasks(taskCount, taskSplit);
        globalTask = buildAggregatedTask(taskSplit);
        return dividedTasks;
    }

    private static void buildTaskAggregations(int taskCount, String[] taskArray) {
        int firstIndex;
        int lastIndex = -2;
        for (int i = 0; i < taskCount; i++) {
            int leftTaskOrderId = lastIndex + 2;
            firstIndex = leftTaskOrderId;
            int rightTaskOrderId = firstIndex + 2;
            lastIndex = rightTaskOrderId;
            int operationIndex = firstIndex + 1;
            NODE_TASKS.put(leftTaskOrderId, new NodeTask(leftTaskOrderId, rightTaskOrderId,
                    taskArray[operationIndex]));
        }
    }

    public static String buildDividedTask(int leftTaskOrderId, int rightTaskOrderId, String taskOperation,
                                          String[] inputTaskSplit) {
        return leftTaskOrderId + "," +
                inputTaskSplit[leftTaskOrderId] +
                "," +
                inputTaskSplit[rightTaskOrderId] +
                "," +
                taskOperation;
    }

    private static String[] buildDividedTasks(int taskCount, String[] taskArray) {
        int taskOrder = 0;
        String[] dividedTasks = new String[taskCount];
        for (int keyTask : NODE_TASKS.keySet()) {
            NodeTask currentTaskAggregation = NODE_TASKS.get(keyTask);
            dividedTasks[taskOrder++] = buildDividedTask(currentTaskAggregation.getLeftTaskOrderId(),
                    currentTaskAggregation.getRightTaskOrderId(), currentTaskAggregation.getTaskOperation(),
                    taskArray);
        }
        return dividedTasks;
    }

    private static String buildAggregatedTask(String[] inputTaskSplit) {
        StringBuilder result = new StringBuilder();
        for (int keyTask : NODE_TASKS.keySet()) {
            NodeTask currentTaskAggregation = NODE_TASKS.get(keyTask);
            result.append("r_")
                    .append(currentTaskAggregation.getLeftTaskOrderId())
                    .append(" ");
            tryToAddNextOperandAfter(currentTaskAggregation.getRightTaskOrderId(), inputTaskSplit,
                    result);
        }
        int maxKey = Collections.max(NODE_TASKS.keySet());
        tryToAddRestInputTaskOperands(inputTaskSplit, result, NODE_TASKS.get(maxKey));
        return result.toString();
    }

    private static boolean existNextOperandAfter(int rightTaskOrderId, int taskArrayLength) {
        return rightTaskOrderId + 1 < taskArrayLength;
    }

    private static void tryToAddNextOperandAfter(int rightTaskOrderId, String[] inputTaskSplit,
                                                 StringBuilder result) {
        int elementCount = inputTaskSplit.length;
        if (existNextOperandAfter(rightTaskOrderId, elementCount)) {
            result.append(inputTaskSplit[rightTaskOrderId + 1])
                    .append(" ");
        }
    }

    private static boolean existsOthersOperandOutOf(int firstOthersNonDividedOperandsIndex, int taskElementCount) {
        return firstOthersNonDividedOperandsIndex <= taskElementCount - 1;
    }

    private static void tryToAddRestInputTaskOperands(String[] inputTaskSplit, StringBuilder result, NodeTask lastNodeTaskWithMaxKey) {
        int lastNodeTaskWithMaxIdRightTaskOrderId = lastNodeTaskWithMaxKey.getRightTaskOrderId();
        int firstOthersNonDividedOperandsIndex = lastNodeTaskWithMaxIdRightTaskOrderId + 2;
        if (existsOthersOperandOutOf(firstOthersNonDividedOperandsIndex, inputTaskSplit.length)) {
            for (int i = firstOthersNonDividedOperandsIndex; i < inputTaskSplit.length; i++) {
                result.append(inputTaskSplit[i]);
                if (i != inputTaskSplit.length - 1) {
                    result.append(" ");
                }
            }
        }
    }

}
