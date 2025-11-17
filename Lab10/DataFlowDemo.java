import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;

public class DataFlowDemo {

    public static void main(String[] args) {
        testLogic("input");
    }

    public static void testLogic(String input) {
        String result = null; // [Node A] 定义变量 (Def)

        // 数据流分支逻辑
        if (input.length() > 5) {
            result = "Valid Input"; // [Node B] 重新定义 (Redef)
        }
        
        // 【检测点 1：空指针隐患】
        // 静态分析引擎会进行路径敏感分析：
        // 存在一条路径 (当 input <= 5 时)，数据流直接从 Node A 到这里，
        // 中间没有赋值，导致 result 仍为 null。
        System.out.println(result.length()); // [Node C] 使用变量 (Use)

        // 【检测点 2：死存储 / 未使用的变量】
        int k = 100; // [Node D] 定义 k
        k = 200;     // [Node E] 再次定义 k
        // 解释：Node D 的赋值在被使用前就被 Node E 覆盖了，
        // 且 Node D 到 Node E 之间没有引用，这叫 "Dead Store"。
        System.out.println(k);

        // 【检测点 3：资源泄漏】
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(new File("test.txt"));
            writer.write("Hello");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        // 缺失 finally { writer.close() }
        // 数据流分析发现 writer 对象在生命周期结束前未被释放。
    }
}