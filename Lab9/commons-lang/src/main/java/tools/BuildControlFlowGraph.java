package tools;

import spoon.Launcher;
import spoon.reflect.declaration.CtClass;
import spoon.reflect.CtModel;
import spoon.reflect.visitor.Filter;
import spoon.reflect.declaration.CtMethod;

import fr.inria.controlflow.ControlFlowBuilder;
// import fr.inria.controlflow.ControlFlowEdge;
import fr.inria.controlflow.ControlFlowGraph;

public class BuildControlFlowGraph {
    public static void main(String[] args) {
        BuildControlFlowGraph builder = new BuildControlFlowGraph();
        builder.buildCFG("capitalize");
    }

    public void buildCFG(String method_name) {
        Launcher launcher = new Launcher();
        launcher.addInputResource("./src/main/java");
        CtModel model = launcher.buildModel();
        CtClass<?> ctClass = model.getElements((Filter<CtClass<?>>) element -> true)
                .stream()
                .filter(c -> c.getQualifiedName().equals("tools.StringUtils"))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Class CodeInfoExtractor not found"));
        CtMethod<?> method = ctClass.getMethodsByName(method_name).get(0);
        ControlFlowBuilder builder = new ControlFlowBuilder();
        builder.visitCtMethod(method);
        // ControlFlowGraph cfg = builder.build(ctClass2);
        // ControlFlowGraph cfg = builder.build(method);
        // builder.build(method2);
        ControlFlowGraph cfg = builder.getResult();
        cfg.simplify(); // Merge/remove invalid nodes
        String dot = cfg.toGraphVisText(); // Generate GraphViz DOT text
        System.out.println(dot);
    }
}
