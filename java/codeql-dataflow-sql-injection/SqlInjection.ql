/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id SQLIVulnerable
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.TaintTracking

module SqliFlowConfig implements DataFlow::ConfigSig {

    predicate isSource(DataFlow::Node source) {
        // System.console().readLine();
        exists(Call read |
            read.getCallee().getName() = "readLine" and
            read = source.asExpr()
        )
    }

    predicate isBarrier(DataFlow::Node sanitizer) { none() }

    predicate isAdditionalFlowStep(DataFlow::Node into, DataFlow::Node out) {
        // Extra taint step
        //     String.format("INSERT INTO users VALUES (%d, '%s')", id, info);
        // Not needed here, but may be needed for larger libraries.
        none()
    }

    predicate isSink(DataFlow::Node sink) {
        // conn.createStatement().executeUpdate(query);
        exists(Call exec |
            exec.getCallee().getName() = "executeUpdate" and
            exec.getArgument(0) = sink.asExpr()
        )
    }
}

module MyDataFlow = TaintTracking::Global<SqliFlowConfig>;
import MyDataFlow::PathGraph

from MyDataFlow::PathNode source, MyDataFlow::PathNode sink
where MyDataFlow::flowPath(source, sink)
select sink, source, sink, "Possible SQL injection"
