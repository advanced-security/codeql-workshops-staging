/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id java/introworkshop
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.TaintTracking

module SqliFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(MethodCall read |
      read.getMethod().getName() = "readLine" and
      read = source.asExpr()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall exec |
      exec.getMethod().getName() = "executeUpdate" and
      exec.getArgument(0) = sink.asExpr()
    )
  }
}

module MyDataFlow = TaintTracking::Global<SqliFlowConfig>;

import MyDataFlow::PathGraph

from MyDataFlow::PathNode source, MyDataFlow::PathNode sink
where MyDataFlow::flowPath(source, sink)
select sink, source, sink, "Possible SQL injection"
