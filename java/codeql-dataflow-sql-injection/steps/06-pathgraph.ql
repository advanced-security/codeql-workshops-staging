/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id java/introworkshop
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.TaintTracking

predicate isReadLine(MethodCall read) {
  read.getMethod().getName() = "readLine"
}

predicate isExecuteUpdate(MethodCall exec) {
  exec.getMethod().getName() = "executeUpdate"
}

module SqliFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isReadLine(source.asExpr())
  }

  predicate isSink(DataFlow::Node sink) {
    isExecuteUpdate(sink.asExpr())
  }
}

module MyDataFlow = TaintTracking::Global<SqliFlowConfig>;

import MyDataFlow::PathGraph

from MyDataFlow::PathNode source, MyDataFlow::PathNode sink
where MyDataFlow::flowPath(source, sink)
select sink, source, sink, "Possible SQL injection"

