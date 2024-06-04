/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id java/introworkshop
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.TaintTracking

/* For further discussions */
private MethodCall getSystemOutPrintln() {
  exists(SystemOut systemOut |
    result.getQualifier() = systemOut.getAnAccess() and
    result.getMethod().getName() = "println"
  )
}

/* For further discussions */
private MethodCall getSystemConsoleReadLine() {
  exists(TypeAccess system, MethodCall systemConsole |
    system.getType() instanceof TypeSystem and
    systemConsole.getQualifier() = system and
    systemConsole.getMethod().getName() = "console" and
    result.getMethod().getName() = "readLine" and
    result.getQualifier() = systemConsole
  )
}

module SqliFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // System.console().readLine();
    exists(MethodCall read |
      read.getMethod().getName() = "readLine" and
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
