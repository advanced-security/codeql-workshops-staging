/**
 * @id javascript/sqlite-sql-injection
 * @kind path-problem
 * @problem.severity error
 */

import javascript

class ReadFileSyncCall extends API::CallNode {
  ReadFileSyncCall() { this = API::moduleImport("fs").getMember("readFileSync").getACall() }
}

class SqliteCall extends DataFlow::SourceNode {
  SqliteCall() {
    this =
      API::moduleImport("sqlite3")
          .getMember("verbose")
          .getACall()
          .getAConstructorInvocation("Database")
  }
}

// Ultimate sink
// ----------------
//     db.exec(query);
Expr uSink(ExecCall exec) { result = exec.getArgument(0) }

class DatabaseNew extends DataFlow::InvokeNode {
  DatabaseNew() { this.getCalleeName() = "Database" }
}

class ExecCall extends MethodCallExpr {
  ExecCall() { this.getMethodName() = "exec" }
}

module IdentifyFlowSink implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node nd) {
    //     const db = new sqlite3.Database(
    nd instanceof SqliteCall
  }

  predicate isSink(DataFlow::Node nd) {
    //     db.exec(query);
    exists(Expr db, ExecCall exec |
      db = exec.getReceiver() and
      nd.asExpr() = db
    )
  }
}

module UltimateFlowCfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node nd) { exists(ReadFileSyncCall r | nd = r) }

  predicate isSink(DataFlow::Node nd) { nd.asExpr() = uSink(_) }
}

import DataFlow::Global<IdentifyFlowSink> as IdentityFlow
import TaintTracking::Global<UltimateFlowCfg> as UltimateFlow

import UltimateFlow::PathGraph

from
  UltimateFlow::PathNode usource, UltimateFlow::PathNode usink,
  DataFlow::Node source, DataFlow::Node sink
where
  IdentityFlow::flow(source, sink) and
  UltimateFlow::flowPath(usource, usink) and
  exists(ExecCall exec |
    sink.asExpr() = exec.getReceiver() and
    usink.getNode().asExpr() = exec.getAnArgument()
  )
select usink, usource, usink, "Sql injected from $@", usource, "here"
