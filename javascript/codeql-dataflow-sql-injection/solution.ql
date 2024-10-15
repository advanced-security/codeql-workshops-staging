/**
 * @id javascript/sqlite-sql-injection
 * @kind path-problem
 * @problem.severity error
 */

import javascript
import DataFlow::PathGraph

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

class IdentifyFlowSink extends TaintTracking::Configuration {
  IdentifyFlowSink() { this = "IdentifyFlowSink" }

  override predicate isSource(DataFlow::Node nd) {
    //     const db = new sqlite3.Database(
    nd instanceof SqliteCall
  }

  override predicate isSink(DataFlow::Node nd) {
    //     db.exec(query);
    exists(Expr db, ExecCall exec |
      db = exec.getReceiver() and
      nd.asExpr() = db
    )
  }
}

class UltimateFlowCfg extends TaintTracking::Configuration {
  UltimateFlowCfg() { this = "UltimateFlowCfg" }

  override predicate isSource(DataFlow::Node nd) { exists(ReadFileSyncCall r | nd = r) }

  override predicate isSink(DataFlow::Node nd) { nd.asExpr() = uSink(_) }
}

from
  UltimateFlowCfg ucfg, DataFlow::PathNode usource, DataFlow::PathNode usink, IdentifyFlowSink cfg,
  DataFlow::Node source, DataFlow::Node sink
where
  cfg.hasFlow(source, sink) and
  ucfg.hasFlowPath(usource, usink) and
  exists(ExecCall exec |
    sink.asExpr() = exec.getReceiver() and
    usink.getNode().asExpr() = exec.getAnArgument()
  )
select usink, usource, usink, "Sql injected from $@", usource, "here"
