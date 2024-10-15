/**
 * @id javascript/sqlite-sql-injection
 * @kind path-problem
 * @problem.severity error
 */

import javascript
import DataFlow::PathGraph

class ReadFileSyncCall extends API::CallNode {
  ReadFileSyncCall() {
    this =
      API::moduleImport("fs")          // 1. describes require("fs") 
          .getMember("readFileSync")   // 2. describes require("fs").readFileSync
          .getACall()                  // 3. describes require("fs").readFileSync()
  }
}

class SqlInjectionConfiguration extends TaintTracking::Configuration {
  SqlInjectionConfiguration() { this = "SQL Injection with SQLite3" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ReadFileSyncCall  // Since ReadFileSyncCall is already a DataFlow::Node, directly use it without converting it into an `Expr`.
  }

  override predicate isSink(DataFlow::Node sink) {
    sink != sink
  }
}

from SqlInjectionConfiguration config, DataFlow::PathNode start, DataFlow::PathNode end
where config.hasFlowPath(start, end)
select end, start, end, "Sql injection from $@", start, "here"

