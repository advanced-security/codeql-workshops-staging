/**
 * @id javascript/sqlite-sql-injection
 * @kind path-problem
 * @problem.severity error
 */

import javascript

class ReadFileSyncCall extends API::CallNode {
  ReadFileSyncCall() {
    this =
      API::moduleImport("fs")          // 1. describes require("fs") 
          .getMember("readFileSync")   // 2. describes require("fs").readFileSync
          .getACall()                  // 3. describes require("fs").readFileSync()
  }
}

module SqlInjectionConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ReadFileSyncCall  // Since ReadFileSyncCall is already a DataFlow::Node, directly use it without converting it into an `Expr`.
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof ReadFileSyncCall
  }
}

import TaintTracking::Global<SqlInjectionConfiguration> as SqlInjectionFlow
import SqlInjectionFlow::PathGraph

from SqlInjectionFlow::PathNode start, SqlInjectionFlow::PathNode end
where SqlInjectionFlow::flowPath(start, end)
select end, start, end, "Sql injection from $@", start, "here"

