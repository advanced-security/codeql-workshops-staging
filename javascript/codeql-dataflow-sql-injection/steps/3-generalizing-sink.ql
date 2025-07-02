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

class SqliteDatabaseInit extends DataFlow::SourceNode {
  SqliteDatabaseInit() {
    this =
      API::moduleImport("sqlite3")                // 1. describes require("sqlite3")
          .getMember("verbose")                   // 2. describes require("sqlite3").verbose
          .getACall()                             // 3. describes require("sqlite3").verbose()
          .getAConstructorInvocation("Database")  // 4. describes new require("sqlite3").verbose().Database()
  }
}

/* =================== !!! WARNING BOILERPLATE CODE INCOMING !!! ======================= */
private DataFlow::SourceNode sqliteDatabaseInitGeneralized(DataFlow::TypeTracker t) {
  t.start() and
  /* ========== Put the thing we want to generalize here; else is boilerplate ========== */
  result instanceof SqliteDatabaseInit
  /*==================================================================================== */
  or
  exists(DataFlow::TypeTracker t2 | result = sqliteDatabaseInitGeneralized(t2).track(t2, t))
}

private DataFlow::SourceNode sqliteDatabaseInitGeneralized() {
  result = sqliteDatabaseInitGeneralized(DataFlow::TypeTracker::end())
}
/* =================== !!! WARNING BOILERPLATE CODE INCOMING !!! ======================= */

module SqlInjectionConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ReadFileSyncCall  // Since ReadFileSyncCall is already a DataFlow::Node, directly use it without converting it into an `Expr`.
  }

  predicate isSink(DataFlow::Node sink) {
    sink = sqliteDatabaseInitGeneralized().getAMethodCall("exec")  // Now it should work.
  }
}

import TaintTracking::Global<SqlInjectionConfiguration> as SqlInjectionFlow
import SqlInjectionFlow::PathGraph

from SqlInjectionFlow::PathNode start, SqlInjectionFlow::PathNode end
where SqlInjectionFlow::flowPath(start, end)
select end, start, end, "Sql injection from $@", start, "here"
