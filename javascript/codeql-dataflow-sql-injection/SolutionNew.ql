/**
 * @id javascript/sqlite-sql-injection
 * @kind path-problem
 * @problem.severity error
 */

import javascript
import DataFlow::PathGraph

/* 1. Source of the vulnerability. */
class ReadFileSyncCall extends API::CallNode {
  ReadFileSyncCall() { this =
     API::moduleImport("fs")
         .getMember("readFileSync")
         .getACall() 
  }
}

/* 2. Sink of the vulnerability. */
class SqliteDatabaseInit extends DataFlow::SourceNode {
  SqliteDatabaseInit() {
    this =
      API::moduleImport("sqlite3")
          .getMember("verbose")
          .getACall()
          .getAConstructorInvocation("Database")
  }
}

/* 3. Sink of the vulnerability, generalized. */
private DataFlow::SourceNode sqliteDatabaseGeneralized(DataFlow::TypeTracker t) {
  t.start() and
  result instanceof SqliteDatabaseInit
  or
  exists(DataFlow::TypeTracker t2 | result = sqliteDatabaseGeneralized(t2).track(t2, t))
}

DataFlow::SourceNode sqliteDatabaseGeneralized() {
  result = sqliteDatabaseGeneralized(DataFlow::TypeTracker::end())
}

class SqlInjectionConfiguration extends TaintTracking::Configuration {
  SqlInjectionConfiguration() { this = "SQL Injection with SQLite3" }

  override predicate isSource(DataFlow::Node source) { source instanceof ReadFileSyncCall }

  override predicate isSink(DataFlow::Node sink) {
    sink = sqliteDatabaseGeneralized().getAMethodCall("exec")
  }
}

from SqlInjectionConfiguration config, DataFlow::PathNode start, DataFlow::PathNode end
where config.hasFlowPath(start, end)
select end, start, end, "Sql injection from $@", start, "here"
