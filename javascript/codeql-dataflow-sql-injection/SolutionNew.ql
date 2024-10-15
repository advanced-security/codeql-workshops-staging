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

class SqliteDatabaseInit extends DataFlow::SourceNode {
  SqliteDatabaseInit() {
    this =
      API::moduleImport("sqlite3")
          .getMember("verbose")
          .getACall()
          .getAConstructorInvocation("Database")
  }
}

private DataFlow::SourceNode sqliteDatabase(DataFlow::TypeTracker t) {
  t.start() and
  exists(SqliteDatabaseInit sqliteDatabaseInit | result = sqliteDatabaseInit)
  or
  exists(DataFlow::TypeTracker t2 | result = sqliteDatabase(t2).track(t2, t))
}

DataFlow::SourceNode sqliteDatabase() { result = sqliteDatabase(DataFlow::TypeTracker::end()) }

class SqlInjectionConfiguration extends TaintTracking::Configuration {
  SqlInjectionConfiguration() { this = "SQL Injection with SQLite3" }

  override predicate isSource(DataFlow::Node source) { source instanceof ReadFileSyncCall }

  override predicate isSink(DataFlow::Node sink) { sink = sqliteDatabase().getAMethodCall("exec") }
}

from SqlInjectionConfiguration config, DataFlow::PathNode start, DataFlow::PathNode end
where config.hasFlowPath(start, end)
select end, start, end, "Sql injection from $@", start, "here"
