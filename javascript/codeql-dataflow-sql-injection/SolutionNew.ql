/**
 * @id javascript/sqlite-sql-injection
 * @kind path-problem
 * @problem.severity error
 */

import javascript

/** 1. Source of the vulnerability. */
class ReadFileSyncCall extends API::CallNode {
  ReadFileSyncCall() { this = API::moduleImport("fs").getMember("readFileSync").getACall() }
}

/** 2. Sink of the vulnerability. */
class SqliteDatabaseInit extends DataFlow::SourceNode {
  SqliteDatabaseInit() {
    this =
      API::moduleImport("sqlite3")
          .getMember("verbose")
          .getACall()
          .getAConstructorInvocation("Database")
  }
}

/** 3. Sink of the vulnerability, generalized. */
private DataFlow::SourceNode sqliteDatabaseInitGeneralized(DataFlow::TypeTracker t) {
  t.start() and
  result instanceof SqliteDatabaseInit
  or
  exists(DataFlow::TypeTracker t2 | result = sqliteDatabaseInitGeneralized(t2).track(t2, t))
}

DataFlow::SourceNode sqliteDatabaseInitGeneralized() {
  result = sqliteDatabaseInitGeneralized(DataFlow::TypeTracker::end())
}

module SqlInjectionConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ReadFileSyncCall }

  predicate isSink(DataFlow::Node sink) {
    sink = sqliteDatabaseInitGeneralized().getAMethodCall("exec")
  }
}

module SqlInjectionConfigurationFlow = TaintTracking::Global<SqlInjectionConfiguration>;

import SqlInjectionConfigurationFlow::PathGraph

from SqlInjectionConfigurationFlow::PathNode start, SqlInjectionConfigurationFlow::PathNode end
where SqlInjectionConfigurationFlow::flowPath(start, end)
select end, start, end, "Sql injection from $@", start, "here"
