/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind problem
 * @id python/SQLIVulnerable
 * @problem.severity warning
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking


module MyFlowConfiguration implements DataFlow::ConfigSig {

    predicate isSource(DataFlow::Node source) { any() }

    predicate isSanitizer(DataFlow::Node sanitizer) { none() }

    predicate isAdditionalTaintStep(DataFlow::Node into, DataFlow::Node out) { none() }

    predicate isSink(DataFlow::Node sink) {any() }
}

module MyFlow = TaintTracking::Global<MyFlowConfiguration>;
import MyFlow::PathGraph

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink, source, sink, "Possible SQL injection"

