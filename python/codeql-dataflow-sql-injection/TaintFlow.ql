/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind problem
 * @id python/SQLIVulnerable
 * @problem.severity warning
 */

 import python
 import semmle.python.ApiGraphs
 import semmle.python.dataflow.new.TaintTracking
 
 predicate isSource1(DataFlow::Node source) {
     API::moduleImport("builtins").getMember("input").getACall() = source
 }
 
 
 predicate isSink(Call call, DataFlow::Node dfsink) {
     call.getFunc().(Attribute).getName() = "executescript" and
     dfsink.asExpr() = call.getArg(0)
 }
 
 module MyFlowConfiguration implements DataFlow::ConfigSig {
 
     predicate isSource(DataFlow::Node source) { isSource1(source) }
 
     predicate isSanitizer(DataFlow::Node sanitizer) { none() }
 
     predicate isAdditionalTaintStep(DataFlow::Node into, DataFlow::Node out) { none() }
 
     predicate isSink(DataFlow::Node sink) {isSink(_, sink) }
 }
 
 module MyFlow = TaintTracking::Global<MyFlowConfiguration>;
 
 from DataFlow::Node source, DataFlow::Node sink
 where MyFlow::flow(source, sink)
 select sink, "Possible SQL injection"
 