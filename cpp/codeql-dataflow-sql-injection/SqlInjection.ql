/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id cpp/sqlivulnerable
 * @problem.severity warning
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

module SqliFlowConfig implements DataFlow::ConfigSig {

    predicate isSource(DataFlow::Node source) {
        // count = read(STDIN_FILENO, buf, BUFSIZE);
        exists(FunctionCall read |
            read.getTarget().getName() = "read" and
            read.getArgument(1) = source.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr()
        )
    }

    predicate isBarrier(DataFlow::Node sanitizer) { none() }

    predicate isAdditionalFlowStep(DataFlow::Node into, DataFlow::Node out) {
        // Extra taint step
        //     snprintf(query, bufsize, "INSERT INTO users VALUES (%d, '%s')", id, info);
        // But snprintf is a macro on mac os.  The actual function's name is
        //     #undef snprintf
        //     #define snprintf(str, len, ...) \
        //       __builtin___snprintf_chk (str, len, 0, __darwin_obsz(str), __VA_ARGS__)
        //     #endif
        exists(FunctionCall printf |
            printf.getTarget().getName().matches("%snprintf%") and
            printf.getArgument(0) = out.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr() and
            // very specific: shifted index for macro.
            printf.getArgument(6) = into.asExpr()
        )
    }

    predicate isSink(DataFlow::Node sink) {
        // rc = sqlite3_exec(db, query, NULL, 0, &zErrMsg);
        exists(FunctionCall exec |
            exec.getTarget().getName() = "sqlite3_exec" and
            exec.getArgument(1) = sink.asExpr()
        )
    }
}

module MyFlow = TaintTracking::Global<SqliFlowConfig>;
import MyFlow::PathGraph

from  MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink, source, sink, "Possible SQL injection"
