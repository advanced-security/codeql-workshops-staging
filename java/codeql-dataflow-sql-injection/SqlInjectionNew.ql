/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind problem
 * @id java/introworkshop
 * @problem.severity warning
 */

import java

/*
 *  A MethodCall is considered as readLine if:
 *    - The method called by it has a name called "readLine".
 */

// predicate isReadLine(MethodCall methodCall) { methodCall.getMethod().getName() = "readLine" }

predicate isExecuteUpdate(Expr argument) {
  exists(MethodCall methodCall |  // <= projection 
    /* selection */
    methodCall.getMethod().getName() = "executeUpdate" and
    methodCall.getArgument(0) = argument
  )
}

predicate isExecuteUpdateNew(Expr argument, MethodCall methodCall) {
  methodCall.getMethod().getName() = "executeUpdate" and
  methodCall.getArgument(0) = argument
}

from MethodCall methodCall
where isExecuteUpdate(methodCall)
select methodCall, "ExecuteUpdate!"
