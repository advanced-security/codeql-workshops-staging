/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind problem
 * @id java/introworkshop
 * @problem.severity warning
 */

import java

predicate isReadLine(MethodCall read) {
  read.getMethod().getName() = "readLine"
}

predicate isExecuteUpdate(MethodCall exec) {
  exec.getMethod().getName() = "executeUpdate"
}

from MethodCall exec
where isExecuteUpdate(exec)
select exec, "Call to executeUpdate"

