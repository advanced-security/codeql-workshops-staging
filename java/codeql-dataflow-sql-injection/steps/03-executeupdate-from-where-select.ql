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

from MethodCall exec
where exec.getMethod().getName() = "executeUpdate"
select exec, "Call to executeUpdate"
