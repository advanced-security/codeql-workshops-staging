/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind problem
 * @id java/introworkshop
 * @problem.severity warning
 */

import java

from MethodCall read
where read.getMethod().getName() = "readLine"
select read, "Call to readLine"