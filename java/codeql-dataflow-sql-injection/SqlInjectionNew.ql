/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind problem
 * @id java/introworkshop
 * @problem.severity warning
 */

import java

from MethodCall methodCall
select methodCall, "Method call"
