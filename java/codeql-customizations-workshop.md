# Adding to Customizations example

## Setup and sample run

The **prerequisite** for this workshop is the `java/codeql-dataflow-sql-injection/` also located in this repository, which centers around detecting a potential SQL Injection vulnerability in a small Java database interaction application.

Now that we have used the query developed in the previous workshop, lets see if there is a pre-existing query that can detect the same vulnerability.

Navigate to the `SQLTainted.ql` query and run it. 

## Identify the problem

Determine if the query detects the following source and sink (again from the previous workshop) using the *Quick Evaluation* feature in the editor:

source: 
```
System.console().readLine();
```
sink:
```
conn.createStatement().executeUpdate(query);
```

## Investigate the Implementation

Its time to look at the query file and libraries responsible for the implementation. Use the *Go to Definition* feature of the editor to investigate the `QueryInjectionSink` class used in the query and the `queryTaintedBy` predicate. 

Also look at the definition of the `RemoteFlowSource` class and take this time to discuss [*Abstract* classes](https://codeql.github.com/docs/ql-language-reference/types/#abstract-classes).

Take some time to investigate the differences between *abstract* and *nonabstract* classes using a generic example:
```
abstract class A extends string {
     A() { this = ["A", "B", "C"] }
   }
  
   class B extends A { B() { this = "B" } }
  
   class C extends A { C() { this = "C" } }

from A a 
select a
```
versus:
```
class A extends string {
     A() { this = ["A", "B", "C"] }
   }
  
   class B extends A { B() { this = "B" } }
  
   class C extends A { C() { this = "C" } }

from A a 
select a
```
(attribution: this example was created by @smowton)

## Add to the Implementation

Now that we understand the reason that `SQLTainted.ql` does not detect the potential SQL Injection vulnerability (it does not model the source), we will add to the `Customizations.qll` file which acts as a query extension interface. This will allow `SQLTainted.ql` to detect the vulnerability.

First determine which import will be required to access the abstract class that we will need to extend:

```
import semmle.code.java.dataflow.FlowSources
```

Then add a custom class that models the
`System.console().readLine()` call:

```
class ReadLineFlowSource extends RemoteFlowSource {
    ReadLineFlowSource() { 
        exists(MethodAccess read |
            read.getCallee().hasName("readLine") and
            this.asExpr() = read
        )
     }
  
    override string getSourceType() { result = "readLine source" }
  }
```

Now when we run `SQLTainted.ql` we will detect the same vulnerability that is detected by the end of the `java/codeql-dataflow-sql-injection/` workshop.

## Additional practice

Now we can also see what it would be like to add an additional sink to the `Customizations.qll` file. While the following doesn't apply for the particular rule `SQLTainted.ql`, we can just use this as an exercise for practice.

We will now take the time to add a model for the `System.err.printf("Sent: %s", query)` call, as a sink in the application.

```
import semmle.code.java.security.QueryInjection

  class PrintfSink extends QueryInjectionSink { 
    PrintfSink(){
        exists(MethodAccess  printf |
            printf.getCallee().hasName("printf")
            and this.asExpr() = printf.getAnArgument()
            )
    }
  }
```

We should now get 2 `path-problem` results when we run `SQLTainted.ql` and we should be familiar with adding custom sources and sinks to `Customizations.qll` to extend the pre-existing queries.