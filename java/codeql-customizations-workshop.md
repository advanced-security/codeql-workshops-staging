# Adding to Customizations example

## Setup and sample run

The **prerequisite** for this workshop is the `java/codeql-dataflow-sql-injection/` also located in this repository, which centers around detecting a potential SQL Injection vulnerability in a small Java database interaction application.

Now that we have used the query developed in the previous workshop, lets see if there is a pre-existing query that can detect the same vulnerability.

Navigate to the `SQLTainted.ql` query and run it. 

To find that file locally use one of the following:

  1) If you are using a [CodeQL bundle](https://github.com/github/codeql-action/releases), this can be found via a search like:
`find <location-of-bundle> -name "SQLTainted.ql"`.

  2) If you are using the [installed packs](https://github.com/orgs/codeql/packages/container/package/java-all) (obtained via Install Pack Dependencies), then the location of the query will be under `~/.codeql/packages/codeql/java-all/`  or  `C:\Users\<username>\.codeql\packages\codeql\java-all\`

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
private import semmle.code.java.dataflow.FlowSources
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

# Model Editor Alternative Technique

[CodeQL Model Editor](https://docs.github.com/en/code-security/codeql-for-vs-code/using-the-advanced-functionality-of-the-codeql-for-vs-code-extension/using-the-codeql-model-editor) can be used when an out of the box CodeQL needs a customization. Currently (as of June 2024) supported customizations via the Model Editor are sources and sinks. The Model Editor will generate [CodeQL model packs](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/creating-and-working-with-codeql-packs#creating-a-codeql-model-pack) which can get added to any analysis at scan runtime.

## Setup the example for `readLine`

As a sample, we want to add the `Console.io.readLine` call to the `RemoteFlowSource` concept, like we did above, and get it to be picked up in the out of the box scans. To accomplish this, **clear any previous changes** in the `Customizations.qll` file to get a fresh start on no customization currently added to `RemoteFlowSource`.

This should reset the results of the `SqlTainted.ql` query to return nothing.

Then double check if there are any out of the box models for `Console.io.readLine` already exist (as of June 2024 [there are](https://github.com/github/codeql/blob/main/java/ql/lib/ext/generated/java.io.model.ym). We want to temporarily remove those **just for demonstration purposes**. 
To do that check:

 1) If you are using a [CodeQL bundle](https://github.com/github/codeql-action/releases), these models can be found locally via a search like:
`grep -R "readLine" <location-of-bundle> | grep "Console" | sort --unique | grep ".yml" | grep "java"`

 2) If you are using the [installed packs](https://github.com/orgs/codeql/packages/container/package/java-all) (obtained via Install Pack Dependencies), then the location of the model will be under `~/.codeql/packages/codeql/java-queries/<some-version>/.codeql/libraries/codeql/java-all/<some-other-version>/ext/generated/java.io.model.yml`.

Once that file is open, remove any lines containing the `java.io.Console.readLine` signature.

## Open the Model Editor

In the QL widget selection, there is a panel labelled "CODEQL METHOD MODELING". Select "Start Modeling". It should open a central panel that shows a display saying that some % of the Java Runtime is modelled (but not 100%). Expanding the Java Runtime panel should show `java.io.Console.readLine()` as a model-able option.

## Model the API

Select Model Type -> "Source" and Kind -> "remote" and then click "Save". This will generate the model pack in the `.github` folder. Take some time to explore that directory and the model pack.

## Enable testing with the model

To [test the model in the editor](https://docs.github.com/en/code-security/codeql-for-vs-code/using-the-advanced-functionality-of-the-codeql-for-vs-code-extension/using-the-codeql-model-editor#testing-codeql-model-packs-in-vs-code), an enable setting must be added to the VSCode settings. Open the `.vscode/settings.json` file and add this line: `"codeQL.runningQueries.useExtensionPacks": "all"`.

## Utilize the model in a test

Create the following sample query to perform a quick test that the model has been succesfully configured and added to a scan:

example.ql
```
import java
import semmle.code.java.dataflow.FlowSources

from RemoteFlowSource r
select r
```

The results of this should now show the `readLine` call!

## Utilize the model in the out of the box query

Open the `SqlTainted.ql` query again and the run it. The results should now show a path through our sample vulnerable application!