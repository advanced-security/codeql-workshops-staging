# SQL injection example
## Setup and sample run

   ```
     npm i sqlite3

     node add-user.js

     ./admin  -c
     ./admin  -s

     echo frank | node add-user.js

     ./admin  -s

     echo 'Johnny"); DROP TABLE users; --' | node add-user.js

     ./admin  -s
   ```

## Identify the problem
   add-user.js is reading from standard input, and writing to a database; looking at the code in
   add-user.js leads to
   `fs.readFileSync(process.stdin.fd);`
   for the read and 
   `db.exec(query);`
   for the write.

   This problem is thus a dataflow problem; in codeql terminology we have
   - a /source/ at the `fs.readFileSync(process.stdin.fd);`
   - a /sink/ at the `db.exec(query);`

   We write codeql to identify these two, and then connect them via
   - a /dataflow configuration/ -- for this problem, the more general /taintflow
     configuration/. 
   
## Create the CodeQL database
   To get started, build the CodeQL database (adjust paths to your setup):
   ```
     # Build the db with source commit id.
     export PATH=$HOME/path-to-CodeQL-CLI-binary:"$PATH"
     SRCDIR=$(pwd)
     DB=$SRCDIR/js-sqli-$(cd $SRCDIR && git rev-parse --short HEAD)

     echo $DB
     test -d "$DB" && rm -fR "$DB"
     mkdir -p "$DB"

     cd $SRCDIR && codeql database create --language=javascript -s . -j 8 -v $DB

     # Check for add-user.js in the db
     unzip -v $DB/src.zip | grep add-user
   ```

   Then add this database directory to your VS Code `DATABASES` tab.


## Develop the query bottom-up
   1. Identify the /source/ part of the 
      : `fs.readFileSync(process.stdin.fd);`
      expression.  
      Start from a `from..where..select`, then convert to a predicate.

   2. Identify the /sink/ part of the
      `db.exec(query);`
      expression, the `query` argument.  Again start from `from..where..select`,
      then convert to a predicate.

   3. Fill in the /taintflow configuration/ boilerplate
      ```
      class FlowCfg extends TaintTracking::Configuration {
      FlowCfg() { this = "FlowCfg" }
 
      override predicate isSource(DataFlow::Node nd) { ... }
 
      override predicate isSink(DataFlow::Node nd) { ... }
      }
      ```