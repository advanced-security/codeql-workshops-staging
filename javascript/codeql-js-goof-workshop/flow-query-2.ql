import javascript


// 1. The sink is any argumnent[i], i >= 1, to  _.merge(message, req.body.message,...)
predicate mergeCallArg(MethodCallExpr call, Expr sink) {
    // Identify the call
    call.getReceiver().toString() =  "_" and
    call.getMethodName() = "merge"
    // Pick any argument -- even the first, although not quite correct
    and  call.getAnArgument() = sink
}
select 1

// 2. The source 

// 3. Local flow between the source and sink

