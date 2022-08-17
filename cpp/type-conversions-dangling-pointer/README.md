# CodeQL C/C++ Vulnerabilities

## Type Conversion Vulnerabilities

Most security related type conversion issues are implicit conversion from *signed integers* to *unsigned integers*. When a *signed integer* is converted to an *unsigned integer* of the same size then the underlying *bit-pattern* remains the same, but the value is potentially interpreted differently. The opposite conversion is *implementation defined*, but typically follows the same implementation of leaving the underlying *bit-pattern* unchanged. 

### Type conversions in CodeQL

In CodeQL all conversions are modeled by the class [`Conversion`](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/exprs/Cast.qll/type.Cast$Conversion.html) and its sub-classes. 

### Signed to unsigned

The implicit conversion becomes relevant in function calls such as in the following example where there is an implicit conversion from `int` to `size_t` (defined as `unsigned int`).

```cpp
int get_len(int fd);
void buffer_overflow(int fd) {
	int len;
	char buf[128];

	len = get_input(fd);
	if (len > 128) {
		return;
	}

	read(fd, buf, len);
}
```

In the following exercise we are going to implement a basic query to find the above problematic implicit conversion.
Why does the conversion pose a security risk?

#### Exercise 1

Create the two classes `SignedInt` and `UnsignedInt` that represent their respective `IntType` types.

##### Solution

```ql
class SignedInt extends IntType {
	SignedInt() {
		this.isSigned()
	}
}

class UnsignedInt extends IntType {
  UnsignedInt() {
    this.isUnsigned()
  }
}
```

#### Exercise 2

In the case of `signed int` to `unsiged int` conversions we are interested in the conversion [`IntegeralConversion`](https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/exprs/Cast.qll/type.Cast$IntegralConversion.html) class that models *implicit* and *explicit* conversions from one integral type to another. 

Create the class `SignedToUnsignedConversion` that models a `signed int` to `unsigned int` conversion. Use the classes `SignedInt` and `UnsignedInt` defined in exercise 1.

##### Solution

```ql
class SignedToUnsignedConversion extends IntegralConversion {
  SignedToUnsignedConversion() {
    this.getExpr().getUnderlyingType() instanceof SignedInt and
    this.getUnderlyingType() instanceof UnsignedInt
  }
}
```


#### Exercise 3

Now that we have modeled the `signed int` to `unsigned int` conversion write a query that find the vulnerable conversion.

##### Solution

Note that this solution uses a `VariableAccess` as an argument of the call. This excludes direct uses of literal values.

```ql
import cpp

class SignedInt extends IntType {
	SignedInt() {
		this.isSigned()
	}
}

class UnsignedInt extends IntType {
	UnsignedInt() {
		this.isUnsigned()
	}
}

class SignedToUnsignedConversion extends IntegralConversion {
  SignedToUnsignedConversion() {
    this.getExpr().getUnderlyingType() instanceof SignedInt and
    this.getUnderlyingType() instanceof UnsignedInt
  }
}

from FunctionCall call, VariableAccess arg
where call.getAnArgument() = arg and arg.getConversion() instanceof SignedToUnsignedConversion
select call, arg
```

An alternative solution is

```ql
import cpp

from FunctionCall call, int idx, Expr arg
where call.getArgument(idx) = arg and arg.getUnspecifiedType().(IntType).isSigned() and not arg.isConstant() and
call.getTarget().getParameter(idx).getUnspecifiedType().(IntType).isUnsigned()
select call, arg
```

#### Exercise 4

On a real-world database our current query provides a lot of results so it is key to turning this into a manageable list that can be audited.
Implement heuristics that can meaningfully reduce the list of results.

##### Solution

One option is to restrict the set of parameters we want to consider by constraining them on a property. Given the specific example we can look at parameters that represent a length or size. We can try the following two heuristics:

1. Look for parameters containing the sub-string `len` or `size`.
2. Look for parameters of type `size_t`.

```ql
import cpp

class SignedInt extends IntType {
	SignedInt() {
		this.isSigned()
	}
}

class UnsignedInt extends IntType {
	UnsignedInt() {
		this.isUnsigned()
	}
}

class SignedToUnsignedConversion extends IntegralConversion {
  SignedToUnsignedConversion() {
    this.getExpr().getUnderlyingType() instanceof SignedInt and
    this.getUnderlyingType() instanceof UnsignedInt
  }
}

from FunctionCall call, VariableAccess arg
where call.getAnArgument() = arg and arg.getConversion() instanceof SignedToUnsignedConversion
select call, arg

predicate isPossibleSizeParameter(Parameter p) {
  p.getName().toLowerCase().matches("%len%")
  or
  p.getName().toLowerCase().matches("%size%")
}

from FunctionCall call, int idx, Expr arg, Parameter p
where call.getArgument(idx) = arg and not arg.isConstant() and arg.getConversion() instanceof SignedToUnsignedConversion and
p = call.getTarget().getParameter(idx) and isPossibleSizeParameter(p)
select call, arg
```

```ql
import cpp

class SignedInt extends IntType {
	SignedInt() {
		this.isSigned()
	}
}

class UnsignedInt extends IntType {
	UnsignedInt() {
		this.isUnsigned()
	}
}

class SignedToUnsignedConversion extends IntegralConversion {
  SignedToUnsignedConversion() {
    this.getExpr().getUnderlyingType() instanceof SignedInt and
    this.getUnderlyingType() instanceof UnsignedInt
  }
}

from FunctionCall call, VariableAccess arg
where call.getAnArgument() = arg and arg.getConversion() instanceof SignedToUnsignedConversion
select call, arg

predicate isSizeTParameter(Parameter p) {
  p.getType().getName() = "size_t" 
}

from FunctionCall call, int idx, Expr arg, Parameter p
where call.getArgument(idx) = arg and not arg.isConstant() and arg.getConversion() instanceof SignedToUnsignedConversion and
p = call.getTarget().getParameter(idx) and isSizeTParameter(p)
select call, arg
```

What else can be done to further reduce the set of results?

1. Determining if the size can be influenced by an attacker through taint tracking.
2. Limit the called function to a list of known interesting functions (e.g., `memcpy`, `read`).
3. Determine if the parameter is part of an array index or pointer computation.

### Unsigned to signed

In the opposite direction unsigned to signed conversion can result in [out of bounds access]( https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33909) when the signed value is used in a pointer computation.

Consider the following example:

```cpp
char* out_of_bounds(char * c, int n) {
	char * ptr = c + n;
	return ptr;
}

#define INT_MAX 2147483648

int main(void) {
	unsigned int n = INT_MAX + 1;

	char buf[1024];

	char *ptr = out_of_bounds(buf, n);

}
```

The variable `n` can range from `-2147483648` to `2147483648` (assuming 32-bit integers). Passing an unsigned integer, which can range from `0` to `4294967296`, to a call to `out_of_bounds` can result in a pointer that is out of bound because `n` can become negative.

In the following exercises we are going to write a query to find the above vulnerable case.

#### Exercise 1

Write the class `UnsignedToSigned` that identifies conversions from `unsigned int` to `signed int`.

##### Solution

```ql
import cpp

class SignedInt extends IntType {
	SignedInt() {
		this.isSigned()
	}
}

class UnsignedInt extends IntType {
	UnsignedInt() {
		this.isUnsigned()
	}
}

class UnsignedToSigned extends IntegralConversion {
  UnsignedToSigned() {
    this.getExpr().getUnderlyingType() instanceof UnsignedInt and
    this.getUnderlyingType() instanceof SignedInt
  }
}

```

### Exercise 2

The second requirement for the vulnerable case is the participation in a computation that results in a pointer.
Complete the query by establishing that the parameter `n` is used to compute a pointer.

#### Hints

1. Pointer arithmetic operations are modeled by the class `PointerArithmeticOperation`.
2. Dataflow analysis can help with determining if a value is used somewhere. For local dataflow analysis you can use `DataFlow::localFlow`
3. The dataflow library provides helper predicates such as `DataFlow::parameterNode` and `DataFlow::exprNode` to relate AST elements to their dataflow graph counterparts.

#### Solution

```ql
import cpp
import semmle.code.cpp.dataflow.DataFlow

class SignedInt extends IntType {
	SignedInt() {
		this.isSigned()
	}
}

class UnsignedInt extends IntType {
	UnsignedInt() {
		this.isUnsigned()
	}
}

class UnsignedToSigned extends IntegralConversion {
  UnsignedToSigned() {
    this.getExpr().getUnderlyingType() instanceof UnsignedInt and
    this.getUnderlyingType() instanceof SignedInt
  }
}

from FunctionCall call, int idx, Expr arg, Parameter p, PointerArithmeticOperation op
where
  call.getArgument(idx) = arg and
  arg.getConversion() instanceof UnsignedToSigned and
  p = call.getTarget().getParameter(idx) and
  DataFlow::localFlow(DataFlow::parameterNode(p), DataFlow::exprNode(op.getAnOperand()))
select call, op, p
```

## Dangling pointers

A dangling pointer is a memory safety violation where the pointer does not point to a valid object.
These dangling pointers are the result of not modifying the value of the pointer after the pointed to object is destructed or not properly initializing the pointer.

The use of a dangling pointer can result in a security issue. Specifically in C++ if the pointer is used to invoke a *virtual* method and an attacker was able to overwrite the parts of the memory that would have contained the `vtable` of the object.

The following snippet shows how a dangling pointer can occur.

```cpp

void dangling_pointer() {
	char **p = nullptr;
	{
		char * s = "hello world";
		p = &s;
	}
	printf("%s", *p);
}

```

A less obvious case is

```cpp
void dangling_pointer() {
	std::string_view s = "hello world"s;
	std::cout << s << std::endl;
}
```

After the full expression is evaluated, the temporary object is destroyed.

Many more interesting examples discussed here https://herbsutter.com/2018/09/20/lifetime-profile-v1-0-posted/

To find these issues we can implement an analysis that tracks lifetimes. A nice specification for a local lifetime analysis is given by https://github.com/isocpp/CppCoreGuidelines/blob/master/docs/Lifetime.pdf

The gist of the analysis is to track for each local variable the things it can point to at a particular location in the program. These are other local variables and special values for global variables, null values, and invalid values. Whenever a variable goes out of scope, each reference to that variable in a points-to set is invalidated.

In the next few exercises, we are going to implement a simplified version of the lifetime profile to find the dangling pointer in the following example:

```cpp
extern void printf(char *, ...);

void simple_dangling_pointer() {
  char **p;
  {
    char *s = "hello world!";
    p = &s;
  }
  printf("%s", *p);
  char *s = "hello world!";
  p = &s;
  printf("%s", *p);
  return;
}
```

The simplified version will track 3 possible *points-to* values.

1. Variable; A pointer points to another pointer. We will only consider local variables represented by the class `LocalVariable`.
2. Invalid; A pointer is not initialized or points to a variable that went out of scope.
3. Unknown; A pointer is assigned something other than the address of another `LocalVariable` (e.g., the address of a string.).

### Exercise 1

In the first exercise we are going to model the entries of the *points-to* set that we are going to associated with pointers at locations in the program.
Implement the [algebraic datatype](https://codeql.github.com/docs/ql-language-reference/types/#algebraic-datatypes) `PSetEntry` that represents the possible entries of our *points-to* set with the three values listed above.

Note that to be able to represent the *invalid* value we need to implement another *algebraic datatype* for the two possible values. You can use the following definition. Besides the `newtype` we define a `class` that extends from the *algebraic datatype*. This is a [standard pattern](https://codeql.github.com/docs/ql-language-reference/types/#standard-pattern-for-using-algebraic-datatypes) that allows us to associate a convenient `toString` member predicate that we will use to print the invalid reason.

```ql
newtype TInvalidReason =
  TUninitialized(DeclStmt ds, LocalVariable lv) { ds.getADeclaration() = lv } or
  TVariableOutOfScope(LocalVariable lv, ControlFlowNode cfn) { goesOutOfScope(lv, cfn) }

class InvalidReason extends TInvalidReason {
  string toString() {
    exists(DeclStmt ds, LocalVariable lv |
      this = TUninitialized(ds, lv) and
      result = "variable " + lv.getName() + " is unitialized."
    )
    or
    exists(LocalVariable lv, ControlFlowNode cfn |
      this = TVariableOutOfScope(lv, n) and
      result = "variable " + lv.getName() + " went out of scope."
    )
  }
}
```

The type `TInvalidReason` creates a user-defined type with values that are neither *primitive* values nor *entities* for database. Each of two values represent an invalid *points-to* value. The case when a pointer is not initialized or pointing to a pointer that is out of scope.

The `TVariableOutOfScope` branch associates a new value of the branch type to the pair `(LocalVariable, ControlFlowNode)` if the local variable goes out of scope at that point in the program. The predicate `goesOutOfScope` has the following definition that you can use.

```ql
predicate goesOutOfScope(LocalVariable lv, ControlFlowNode cfn) {
  exists(BlockStmt scope |
    scope = lv.getParentScope() and
    if exists(scope.getFollowingStmt()) 
	then scope.getFollowingStmt() = cfn 
	else cfn = scope
  )
}
```

#### Solution

Like the `TInvalidReason` type we model the `TPSetEntry` type as follows.

```ql
newtype TPSetEntry =
  PSetVar(LocalVariable lv) or
  PSetInvalid(InvalidReason ir) or
  PSetUnknown()

class PSetEntry extends TPSetEntry {
  string toString() {
    exists(LocalVariable lv |
      this = PSetVar(lv) and
      result = "Var(" + lv.toString() + ")"
    )
    or
    this = PSetUnknown() and result = "Unknown"
    or
    exists(InvalidReason ir |
      this = PSetInvalid(ir) and
      result = "Invalid because " + ir.toString()
    )
  }
}
```

### Exercise 2

With the *points-to* set entries modeled we can start to implement parts of our *points-to* set that will associate *points-to* set entries to local variables at a program location. That map will be implemented by the predicate `pointsToMap`.

The following snippet shows the skeleton of that predicate.

```ql
predicate pointsToMap(ControlFlowNode cfn, LocalVariable lv, PSEntry pse) {
}
```

In this predicate we must consider three cases:

1. The local variable `lv` is assigned a value at location `cfn` that defines the *points-to* set entry `pse`.
2. The local local variable `lv` is not assigned so we have to propagate the *points-to* set entry from a previous location.
3. The local variable `lv` is not assigned, but points to a variable that went out of scope at location `cfn` so we need to invalid the entry for that variable.

In this exercise we are going to implement the first case by implementing the two predicates `isPSetReassigned` and `getAnAssignedPSetEntry`.

- The predicate `isPSetReassigned` should hold if a new *points-to* entry should be assigned at that location. This happens when:
	- A local variable is declared and is uninitialized.
	- A local variable is assigned a value.
- The predicate `getAnAssignedPSEntry` should relate a program location and variable to a *points-to* entry.

The following snippet provides the skeleton that needs to be completed.

```ql
predicate pointsToMap(ControlFlowNode cfn, LocalVariable lv, PSEntry pse) {
	if isPSetReassigned(cfn, lv)
	then pse = getAnAssignedPSetEntry(cfn, lv)
	else
		...
}

predicate isPSetReassigned(ControlFlowNode cfn, LocalVariable lv) {
	
}

PSEntry getAnAssignedPSetEntry(ControlFlowNode cfn, LocalVariable lv) {
	
}
```

#### Hints

1. The class `DeclStmt` models a declaration statement and the predicate `getADeclaration` relates what is declared (e.g., a `Variable`)
2. For a `Variable` we can get the `Expr` that represent the value that is assigned to the variable with the predicate `getAnAssignedValue`.
3. The `AddressOfExpr` models address taken of operation that when assigned to a variable can be used to determine if one variable points-to another variable. 

#### Solution

The local variable `lv` get assigned a *points-to* entry when it is declared or assigned a value.

```ql
predicate isPSetReassigned(ControlFlowNode cfn, LocalVariable lv) {
  exists(DeclStmt ds |
    cfn = ds and
    ds.getADeclaration() = lv and
    lv.getType() instanceof PointerType
  )
  or
  cfn = lv.getAnAssignedValue()
}

PSEntry getAnAssignedPSetEntry(ControlFlowNode cfn, LocalVariable lv) {
  exists(DeclStmt ds |
    cfn = ds and
    ds.getADeclaration() = lv
  |
    lv.getType() instanceof PointerType and
    result = PSetInvalid(TUninitialized(ds, lv))
  )
  or
  exists(Expr assign |
    assign = lv.getAnAssignedValue() and
    cfn = assign
  |
    exists(LocalVariable v | v = assign.(AddressOfExpr).getOperand().(VariableAccess).getTarget() |
      result = PSetVar(v)
    )
    or
    exists(VariableAccess va |
      va = assign and
      va.getTarget().(LocalScopeVariable).getType() instanceof PointerType and
      pointsToMap(assign.getAPredecessor(), va.getTarget(), result)
    )
    or
    not assign instanceof AddressOfExpr and
    not assign instanceof VariableAccess and
    result = PSetUnknown()
  )
}
```

### Exercise 3

With case 1 of the `pointsToMap` being implemented we are going to implement case 2 and 3.
For case 2 we need to propagate a *points-to* entry from a previous location and for case 3 we need to invalidate a *points-to* entry if the entry at the previous location is a `PSetVar` for which the variable goes out of scope at our current location `cfn`.

Note that we only consider case 2 and case 3 if the variable doesn't go out of scope at the current location, otherwise we stop propagation for of *points-to* entries for that variable.

```ql
predicate pointsToMap(ControlFlowNode cfn, LocalVariable lv, PSEntry pse) {
	if isPSetReassigned(cfn, lv)
	then pse = getAnAssignedPSetEntry(cfn, lv)
	else
		exists(ControlFlowNode pred, PSEntry prevPse |
			pred = cfn.getAPredecessor() and
			pointsToMap(pred, lv, prevPse) and
			not goesOutOfScope(lv, cfn)
		|
			// case 2
			or
			// case 3
		)
}
```

#### Solution

```ql
predicate pointsToMap(ControlFlowNode cfn, LocalVariable lv, PSetEntry pse) {
  if isPSetReassigned(cfn, lv)
  then pse = getAnAssignedPSetEntry(cfn, lv)
  else
    exists(ControlFlowNode predCfn, PSetEntry prevPse |
      predCfn = cfn.getAPredecessor() and
      pointsToMap(predCfn, lv, prevPse) and
      not goesOutOfScope(lv, cfn)
    |
      pse = prevPse and
      not exists(LocalVariable otherLv |
        prevPse = PSetVar(otherLv) and
        goesOutOfScope(otherLv, cfn)
      )
      or
      exists(LocalVariable otherLv |
        prevPse = PSetVar(otherLv) and
        goesOutOfScope(otherLv, cfn) and
        pse = PSetInvalid(TVariableOutOfScope(otherLv, cfn))
      )
    )
}
```

### Exercise 4

With the *points-to* map implemented we can find *uses* of dangling pointers. 

Implement the class `DanglingPointerAccess` that finds uses of dangling points.

```ql
class DanglingPointerAccess extends PointerDereferenceExpr {
  DanglingPointerAccess() {
    exists(LocalVariable lv, PSetEntry pse |
      this.getOperand().(VariableAccess).getTarget() = lv and
      ...
    )
  }
}
```

#### Solution

```ql
class DanglingPointerAccess extends PointerDereferenceExpr {
  DanglingPointerAccess() {
    exists(LocalVariable lv, PSetEntry pse |
      this.getOperand().(VariableAccess).getTarget() = lv and
      pointsToMap(this, lv, pse) and
      pse = PSetInvalid(TVariableOutOfScope(_, _))
    )
  }
}
```

### Full solution

```ql
import cpp

newtype TInvalidReason =
  TUninitialized(DeclStmt ds, LocalVariable lv) { ds.getADeclaration() = lv } or
  TVariableOutOfScope(LocalVariable lv, ControlFlowNode cfn) { goesOutOfScope(lv, cfn) }

class InvalidReason extends TInvalidReason {
  string toString() {
    exists(DeclStmt ds, LocalVariable lv |
      this = TUninitialized(ds, lv) and
      result = "variable " + lv.getName() + " is unitialized."
    )
    or
    exists(LocalVariable lv, ControlFlowNode cfn |
      this = TVariableOutOfScope(lv, cfn) and
      result = "variable " + lv.getName() + " went out of scope."
    )
  }
}

newtype TPSetEntry =
  PSetVar(LocalVariable lv) or
  PSetInvalid(InvalidReason ir) or
  PSetUnknown()

class PSetEntry extends TPSetEntry {
  string toString() {
    exists(LocalVariable lv |
      this = PSetVar(lv) and
      result = "Var(" + lv.toString() + ")"
    )
    or
    this = PSetUnknown() and result = "Unknown"
    or
    exists(InvalidReason ir |
      this = PSetInvalid(ir) and
      result = "Invalid because " + ir.toString()
    )
  }
}

predicate goesOutOfScope(LocalVariable lv, ControlFlowNode cfn) {
  exists(BlockStmt scope |
    scope = lv.getParentScope() and
    if exists(scope.getFollowingStmt()) then scope.getFollowingStmt() = cfn else cfn = scope
  )
}

private predicate isPSetReassigned(ControlFlowNode cfn, LocalVariable lv) {
  exists(DeclStmt ds |
    cfn = ds and
    ds.getADeclaration() = lv and
    lv.getType() instanceof PointerType
  )
  or
  cfn = lv.getAnAssignedValue()
}

private PSetEntry getAnAssignedPSetEntry(ControlFlowNode cfn, LocalVariable lv) {
  exists(DeclStmt ds |
    cfn = ds and
    ds.getADeclaration() = lv
  |
    lv.getType() instanceof PointerType and
    result = PSetInvalid(TUninitialized(ds, lv))
  )
  or
  exists(Expr assign |
    assign = lv.getAnAssignedValue() and
    cfn = assign
  |
    exists(LocalVariable otherLv |
      otherLv = assign.(AddressOfExpr).getOperand().(VariableAccess).getTarget()
    |
      result = PSetVar(otherLv)
    )
    or
    exists(VariableAccess va |
      va = assign and
      va.getTarget().(LocalScopeVariable).getType() instanceof PointerType and
      pointsToMap(assign.getAPredecessor(), va.getTarget(), result)
    )
    or
    not assign instanceof AddressOfExpr and
    not assign instanceof VariableAccess and
    result = PSetUnknown()
  )
}

predicate pointsToMap(ControlFlowNode cfn, LocalVariable lv, PSetEntry pse) {
  if isPSetReassigned(cfn, lv)
  then pse = getAnAssignedPSetEntry(cfn, lv)
  else
    exists(ControlFlowNode predCfn, PSetEntry prevPse |
      predCfn = cfn.getAPredecessor() and
      pointsToMap(predCfn, lv, prevPse) and
      not goesOutOfScope(lv, cfn)
    |
      pse = prevPse and
      not exists(LocalVariable otherLv |
        prevPse = PSetVar(otherLv) and
        goesOutOfScope(otherLv, cfn)
      )
      or
      exists(LocalVariable otherLv |
        prevPse = PSetVar(otherLv) and
        goesOutOfScope(otherLv, cfn) and
        pse = PSetInvalid(TVariableOutOfScope(otherLv, cfn))
      )
    )
}

class DanglingPointerAccess extends PointerDereferenceExpr {
  DanglingPointerAccess() {
    exists(LocalVariable lv |
      this.getOperand().(VariableAccess).getTarget() = lv and
      pointsToMap(this, lv, PSetInvalid(TVariableOutOfScope(_, _)))
    )
  }
}

from DanglingPointerAccess dpa
select dpa

```
