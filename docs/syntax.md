# Syntax of `// gomodjail:...` comments

e.g.,
```go-module
// gomodjail:confined
module example.com/foo

go 1.23

require (
        example.com/mod100 v1.2.3
        example.com/mod101 v1.2.3 // gomodjail:unconfined
        example.com/mod102 v1.2.3
        // gomodjail:unconfined
        example.com/mod103 v1.2.3
)

require (
        // gomodjail:unconfined
        example.com/mod200 v1.2.3 // indirect
        example.com/mod201 v1.2.3 // indirect
)

// policy cannot be specified here because the parser ignores
// the comment lines here
require (
)
```

This makes the following modules confined: `mod100`, `mod102`, and `mod201`.

The version numbers are ignored.
