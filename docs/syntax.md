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

//gomodjail:unconfined
require (
        example.com/mod300 v1.2.3
        example.com/mod301 v1.2.3 // gomodjail:confined
        example.com/mod302 v1.2.3
)
```

This makes the following modules confined: `mod100`, `mod102`, `mod201`, and `mod301`.

The version numbers are ignored.
