(call_expression
  function: (scoped_identifier) @callee
  arguments: (arguments (_) @input)
  (#eq? @callee "std::fs::write")) @finding
