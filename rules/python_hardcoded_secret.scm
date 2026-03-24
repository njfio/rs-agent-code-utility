(assignment
  left: (identifier) @name
  right: [(string) (concatenated_string)] @secret
  (#match? @name "(?i)(api[_-]?key|secret|token|password)")) @finding
