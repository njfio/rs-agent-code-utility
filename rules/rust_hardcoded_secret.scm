(const_item
  name: (identifier) @name
  value: (string_literal) @secret
  (#match? @name "(?i)(api[_-]?key|secret|token|password)")) @finding
