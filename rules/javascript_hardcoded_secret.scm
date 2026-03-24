(variable_declarator
  name: (identifier) @name
  value: [(string) (template_string)] @secret
  (#match? @name "(?i)(api[_-]?key|secret|token|password)")) @finding
