# stream_data is a test-only dependency, so its formatter settings are
# repeated here instead of using import_deps.
[
  inputs: ["{mix,.formatter}.exs", "{config,lib,test,scripts,bench}/**/*.{ex,exs}"],
  locals_without_parens: [all: :*, check: :*, property: 1, property: 2, property: 3, gen: :*]
]
