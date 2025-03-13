# Testing in Unicorn

Unicorn focus on the testing to reduce bugs and ensure the expected behaviors. The `tests/` directory contains a few subdirectories for testing purposes.

- `unit/`: C unit tests since Unicorn 2.
- `regress/`: The regression tests written in Python and C, imported from Unicorn 1.
- `rust-tests/`: The tests written in rust.
- `fuzz/`: The fuzz drivers for OSS-Fuzz.
- `benchmarks/`: The benchmark suite imported from Unicorn 1.

## Contribution Guide

Generally, it is ideal to add new tests whenever a PR is made. `unit/` should be the first place for the new tests to go.