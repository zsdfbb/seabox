tasks:
  - id: execute-refactor
    type: impl
    description: 重写 execute()，Command::spawn → raw fork
    files:
      - src/linux/mod.rs
    depends_on: []

  - id: regression-test
    type: test
    description: 全量回归测试（landlock/seccomp/namespace）
    depends_on: [execute-refactor]
