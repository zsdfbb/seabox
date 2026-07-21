tasks:
  - id: pre-exec-pid-reaper
    type: impl
    description: "修改 pre_exec 闭包，实现 PID namespace double-fork reaper 模型"
    files:
      - src/linux/mod.rs
    depends_on: []

  - id: test-update
    type: test
    description: "更新 N8 测试验证 PID=2"
    files:
      - tests/namespace_test.rs
    depends_on: [pre-exec-pid-reaper]
