use seabox::{CommandSpec, Sandbox};
use std::sync::{Arc, Barrier};
use std::thread;

/// 多线程并发 fork 压力测试。
///
/// 一个线程持续做堆分配（保持 malloc 锁活跃），
/// 同时另一个线程反复 fork sandbox。
/// 如果 child 碰了堆，会死锁。test timeout 兜底。
#[test]
fn concurrent_fork_stress() {
    use seabox::SandboxConfig;
    let sandbox = Sandbox::from_config(SandboxConfig::default()).unwrap();
    let ready = Arc::new(Barrier::new(3));

    let r1 = ready.clone();
    let allocator = thread::spawn(move || {
        r1.wait();
        for _ in 0..10_000 {
            // 持续堆分配，保持 malloc 锁活跃
            let mut v: Vec<u8> = Vec::with_capacity(4096);
            v.resize(4096, 0x42);
            drop(v);
        }
    });

    let r2 = ready.clone();
    let forker = thread::spawn(move || {
        r2.wait();
        for i in 0..500 {
            let output = sandbox
                .execute(&CommandSpec::default().with_program("true"))
                .unwrap();
            assert_eq!(
                output.0.exit_code, 0,
                "iteration {}: expected exit 0, got {}",
                i, output.0.exit_code
            );
        }
    });

    ready.wait();
    allocator.join().unwrap();
    forker.join().unwrap();
}
