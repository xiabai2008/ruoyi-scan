fn main() {
    // 单 exe 发布：把 PyInstaller 引擎（ruoyi-scan-engine.exe）在编译期嵌入壳二进制。
    //
    // 机制：引擎产物复制到 OUT_DIR/embedded_engine.bin，lib.rs 用 include_bytes! 固定路径嵌入。
    //   - CI / 本地打包：先跑 desktop/engine/build-engine.cmd（或 CI 阶段 1）产出引擎，
    //     build.rs 复制嵌入 → 发布版单 exe 双击即用。
    //   - 开发模式：引擎未构建 → 写入 0 字节占位，lib.rs 检测到空字节回退 python sidecar。
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let embedded = std::path::Path::new(&out_dir).join("embedded_engine.bin");
    let engine = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../engine/dist/ruoyi-scan-engine.exe");

    if engine.is_file() {
        // 半成品 / 被截断的产物（例如中断的 PyInstaller 构建）绝不能静默嵌入：
        // 校验最小体积，并核对实际复制字节数，短拷贝直接让构建失败。
        const MIN_ENGINE_BYTES: u64 = 1_000_000;
        let src_len = std::fs::metadata(&engine)
            .expect("failed to stat engine artifact")
            .len();
        if src_len < MIN_ENGINE_BYTES {
            panic!(
                "引擎产物疑似不完整（{} 字节 < {} 字节），请重新构建 {}",
                src_len,
                MIN_ENGINE_BYTES,
                engine.display()
            );
        }
        let copied = std::fs::copy(&engine, &embedded).expect("failed to copy engine into OUT_DIR");
        if copied != src_len {
            panic!("引擎复制不完整：{} / {} 字节", copied, src_len);
        }
        println!("cargo:warning=嵌入引擎 {} ({} MB)", engine.display(), src_len / 1024 / 1024);
    } else {
        std::fs::write(&embedded, b"").expect("failed to write placeholder");
        println!(
            "cargo:warning=未找到引擎产物（desktop/engine/dist/ruoyi-scan-engine.exe），开发模式构建（不嵌入引擎）"
        );
    }
    // 跟踪引擎所在目录而非文件本身：开发模式下产物不存在时，Cargo 会把不存在的
    // rerun-if-changed 目标视为“始终变化”，导致本脚本每次构建都无谓重跑。
    println!(
        "cargo:rerun-if-changed={}",
        engine.parent().expect("engine path has a parent").display()
    );
    tauri_build::build()
}
