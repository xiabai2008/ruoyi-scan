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
        std::fs::copy(&engine, &embedded).expect("failed to copy engine into OUT_DIR");
        let size = std::fs::metadata(&engine).map(|m| m.len()).unwrap_or(0);
        println!("cargo:warning=嵌入引擎 {} ({} MB)", engine.display(), size / 1024 / 1024);
    } else {
        std::fs::write(&embedded, b"").expect("failed to write placeholder");
        println!(
            "cargo:warning=未找到引擎产物（desktop/engine/dist/ruoyi-scan-engine.exe），开发模式构建（不嵌入引擎）"
        );
    }
    println!("cargo:rerun-if-changed={}", engine.display());
    tauri_build::build()
}
