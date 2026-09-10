// Ruoyi-Scan 桌面端 —— Rust 宿主（单 exe 架构）
//
// 发布形态：一个 Ruoyi-Scan.exe 双击即用，无需安装器、无需 Python。
//   - PyInstaller 冻结的 FastAPI 引擎在编译期嵌入壳二进制（build.rs → OUT_DIR/embedded_engine.bin）
//   - 首次运行自解压到 %LOCALAPPDATA%\Ruoyi-Scan\engine\（版本戳不匹配时覆盖更新）
//   - 拉起引擎（127.0.0.1:8123）→ 退出时回收（正常退出走 Exit 事件；被强杀走 JobObject）
//
// 开发回退：引擎未嵌入（0 字节）时回退 python main.py --serve（仓库根，M1 开发体验）。

use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::Duration;

#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
// JOBOBJECT_EXTENDED_LIMIT_INFORMATION 与信息类常量同名，别名引入
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION as JOB_EXT_LIMIT_INFO;

use tauri::Manager;
use tauri::RunEvent;

const API_PORT: u16 = 8123;
// desktop/src-tauri 的上级上级 = 仓库根（开发模式定位 main.py）
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

// 编译期嵌入的引擎字节流（build.rs 复制 engine/dist/ruoyi-scan-engine.exe 到 OUT_DIR）
static EMBEDDED_ENGINE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/embedded_engine.bin"));

struct BackendChild(Mutex<Option<Child>>);

fn port_open(port: u16) -> bool {
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

/// 引擎自解压目录：%LOCALAPPDATA%\Ruoyi-Scan\engine\
#[cfg(windows)]
fn engine_dir() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(|d| PathBuf::from(d).join("Ruoyi-Scan").join("engine"))
        .unwrap_or_else(|_| PathBuf::from("engine"))
}

#[cfg(not(windows))]
fn engine_dir() -> PathBuf {
    std::env::var("HOME")
        .map(|d| PathBuf::from(d).join(".ruoyi-scan").join("engine"))
        .unwrap_or_else(|_| PathBuf::from("engine"))
}

/// 引擎就位：嵌入字节流非空时，解压到用户目录（内容变化时覆盖）。
/// 返回 Some(exe) 表示发布模式引擎可用；None 表示开发模式（未嵌入引擎）。
fn materialize_engine() -> Option<PathBuf> {
    if EMBEDDED_ENGINE.is_empty() {
        eprintln!("[ruoyi-scan-desktop] 未嵌入引擎（开发模式构建），回退 python sidecar");
        return None;
    }
    let dir = engine_dir();
    let exe = dir.join("ruoyi-scan-engine.exe");
    let stamp = dir.join(".engine-stamp");

    // 以「字节数 + 简单校验和」作版本戳：壳升级换引擎时自动覆盖旧解压产物
    let checksum: u64 = EMBEDDED_ENGINE.iter().map(|&b| b as u64).sum();
    let expected = format!("{}\n{}\n", EMBEDDED_ENGINE.len(), checksum);
    let need_extract = match std::fs::read_to_string(&stamp) {
        Ok(prev) => prev != expected,
        Err(_) => true,
    };
    if need_extract {
        std::fs::create_dir_all(&dir).ok()?;
        // 先写临时文件再改名，避免写入中断留下残缺引擎
        let tmp = dir.join(".engine.tmp");
        if std::fs::write(&tmp, EMBEDDED_ENGINE).is_err() {
            eprintln!("[ruoyi-scan-desktop] 引擎自解压失败（目录不可写？）：{:?}", dir);
            return None;
        }
        // 旧引擎若正被运行中的进程锁定，remove/rename 会失败 → 此时若端口已开则复用现有引擎
        if exe.exists() {
            let _ = std::fs::remove_file(&exe);
        }
        if std::fs::rename(&tmp, &exe).is_err() {
            let _ = std::fs::remove_file(&tmp);
            if port_open(API_PORT) {
                eprintln!("[ruoyi-scan-desktop] 引擎文件被占用但服务已在线，复用现有引擎");
                return Some(exe);
            }
            eprintln!("[ruoyi-scan-desktop] 引擎更新失败且服务离线");
            return None;
        }
        std::fs::write(&stamp, expected).ok()?;
        eprintln!("[ruoyi-scan-desktop] 引擎已释放：{:?}", exe);
    }
    Some(exe)
}

/// Windows：把子进程挂进 KILL_ON_JOB_CLOSE 的 Job Object。
/// 壳进程无论正常退出、崩溃还是被任务管理器强杀，Job 句柄关闭时引擎整树自动回收，
/// 避免 8123 端口被孤儿引擎长期占用。
///
/// 重要：Job 句柄**刻意不 CloseHandle** —— 它必须随壳进程存活，壳退出时由内核关闭
/// 句柄并触发 KILL_ON_JOB_CLOSE。句柄泄漏在此处是设计意图，不是缺陷。
///
/// 返回是否挂接成功；诊断信息同时落盘（release 版壳是 GUI 子系统，stderr 不可见）。
#[cfg(windows)]
fn tie_to_job(child: &Child) -> bool {
    use std::os::windows::io::AsRawHandle;

    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            write_job_diag("create_job_failed");
            eprintln!("[ruoyi-scan-desktop] JobObject 创建失败，回退为普通子进程");
            return false;
        }
        let mut info: JOB_EXT_LIMIT_INFO = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ret = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOB_EXT_LIMIT_INFO>() as u32,
        );
        if ret == 0 {
            write_job_diag("set_info_failed");
            eprintln!("[ruoyi-scan-desktop] JobObject 配置失败");
            return false;
        }
        // 挂接可能因子进程已先挂进别的 Job（嵌套限制）而失败 —— 重试几次吸收瞬时失败
        let mut ok = false;
        for attempt in 0..3 {
            if AssignProcessToJobObject(job, child.as_raw_handle()) != 0 {
                ok = true;
                break;
            }
            eprintln!("[ruoyi-scan-desktop] 引擎挂接 JobObject 第 {} 次失败，重试", attempt + 1);
            std::thread::sleep(Duration::from_millis(50));
        }
        if ok {
            write_job_diag(&format!("attached pid={}", child.id()));
            eprintln!("[ruoyi-scan-desktop] 引擎已挂接 JobObject（KILL_ON_JOB_CLOSE）pid={}", child.id());
            // 不调用 CloseHandle：Job 句柄随壳进程存活，壳退出（含被杀）时句柄关闭 → 引擎树终止
            let _ = job;
        } else {
            write_job_diag(&format!("assign_failed pid={}", child.id()));
            eprintln!("[ruoyi-scan-desktop] 引擎挂接 JobObject 失败（回收仍由 Exit 事件兜底）");
        }
        ok
    }
}

/// 把 JobObject 挂接诊断写入引擎目录（release 版壳 stderr 不可达，供 CI 断言读取）
#[cfg(windows)]
fn write_job_diag(msg: &str) {
    let path = engine_dir().join("job-diag.txt");
    let _ = std::fs::write(path, format!("{}\n", msg));
}

#[cfg(not(windows))]
fn tie_to_job(_child: &Child) -> bool {
    false
}

fn spawn_backend() -> Option<Child> {
    if port_open(API_PORT) {
        eprintln!("[ruoyi-scan-desktop] 后端已在 {} 端口运行，跳过拉起", API_PORT);
        return None;
    }
    let cors = [
        "http://tauri.localhost",
        "https://tauri.localhost",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    .join(",");

    // 发布模式：自解压出的引擎（单 exe 双击即用的核心路径）
    if let Some(engine) = materialize_engine() {
        match Command::new(&engine)
            .args([
                "--serve",
                "--host",
                "127.0.0.1",
                "--port",
                &API_PORT.to_string(),
                "--cors-origins",
                &cors,
                "--no-cta",
            ])
            .current_dir(engine.parent().map(|p| p.to_path_buf()).unwrap_or_default())
            .spawn()
        {
            Ok(child) => {
                tie_to_job(&child);
                eprintln!("[ruoyi-scan-desktop] 捆绑引擎已拉起 pid={}", child.id());
                return Some(child);
            }
            Err(e) => {
                eprintln!("[ruoyi-scan-desktop] 捆绑引擎拉起失败（{}），回退 python", e);
            }
        }
    }

    // 开发回退：python main.py --serve
    let python = std::env::var("RUOYI_SCAN_PYTHON").unwrap_or_else(|_| "python".to_string());
    let main_py = format!("{}/main.py", REPO_ROOT);
    match Command::new(&python)
        .args([
            &main_py,
            "--serve",
            "--host",
            "127.0.0.1",
            "--port",
            &API_PORT.to_string(),
            "--cors-origins",
            &cors,
            "--no-cta",
        ])
        .current_dir(REPO_ROOT)
        .spawn()
    {
        Ok(child) => {
            tie_to_job(&child);
            eprintln!("[ruoyi-scan-desktop] 后端已拉起 pid={}（python 开发模式）", child.id());
            Some(child)
        }
        Err(e) => {
            eprintln!("[ruoyi-scan-desktop] 拉起后端失败（{}）：请在设置页手动连接已启动的服务", e);
            None
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let child = spawn_backend();
            app.manage(BackendChild(Mutex::new(child)));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building ruoyi-scan desktop");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            let taken: Option<Child>;
            {
                let state = app_handle.state::<BackendChild>();
                let mut guard = match state.0.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                taken = guard.take();
            } // state 与 guard 在此释放，taken 为独立所有权
            if let Some(mut child) = taken {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("[ruoyi-scan-desktop] 后端子进程已回收");
            }
        }
    });
}
