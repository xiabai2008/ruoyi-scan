// Ruoyi-Scan 桌面端 —— Rust 宿主
//
// 职责：
//   1. 启动时自动拉起本地 FastAPI sidecar（127.0.0.1:8123）
//      若 8123 端口已被占用则视为外部已启动，跳过拉起。
//   2. 应用退出时回收子进程。
//
// 后端解析优先级（发布版零配置的关键）：
//   a) 捆绑引擎：exe 同目录的 ruoyi-scan-engine.exe（NSIS 资源目录 / dev 引擎构建产物）
//   b) 开发回退：python main.py --serve（RUOYI_SCAN_PYTHON 可指定解释器，工作目录取仓库根）

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
// JOBOBJECT_EXTENDED_LIMIT_INFORMATION 与信息类同名冲突，用别名引入
use windows_sys::Win32::System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION as JOB_EXT_LIMIT_INFO;

use tauri::Manager;
use tauri::RunEvent;

const API_PORT: u16 = 8123;
// desktop/src-tauri 的上级上级 = 仓库根（开发模式定位 main.py）
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const ENGINE_EXE: &str = "ruoyi-scan-engine.exe";

struct BackendChild(Mutex<Option<Child>>);

/// Windows：把子进程挂进 KILL_ON_JOB_CLOSE 的 Job Object。
/// 壳进程无论正常退出、崩溃还是被任务管理器强杀，Job 句柄关闭时引擎整树自动回收，
/// 避免 8123 端口被孤儿引擎长期占用。
#[cfg(windows)]
fn tie_to_job(child: &Child) {
    use std::os::windows::io::AsRawHandle;

    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            eprintln!("[ruoyi-scan-desktop] JobObject 创建失败，回退为普通子进程");
            return;
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
            eprintln!("[ruoyi-scan-desktop] JobObject 配置失败");
            return;
        }
        if AssignProcessToJobObject(job, child.as_raw_handle()) == 0 {
            eprintln!("[ruoyi-scan-desktop] 引擎挂接 JobObject 失败（回收仍由 Exit 事件兜底）");
        } else {
            eprintln!("[ruoyi-scan-desktop] 引擎已挂接 JobObject（KILL_ON_JOB_CLOSE）");
            // 不调用 CloseHandle：Job 句柄随壳进程存活，壳退出（含被杀）时句柄关闭 → 引擎树终止
            let _ = job;
        }
    }
}

#[cfg(not(windows))]
fn tie_to_job(_child: &Child) {}

fn port_open(port: u16) -> bool {
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok()
}

/// 定位捆绑的引擎 exe：
///   - 开发模式：desktop/engine/dist/ruoyi-scan-engine.exe（本地构建验证用）
///   - 安装模式：主程序同目录（NSIS 资源目录）
fn bundled_engine() -> Option<PathBuf> {
    // 1) 主程序同目录（安装后始终命中）
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(ENGINE_EXE);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    // 2) 开发模式：引擎构建产物目录
    let dev_engine = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../engine/dist")
        .join(ENGINE_EXE);
    if dev_engine.is_file() {
        return Some(dev_engine);
    }
    None
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

    // 优先捆绑引擎（发布版路径；用户机器无需 Python）
    if let Some(engine) = bundled_engine() {
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
