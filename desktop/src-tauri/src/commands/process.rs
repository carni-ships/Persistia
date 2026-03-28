use crate::state::{AppConfig, AppState, ManagedProcess, ProcessStatus};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Instant;
use tauri::{AppHandle, Emitter, Manager, State};

fn stream_output(app: AppHandle, reader: impl std::io::Read + Send + 'static, event: &'static str) {
    std::thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines() {
            if let Ok(line) = line {
                let _ = app.emit(event, &line);
            }
        }
    });
}

/// Resolve the path to the Node.js binary.
/// In dev mode, we use the system `node` / `tsx`.
/// In production, we use the bundled sidecar.
fn resolve_node_path(app: &AppHandle) -> String {
    // In dev, try system tsx first
    if cfg!(debug_assertions) {
        if let Ok(output) = Command::new("which").arg("tsx").output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
    }

    // Bundled node sidecar
    app.path()
        .resource_dir()
        .map(|d| d.join("bin").join("node").to_string_lossy().into())
        .unwrap_or_else(|_| "node".into())
}

/// Walk up from cwd looking for the repo root (has wrangler.toml).
fn find_repo_root() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    for _ in 0..10 {
        if dir.join("wrangler.toml").exists() {
            return Some(dir);
        }
        dir = dir.parent()?.to_path_buf();
    }
    None
}

fn resolve_prover_script(app: &AppHandle) -> String {
    if cfg!(debug_assertions) {
        if let Some(root) = find_repo_root() {
            let path = root
                .join("contracts")
                .join("zk-noir")
                .join("prover")
                .join("src")
                .join("prover.ts");
            if path.exists() {
                return path.to_string_lossy().into();
            }
        }
    }

    app.path()
        .resource_dir()
        .map(|d| {
            d.join("resources")
                .join("prover")
                .join("src")
                .join("prover.ts")
                .to_string_lossy()
                .into()
        })
        .unwrap_or_default()
}

fn resolve_generator_script(app: &AppHandle) -> String {
    if cfg!(debug_assertions) {
        if let Some(root) = find_repo_root() {
            let path = root.join("scripts").join("generate-events.ts");
            if path.exists() {
                return path.to_string_lossy().into();
            }
        }
    }

    app.path()
        .resource_dir()
        .map(|d| {
            d.join("resources")
                .join("scripts")
                .join("generate-events.ts")
                .to_string_lossy()
                .into()
        })
        .unwrap_or_default()
}

#[tauri::command]
pub fn start_prover(app: AppHandle, state: State<'_, AppState>) -> Result<ProcessStatus, String> {
    let mut proc_lock = state.prover.lock().unwrap();
    if proc_lock.is_some() {
        return Err("Prover is already running".into());
    }

    let config = state.config.lock().unwrap().clone();
    let node_bin = resolve_node_path(&app);
    let script = resolve_prover_script(&app);

    if !std::path::Path::new(&script).exists() {
        return Err(format!("Prover script not found: {}", script));
    }

    let mut args: Vec<String> = vec![script.clone(), config.prover_mode.clone()];
    args.extend(["--node".into(), config.node_url.clone()]);

    if !config.shard.is_empty() {
        args.extend(["--shard".into(), config.shard.clone()]);
    }

    args.extend([
        "--interval".into(),
        config.prover_interval.to_string(),
    ]);

    if config.prover_mode == "watch-parallel" || config.prover_mode == "watch-parallel-msgpack" {
        args.extend(["--workers".into(), config.prover_workers.to_string()]);
    }

    if config.prover_native {
        args.push("--native".into());
    }

    if config.prover_recursive {
        args.push("--recursive".into());
    }

    // Log the command for debugging
    let _ = app.emit("prover:stdout", &format!("[desktop] {} {}", node_bin, args.join(" ")));

    let mut child = Command::new(&node_bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start prover: {}", e))?;

    let pid = child.id();

    if let Some(stdout) = child.stdout.take() {
        stream_output(app.clone(), stdout, "prover:stdout");
    }
    if let Some(stderr) = child.stderr.take() {
        stream_output(app.clone(), stderr, "prover:stderr");
    }

    let managed = ManagedProcess {
        child,
        pid,
        mode: config.prover_mode.clone(),
        started_at: Instant::now(),
    };

    let status = ProcessStatus {
        running: true,
        pid: Some(pid),
        mode: Some(config.prover_mode),
        uptime_secs: Some(0),
    };

    *proc_lock = Some(managed);
    let _ = app.emit("prover:status", &status);
    Ok(status)
}

#[tauri::command]
pub fn stop_prover(app: AppHandle, state: State<'_, AppState>) -> Result<ProcessStatus, String> {
    let mut proc_lock = state.prover.lock().unwrap();
    if let Some(mut proc) = proc_lock.take() {
        let _ = proc.child.kill();
        let _ = proc.child.wait();
    }
    let status = ProcessStatus {
        running: false,
        pid: None,
        mode: None,
        uptime_secs: None,
    };
    let _ = app.emit("prover:status", &status);
    Ok(status)
}

#[tauri::command]
pub fn get_prover_status(state: State<'_, AppState>) -> ProcessStatus {
    let proc_lock = state.prover.lock().unwrap();
    match &*proc_lock {
        Some(p) => ProcessStatus {
            running: true,
            pid: Some(p.pid),
            mode: Some(p.mode.clone()),
            uptime_secs: Some(p.started_at.elapsed().as_secs()),
        },
        None => ProcessStatus {
            running: false,
            pid: None,
            mode: None,
            uptime_secs: None,
        },
    }
}

#[tauri::command]
pub fn start_generator(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ProcessStatus, String> {
    let mut proc_lock = state.generator.lock().unwrap();
    if proc_lock.is_some() {
        return Err("Generator is already running".into());
    }

    let config = state.config.lock().unwrap().clone();
    let node_bin = resolve_node_path(&app);
    let script = resolve_generator_script(&app);

    if !std::path::Path::new(&script).exists() {
        return Err(format!("Generator script not found: {}", script));
    }

    let mut args: Vec<String> = vec![script.clone()];
    args.extend(["--node".into(), config.node_url.clone()]);

    if !config.shard.is_empty() {
        args.extend(["--shard".into(), config.shard.clone()]);
    }

    args.extend([
        "--agents".into(),
        config.generator_agents.to_string(),
        "--interval".into(),
        config.generator_interval.to_string(),
    ]);

    // Log the command for debugging
    let _ = app.emit("generator:stdout", &format!("[desktop] {} {}", node_bin, args.join(" ")));

    let mut child = Command::new(&node_bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start generator: {}", e))?;

    let pid = child.id();

    if let Some(stdout) = child.stdout.take() {
        stream_output(app.clone(), stdout, "generator:stdout");
    }
    if let Some(stderr) = child.stderr.take() {
        stream_output(app.clone(), stderr, "generator:stderr");
    }

    let managed = ManagedProcess {
        child,
        pid,
        mode: "generate".into(),
        started_at: Instant::now(),
    };

    let status = ProcessStatus {
        running: true,
        pid: Some(pid),
        mode: Some("generate".into()),
        uptime_secs: Some(0),
    };

    *proc_lock = Some(managed);
    let _ = app.emit("generator:status", &status);
    Ok(status)
}

#[tauri::command]
pub fn stop_generator(app: AppHandle, state: State<'_, AppState>) -> Result<ProcessStatus, String> {
    let mut proc_lock = state.generator.lock().unwrap();
    if let Some(mut proc) = proc_lock.take() {
        let _ = proc.child.kill();
        let _ = proc.child.wait();
    }
    let status = ProcessStatus {
        running: false,
        pid: None,
        mode: None,
        uptime_secs: None,
    };
    let _ = app.emit("generator:status", &status);
    Ok(status)
}

#[tauri::command]
pub fn get_generator_status(state: State<'_, AppState>) -> ProcessStatus {
    let proc_lock = state.generator.lock().unwrap();
    match &*proc_lock {
        Some(p) => ProcessStatus {
            running: true,
            pid: Some(p.pid),
            mode: Some(p.mode.clone()),
            uptime_secs: Some(p.started_at.elapsed().as_secs()),
        },
        None => ProcessStatus {
            running: false,
            pid: None,
            mode: None,
            uptime_secs: None,
        },
    }
}
