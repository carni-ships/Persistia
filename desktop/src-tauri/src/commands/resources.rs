use std::fs;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[derive(serde::Serialize)]
pub struct ResourcePaths {
    pub node_bin: String,
    pub bb_bin: String,
    pub circuits_dir: String,
    pub prover_dir: String,
    pub scripts_dir: String,
}

#[tauri::command]
pub fn get_resource_paths(app: AppHandle) -> Result<ResourcePaths, String> {
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|e| format!("No resource dir: {}", e))?;

    // Sidecars are resolved by Tauri based on architecture
    let node_bin = app
        .path()
        .resource_dir()
        .map(|d| d.join("bin").join("node"))
        .map_err(|e| e.to_string())?;

    let bb_bin = app
        .path()
        .resource_dir()
        .map(|d| d.join("bin").join("bb"))
        .map_err(|e| e.to_string())?;

    Ok(ResourcePaths {
        node_bin: node_bin.to_string_lossy().into(),
        bb_bin: bb_bin.to_string_lossy().into(),
        circuits_dir: resource_dir
            .join("resources")
            .join("circuits")
            .to_string_lossy()
            .into(),
        prover_dir: resource_dir
            .join("resources")
            .join("prover")
            .to_string_lossy()
            .into(),
        scripts_dir: resource_dir
            .join("resources")
            .join("scripts")
            .to_string_lossy()
            .into(),
    })
}

#[tauri::command]
pub fn ensure_bb_installed(app: AppHandle) -> Result<String, String> {
    let bb_home = dirs::home_dir()
        .unwrap_or_default()
        .join(".bb");
    let bb_dest = bb_home.join("bb");

    // If bb already exists at ~/.bb/bb, we're good
    if bb_dest.exists() {
        return Ok(bb_dest.to_string_lossy().into());
    }

    // Copy bundled bb to ~/.bb/bb
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|e| format!("No resource dir: {}", e))?;

    // Try sidecar location first
    let bundled_bb = find_bundled_bb(&resource_dir)?;

    let _ = fs::create_dir_all(&bb_home);
    fs::copy(&bundled_bb, &bb_dest).map_err(|e| format!("Failed to copy bb: {}", e))?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&bb_dest, fs::Permissions::from_mode(0o755));
    }

    Ok(bb_dest.to_string_lossy().into())
}

fn find_bundled_bb(resource_dir: &PathBuf) -> Result<PathBuf, String> {
    // Check in the bin directory for architecture-specific binary
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else {
        "x86_64-apple-darwin"
    };

    let candidates = [
        resource_dir.join("bin").join(format!("bb-{}", arch)),
        resource_dir.join("bin").join("bb"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    Err("Bundled bb binary not found".into())
}
