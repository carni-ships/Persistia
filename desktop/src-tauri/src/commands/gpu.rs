use std::process::Command;

#[derive(serde::Serialize)]
pub struct GpuInfo {
    pub bb_available: bool,
    pub bb_version: Option<String>,
    pub metal_msm_available: bool,
    pub gpu_name: Option<String>,
    pub unified_memory: Option<bool>,
}

#[tauri::command]
pub fn check_gpu_info() -> GpuInfo {
    let bb_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".bb")
        .join("bb");

    let msm_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".zkmsm")
        .join("zkmsm");

    let bb_version = Command::new(&bb_path)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());

    let bb_available = bb_version.is_some();

    let msm_output = Command::new(&msm_path)
        .arg("--info")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        });

    let (metal_msm_available, gpu_name, unified_memory) = if let Some(output) = msm_output {
        if let Ok(info) = serde_json::from_str::<serde_json::Value>(&output) {
            (
                true,
                info.get("gpu").and_then(|v| v.as_str()).map(String::from),
                info.get("unified_memory").and_then(|v| v.as_bool()),
            )
        } else {
            (true, None, None)
        }
    } else {
        (false, None, None)
    };

    GpuInfo {
        bb_available,
        bb_version,
        metal_msm_available,
        gpu_name,
        unified_memory,
    }
}
