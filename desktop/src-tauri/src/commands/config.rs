use crate::state::{AppConfig, AppState};
use std::fs;
use tauri::State;

fn config_path() -> std::path::PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_default()
        .join(".persistia-desktop");
    let _ = fs::create_dir_all(&dir);
    dir.join("config.json")
}

#[tauri::command]
pub fn load_config(state: State<'_, AppState>) -> AppConfig {
    let path = config_path();
    if path.exists() {
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<AppConfig>(&data) {
                let mut config = state.config.lock().unwrap();
                *config = cfg.clone();
                return cfg;
            }
        }
    }
    let config = state.config.lock().unwrap();
    config.clone()
}

#[tauri::command]
pub fn save_config(state: State<'_, AppState>, config: AppConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    fs::write(config_path(), json).map_err(|e| e.to_string())?;
    let mut current = state.config.lock().unwrap();
    *current = config;
    Ok(())
}
