mod commands;
mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::process::start_prover,
            commands::process::stop_prover,
            commands::process::get_prover_status,
            commands::process::start_generator,
            commands::process::stop_generator,
            commands::process::get_generator_status,
            commands::config::load_config,
            commands::config::save_config,
            commands::resources::get_resource_paths,
            commands::resources::ensure_bb_installed,
            commands::gpu::check_gpu_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Persistia");
}
