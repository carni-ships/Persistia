use serde::{Deserialize, Serialize};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct ManagedProcess {
    pub child: Child,
    pub pid: u32,
    pub mode: String,
    pub started_at: Instant,
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

pub struct AppState {
    pub prover: Arc<Mutex<Option<ManagedProcess>>>,
    pub generator: Arc<Mutex<Option<ManagedProcess>>>,
    pub config: Arc<Mutex<AppConfig>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            prover: Arc::new(Mutex::new(None)),
            generator: Arc::new(Mutex::new(None)),
            config: Arc::new(Mutex::new(AppConfig::default())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub node_url: String,
    pub shard: String,
    pub prover_mode: String,
    pub prover_interval: u32,
    pub prover_workers: u32,
    pub prover_native: bool,
    pub prover_recursive: bool,
    pub generator_agents: u32,
    pub generator_interval: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            node_url: "https://persistia.carnation-903.workers.dev".into(),
            shard: "node-1".into(),
            prover_mode: "watch-incremental".into(),
            prover_interval: 5,
            prover_workers: 6,
            prover_native: true,
            prover_recursive: true,
            generator_agents: 3,
            generator_interval: 500,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub mode: Option<String>,
    pub uptime_secs: Option<u64>,
}
