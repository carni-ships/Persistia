import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppConfig,
  GpuInfo,
  ProcessStatus,
  ResourcePaths,
} from "./types";

// Process commands
export const startProver = () => invoke<ProcessStatus>("start_prover");
export const stopProver = () => invoke<ProcessStatus>("stop_prover");
export const getProverStatus = () => invoke<ProcessStatus>("get_prover_status");
export const startGenerator = () => invoke<ProcessStatus>("start_generator");
export const stopGenerator = () => invoke<ProcessStatus>("stop_generator");
export const getGeneratorStatus = () => invoke<ProcessStatus>("get_generator_status");

// Config commands
export const loadConfig = () => invoke<AppConfig>("load_config");
export const saveConfig = (config: AppConfig) => invoke<void>("save_config", { config });

// Resource commands
export const getResourcePaths = () => invoke<ResourcePaths>("get_resource_paths");
export const ensureBbInstalled = () => invoke<string>("ensure_bb_installed");

// GPU commands
export const checkGpuInfo = () => invoke<GpuInfo>("check_gpu_info");

// Event listeners
export function onProverStdout(cb: (line: string) => void): Promise<UnlistenFn> {
  return listen<string>("prover:stdout", (e) => cb(e.payload));
}

export function onProverStderr(cb: (line: string) => void): Promise<UnlistenFn> {
  return listen<string>("prover:stderr", (e) => cb(e.payload));
}

export function onGeneratorStdout(cb: (line: string) => void): Promise<UnlistenFn> {
  return listen<string>("generator:stdout", (e) => cb(e.payload));
}

export function onGeneratorStderr(cb: (line: string) => void): Promise<UnlistenFn> {
  return listen<string>("generator:stderr", (e) => cb(e.payload));
}

export function onProverStatus(cb: (status: ProcessStatus) => void): Promise<UnlistenFn> {
  return listen<ProcessStatus>("prover:status", (e) => cb(e.payload));
}

export function onGeneratorStatus(cb: (status: ProcessStatus) => void): Promise<UnlistenFn> {
  return listen<ProcessStatus>("generator:status", (e) => cb(e.payload));
}
