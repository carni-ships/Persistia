// ─── Virtual Filesystem ────────────────────────────────────────────────────────
// Unified file-tree abstraction over multiple storage backends (R2, SQLite, KV).
// The host mounts pre-configured backend handles; VFS resolves paths to the
// correct backend and delegates reads/writes/deletes transparently.
//
// Metadata cache (SQLite) avoids repeated R2 HEAD calls for stat/list.

// ─── Types ──────────────────────────────────────────────────────────────────────

export type VFSBackend = "r2" | "sqlite" | "kv";

export interface VFSMount {
  path: string;           // mount point, e.g. "/proofs", "/chain/blocks"
  backend: VFSBackend;
  readOnly: boolean;
  config: R2MountConfig | SQLiteMountConfig | KVMountConfig;
}

export interface R2MountConfig {
  bucket: R2Bucket;
  keyPrefix: string;      // e.g. "chunks/shard-1/"
}

export interface SQLiteMountConfig {
  sql: any;
  table: string;
  keyColumn: string;
  valueColumn: string;
  filterColumns?: Record<string, string>;
}

export interface KVMountConfig {
  sql: any;
  table: string;
  keyColumn: string;
  valueColumn: string;
}

export interface VFSStat {
  path: string;
  size: number;
  backend: VFSBackend;
  modifiedAt: number;
  isDirectory: boolean;
}

export interface VFSReadResult {
  data: Uint8Array | string;
  contentType: string;
  stat: VFSStat;
}

export interface VFSListOptions {
  limit?: number;
  cursor?: string;
}

export interface VFSListResult {
  entries: VFSStat[];
  cursor?: string;
  truncated: boolean;
}

// ─── Resolved Mount ─────────────────────────────────────────────────────────────

interface ResolvedMount {
  mount: VFSMount;
  relativePath: string;
}

// ─── VirtualFilesystem ──────────────────────────────────────────────────────────

export class VirtualFilesystem {
  private mounts: VFSMount[] = [];
  private metaSql: any | null;

  /**
   * Initialize the vfs_metadata table for R2 metadata caching.
   * Call once during DO initialization.
   */
  static initTables(sql: any): void {
    sql.exec(`
      CREATE TABLE IF NOT EXISTS vfs_metadata (
        path TEXT PRIMARY KEY,
        backend TEXT NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
        modified_at INTEGER NOT NULL,
        r2_key TEXT,
        checksum TEXT
      )
    `);
    sql.exec(`
      CREATE INDEX IF NOT EXISTS idx_vfs_path_prefix ON vfs_metadata(path)
    `);
  }

  /**
   * @param mounts  Initial mount points.
   * @param metaSql Optional SQLite handle for the metadata cache.
   *                If omitted, metadata caching is disabled.
   */
  constructor(mounts: VFSMount[], metaSql?: any) {
    this.metaSql = metaSql ?? null;
    for (const m of mounts) {
      this.addMount(m);
    }
  }

  // ─── Mount Management ───────────────────────────────────────────────────────

  addMount(mount: VFSMount): void {
    const normalized = { ...mount, path: normalizePath(mount.path) };
    // Remove existing mount at same path
    this.mounts = this.mounts.filter(m => m.path !== normalized.path);
    this.mounts.push(normalized);
    // Sort by path length descending — longest prefix matches first
    this.mounts.sort((a, b) => b.path.length - a.path.length);
  }

  removeMount(path: string): void {
    const norm = normalizePath(path);
    this.mounts = this.mounts.filter(m => m.path !== norm);
  }

  getMounts(): VFSMount[] {
    return [...this.mounts];
  }

  // ─── Core Operations ────────────────────────────────────────────────────────

  async read(path: string): Promise<VFSReadResult | null> {
    const norm = normalizePath(path);
    const resolved = this.resolveMount(norm);
    if (!resolved) return null;

    const { mount, relativePath } = resolved;

    switch (mount.backend) {
      case "r2":
        return this.readR2(mount, norm, relativePath);
      case "sqlite":
        return this.readSQLite(mount, norm, relativePath);
      case "kv":
        return this.readKV(mount, norm, relativePath);
    }
  }

  async write(path: string, data: Uint8Array | string): Promise<void> {
    const norm = normalizePath(path);
    const resolved = this.resolveMount(norm);
    if (!resolved) throw new Error(`No mount found for path: ${path}`);
    if (resolved.mount.readOnly) throw new Error(`Mount at ${resolved.mount.path} is read-only`);

    const { mount, relativePath } = resolved;

    switch (mount.backend) {
      case "r2":
        return this.writeR2(mount, norm, relativePath, data);
      case "sqlite":
        return this.writeSQLite(mount, relativePath, data);
      case "kv":
        return this.writeKV(mount, relativePath, data);
    }
  }

  async delete(path: string): Promise<void> {
    const norm = normalizePath(path);
    const resolved = this.resolveMount(norm);
    if (!resolved) return;
    if (resolved.mount.readOnly) throw new Error(`Mount at ${resolved.mount.path} is read-only`);

    const { mount, relativePath } = resolved;

    switch (mount.backend) {
      case "r2":
        return this.deleteR2(mount, norm, relativePath);
      case "sqlite":
        return this.deleteSQLite(mount, relativePath);
      case "kv":
        return this.deleteKV(mount, relativePath);
    }
  }

  async stat(path: string): Promise<VFSStat | null> {
    const norm = normalizePath(path);

    // Check if path is a mount point (virtual directory)
    if (this.isMountPoint(norm)) {
      return { path: norm, size: 0, backend: "r2", modifiedAt: 0, isDirectory: true };
    }

    // Check if path is a parent of any mount point (virtual directory)
    if (this.isVirtualDirectory(norm)) {
      return { path: norm, size: 0, backend: "r2", modifiedAt: 0, isDirectory: true };
    }

    const resolved = this.resolveMount(norm);
    if (!resolved) return null;

    const { mount, relativePath } = resolved;

    // Directory-style path
    if (norm.endsWith("/")) {
      return { path: norm, size: 0, backend: mount.backend, modifiedAt: 0, isDirectory: true };
    }

    // Try metadata cache first (for R2)
    if (mount.backend === "r2" && this.metaSql) {
      const cached = this.metaSql.exec(
        "SELECT size, content_type, modified_at FROM vfs_metadata WHERE path = ?", norm
      ).toArray();
      if (cached.length > 0) {
        return {
          path: norm,
          size: cached[0].size as number,
          backend: "r2",
          modifiedAt: cached[0].modified_at as number,
          isDirectory: false,
        };
      }
    }

    switch (mount.backend) {
      case "r2":
        return this.statR2(mount, norm, relativePath);
      case "sqlite":
        return this.statSQLite(mount, norm, relativePath);
      case "kv":
        return this.statKV(mount, norm, relativePath);
    }
  }

  async exists(path: string): Promise<boolean> {
    return (await this.stat(path)) !== null;
  }

  async list(path: string, opts?: VFSListOptions): Promise<VFSListResult> {
    const norm = normalizePath(path.endsWith("/") ? path : path + "/");
    const limit = opts?.limit ?? 1000;
    const entries: VFSStat[] = [];

    // Collect virtual directory entries from child mount points
    const seen = new Set<string>();
    for (const m of this.mounts) {
      if (m.path.startsWith(norm) && m.path !== norm) {
        // Extract the next path segment after norm
        const rest = m.path.slice(norm.length);
        const nextSegment = rest.split("/")[0];
        const childPath = norm + nextSegment;
        if (!seen.has(childPath)) {
          seen.add(childPath);
          entries.push({
            path: childPath,
            size: 0,
            backend: m.backend,
            modifiedAt: 0,
            isDirectory: true,
          });
        }
      }
    }

    // Resolve mount for this path and list backend entries
    const resolved = this.resolveMount(norm);
    if (!resolved) {
      return { entries, cursor: undefined, truncated: false };
    }

    const { mount, relativePath } = resolved;
    let cursor: string | undefined;
    let truncated = false;

    switch (mount.backend) {
      case "r2": {
        const result = await this.listR2(mount, norm, relativePath, limit, opts?.cursor);
        entries.push(...result.entries);
        cursor = result.cursor;
        truncated = result.truncated;
        break;
      }
      case "sqlite": {
        entries.push(...this.listSQLiteOrKV(mount, norm, relativePath, limit));
        break;
      }
      case "kv": {
        entries.push(...this.listSQLiteOrKV(mount, norm, relativePath, limit));
        break;
      }
    }

    return { entries, cursor, truncated };
  }

  // ─── R2 Backend ─────────────────────────────────────────────────────────────

  private async readR2(mount: VFSMount, fullPath: string, relativePath: string): Promise<VFSReadResult | null> {
    const cfg = mount.config as R2MountConfig;
    const key = cfg.keyPrefix + relativePath;
    const obj = await cfg.bucket.get(key);
    if (!obj) return null;

    const contentType = obj.httpMetadata?.contentType ?? "application/octet-stream";
    const isText = contentType.startsWith("text/") || contentType === "application/json";
    const data = isText ? await obj.text() : new Uint8Array(await obj.arrayBuffer());
    const size = obj.size;
    const modifiedAt = obj.uploaded?.getTime() ?? Date.now();

    // Update metadata cache
    this.updateMetadataCache(fullPath, "r2", size, contentType, modifiedAt, key);

    return {
      data,
      contentType,
      stat: { path: fullPath, size, backend: "r2", modifiedAt, isDirectory: false },
    };
  }

  private async writeR2(mount: VFSMount, fullPath: string, relativePath: string, data: Uint8Array | string): Promise<void> {
    const cfg = mount.config as R2MountConfig;
    const key = cfg.keyPrefix + relativePath;
    await cfg.bucket.put(key, data);

    const size = typeof data === "string" ? new TextEncoder().encode(data).byteLength : data.byteLength;
    const contentType = typeof data === "string" ? "text/plain" : "application/octet-stream";
    const now = Date.now();
    this.updateMetadataCache(fullPath, "r2", size, contentType, now, key);
  }

  private async deleteR2(mount: VFSMount, fullPath: string, relativePath: string): Promise<void> {
    const cfg = mount.config as R2MountConfig;
    const key = cfg.keyPrefix + relativePath;
    await cfg.bucket.delete(key);
    this.removeMetadataCache(fullPath);
  }

  private async statR2(mount: VFSMount, fullPath: string, relativePath: string): Promise<VFSStat | null> {
    const cfg = mount.config as R2MountConfig;
    const key = cfg.keyPrefix + relativePath;
    const head = await cfg.bucket.head(key);
    if (!head) return null;

    const modifiedAt = head.uploaded?.getTime() ?? Date.now();
    const contentType = head.httpMetadata?.contentType ?? "application/octet-stream";
    this.updateMetadataCache(fullPath, "r2", head.size, contentType, modifiedAt, key);

    return { path: fullPath, size: head.size, backend: "r2", modifiedAt, isDirectory: false };
  }

  private async listR2(
    mount: VFSMount,
    basePath: string,
    relativePath: string,
    limit: number,
    cursor?: string,
  ): Promise<{ entries: VFSStat[]; cursor?: string; truncated: boolean }> {
    const cfg = mount.config as R2MountConfig;
    const prefix = cfg.keyPrefix + relativePath;
    const result = await cfg.bucket.list({ prefix, limit, cursor });

    const entries: VFSStat[] = result.objects.map(obj => {
      // Convert R2 key back to VFS path
      const objRelative = obj.key.slice(cfg.keyPrefix.length);
      const vfsPath = mount.path + "/" + objRelative;
      const modifiedAt = obj.uploaded?.getTime() ?? Date.now();
      return { path: vfsPath, size: obj.size, backend: "r2" as VFSBackend, modifiedAt, isDirectory: false };
    });

    return {
      entries,
      cursor: result.truncated ? (result as any).cursor : undefined,
      truncated: result.truncated,
    };
  }

  // ─── SQLite Backend ─────────────────────────────────────────────────────────

  private readSQLite(mount: VFSMount, fullPath: string, relativePath: string): VFSReadResult | null {
    const cfg = mount.config as SQLiteMountConfig;
    let query = `SELECT ${cfg.valueColumn} FROM ${cfg.table} WHERE ${cfg.keyColumn} = ?`;
    const params: any[] = [relativePath];

    if (cfg.filterColumns) {
      for (const [col, val] of Object.entries(cfg.filterColumns)) {
        query += ` AND ${col} = ?`;
        params.push(val);
      }
    }

    const rows = cfg.sql.exec(query, ...params).toArray();
    if (rows.length === 0) return null;

    const value = rows[0][cfg.valueColumn];
    const data = typeof value === "string" ? value : new Uint8Array(value);
    const size = typeof data === "string" ? new TextEncoder().encode(data).byteLength : data.byteLength;
    const contentType = typeof data === "string" ? "text/plain" : "application/octet-stream";

    return {
      data,
      contentType,
      stat: { path: fullPath, size, backend: "sqlite", modifiedAt: Date.now(), isDirectory: false },
    };
  }

  private writeSQLite(mount: VFSMount, relativePath: string, data: Uint8Array | string): void {
    const cfg = mount.config as SQLiteMountConfig;
    cfg.sql.exec(
      `INSERT INTO ${cfg.table} (${cfg.keyColumn}, ${cfg.valueColumn})
       VALUES (?, ?)
       ON CONFLICT(${cfg.keyColumn}) DO UPDATE SET ${cfg.valueColumn} = excluded.${cfg.valueColumn}`,
      relativePath,
      data,
    );
  }

  private deleteSQLite(mount: VFSMount, relativePath: string): void {
    const cfg = mount.config as SQLiteMountConfig;
    cfg.sql.exec(`DELETE FROM ${cfg.table} WHERE ${cfg.keyColumn} = ?`, relativePath);
  }

  private statSQLite(mount: VFSMount, fullPath: string, relativePath: string): VFSStat | null {
    const cfg = mount.config as SQLiteMountConfig;
    let query = `SELECT length(${cfg.valueColumn}) as size FROM ${cfg.table} WHERE ${cfg.keyColumn} = ?`;
    const params: any[] = [relativePath];

    if (cfg.filterColumns) {
      for (const [col, val] of Object.entries(cfg.filterColumns)) {
        query += ` AND ${col} = ?`;
        params.push(val);
      }
    }

    const rows = cfg.sql.exec(query, ...params).toArray();
    if (rows.length === 0) return null;

    return {
      path: fullPath,
      size: rows[0].size as number,
      backend: "sqlite",
      modifiedAt: Date.now(),
      isDirectory: false,
    };
  }

  // ─── KV Backend ─────────────────────────────────────────────────────────────

  private readKV(mount: VFSMount, fullPath: string, relativePath: string): VFSReadResult | null {
    const cfg = mount.config as KVMountConfig;
    const rows = cfg.sql.exec(
      `SELECT ${cfg.valueColumn} FROM ${cfg.table} WHERE ${cfg.keyColumn} = ?`,
      relativePath,
    ).toArray();
    if (rows.length === 0) return null;

    const value = rows[0][cfg.valueColumn];
    const data = typeof value === "string" ? value : new Uint8Array(value);
    const size = typeof data === "string" ? new TextEncoder().encode(data).byteLength : data.byteLength;
    const contentType = typeof data === "string" ? "text/plain" : "application/octet-stream";

    return {
      data,
      contentType,
      stat: { path: fullPath, size, backend: "kv", modifiedAt: Date.now(), isDirectory: false },
    };
  }

  private writeKV(mount: VFSMount, relativePath: string, data: Uint8Array | string): void {
    const cfg = mount.config as KVMountConfig;
    cfg.sql.exec(
      `INSERT INTO ${cfg.table} (${cfg.keyColumn}, ${cfg.valueColumn})
       VALUES (?, ?)
       ON CONFLICT(${cfg.keyColumn}) DO UPDATE SET ${cfg.valueColumn} = excluded.${cfg.valueColumn}`,
      relativePath,
      data,
    );
  }

  private deleteKV(mount: VFSMount, relativePath: string): void {
    const cfg = mount.config as KVMountConfig;
    cfg.sql.exec(`DELETE FROM ${cfg.table} WHERE ${cfg.keyColumn} = ?`, relativePath);
  }

  private statKV(mount: VFSMount, fullPath: string, relativePath: string): VFSStat | null {
    const cfg = mount.config as KVMountConfig;
    const rows = cfg.sql.exec(
      `SELECT length(${cfg.valueColumn}) as size FROM ${cfg.table} WHERE ${cfg.keyColumn} = ?`,
      relativePath,
    ).toArray();
    if (rows.length === 0) return null;

    return {
      path: fullPath,
      size: rows[0].size as number,
      backend: "kv",
      modifiedAt: Date.now(),
      isDirectory: false,
    };
  }

  // ─── Shared: SQLite/KV List ─────────────────────────────────────────────────

  private listSQLiteOrKV(mount: VFSMount, basePath: string, relativePath: string, limit: number): VFSStat[] {
    const cfg = mount.config as SQLiteMountConfig | KVMountConfig;
    const prefix = relativePath || "";
    const pattern = prefix ? `${prefix}%` : "%";

    const rows = cfg.sql.exec(
      `SELECT ${cfg.keyColumn}, length(${cfg.valueColumn}) as size
       FROM ${cfg.table}
       WHERE ${cfg.keyColumn} LIKE ?
       LIMIT ?`,
      pattern,
      limit,
    ).toArray();

    return rows.map((row: any) => ({
      path: mount.path + "/" + row[cfg.keyColumn],
      size: row.size as number,
      backend: mount.backend,
      modifiedAt: Date.now(),
      isDirectory: false,
    }));
  }

  // ─── Metadata Cache ─────────────────────────────────────────────────────────

  private updateMetadataCache(
    path: string,
    backend: VFSBackend,
    size: number,
    contentType: string,
    modifiedAt: number,
    r2Key?: string,
  ): void {
    if (!this.metaSql) return;
    try {
      this.metaSql.exec(
        `INSERT INTO vfs_metadata (path, backend, size, content_type, modified_at, r2_key)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(path) DO UPDATE SET
           size = excluded.size,
           content_type = excluded.content_type,
           modified_at = excluded.modified_at,
           r2_key = excluded.r2_key`,
        path, backend, size, contentType, modifiedAt, r2Key ?? null,
      );
    } catch (_) {
      // Best-effort — cache miss is fine
    }
  }

  private removeMetadataCache(path: string): void {
    if (!this.metaSql) return;
    try {
      this.metaSql.exec("DELETE FROM vfs_metadata WHERE path = ?", path);
    } catch (_) {
      // Best-effort
    }
  }

  // ─── Path Resolution ───────────────────────────────────────────────────────

  private resolveMount(path: string): ResolvedMount | null {
    for (const mount of this.mounts) {
      if (path === mount.path || path.startsWith(mount.path + "/")) {
        const relativePath = path === mount.path ? "" : path.slice(mount.path.length + 1);
        return { mount, relativePath };
      }
    }
    return null;
  }

  private isMountPoint(path: string): boolean {
    return this.mounts.some(m => m.path === path);
  }

  private isVirtualDirectory(path: string): boolean {
    const prefix = path.endsWith("/") ? path : path + "/";
    return this.mounts.some(m => m.path.startsWith(prefix));
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Normalize a path: ensure leading slash, strip trailing slash, collapse double slashes. */
function normalizePath(p: string): string {
  let norm = p.replace(/\/+/g, "/");
  if (!norm.startsWith("/")) norm = "/" + norm;
  if (norm.length > 1 && norm.endsWith("/")) norm = norm.slice(0, -1);
  return norm;
}
