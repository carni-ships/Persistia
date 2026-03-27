// Minimal DO — does absolutely nothing in constructor.
// Each fetch drops one table and returns.
export class PersistiaWorld {
  private state: DurableObjectState;

  constructor(state: DurableObjectState, env: any) {
    this.state = state;
    // DO NOTHING — any SQL here could exceed the free tier row limit
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const table = url.searchParams.get("drop");

    if (table) {
      try {
        this.state.storage.sql.exec(`DROP TABLE IF EXISTS "${table}"`);
        return json({ ok: true, dropped: table });
      } catch (e: any) {
        return json({ ok: false, error: e.message });
      }
    }

    // List tables
    try {
      const tables = [...this.state.storage.sql.exec(
        "SELECT name FROM sqlite_master WHERE type='table'"
      )].map((r: any) => r.name);
      return json({ tables });
    } catch (e: any) {
      // Even listing tables might fail
      try {
        await this.state.storage.deleteAll();
        return json({ ok: true, message: "deleteAll succeeded" });
      } catch (e2: any) {
        return json({ ok: false, error: e.message, deleteAllError: e2.message });
      }
    }
  }

  async alarm() {}
}

function json(data: any): Response {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}

