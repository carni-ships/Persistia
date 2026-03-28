export function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function shortKey(key: string, len = 8): string {
  if (!key) return "";
  if (key.length <= len * 2 + 2) return key;
  return key.slice(0, len + 2) + "..." + key.slice(-len);
}

export function formatNumber(n: number): string {
  return n.toLocaleString();
}

export function uptimeStr(secs: number): string {
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const s = secs % 60;
  if (mins < 60) return `${mins}m ${s}s`;
  const hrs = Math.floor(mins / 60);
  const m = mins % 60;
  return `${hrs}h ${m}m`;
}

export function nodeColor(id: string): string {
  const colors = ["#6c5ce7", "#00cec9", "#e17055", "#fdcb6e", "#55efc4", "#a29bfe"];
  let hash = 0;
  for (let i = 0; i < id.length; i++) hash = ((hash << 5) - hash + id.charCodeAt(i)) | 0;
  return colors[Math.abs(hash) % colors.length];
}
