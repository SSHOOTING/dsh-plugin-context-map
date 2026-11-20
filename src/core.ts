/**
 * Pure, dependency-free core for dsh-plugin-context-map (Context Source Map).
 * Reads only metadata from session events; never prompts, tool bodies or file contents.
 */

const SECRET_RE = /((?:token|key|secret|password|authorization|bearer)[^\s:=]{0,24}[:=]\s*)[^\s&]+/gi
const QUERY_RE = /([?&](?:token|key|secret|password|auth)=)[^&#\s]+/gi
/** Strip credential-looking substrings before anything is printed. */
export function redact(value: unknown): string {
  const text = value instanceof Error ? value.stack || value.message : String(value)
  return text.replace(SECRET_RE, '$1[redacted]').replace(QUERY_RE, '$1[redacted]')
}
export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function analyze(events: readonly unknown[]): any {
  const list = Array.isArray(events) ? events : []
  const counts = new Map<any, any>()
  let sized = 0
  for (const e of list) {
    if (!isRecord(e) || typeof e.type !== 'string') continue
    const family = e.type.split('/')[0]
    counts.set(family, (counts.get(family) || 0) + 1)
    if (isRecord(e.data) && typeof e.data.tokens === 'number') sized += e.data.tokens
  }
  const sources = [...counts.entries()]
    .map(([family, count]) => ({ family, count }))
    .sort((a, b) => b.count - a.count)
  const total = sources.reduce((n, s) => n + s.count, 0)
  const compaction = sources
    .filter(s => s.family === 'tool' || s.family === 'file')
    .map(s => s.family)
  return { sampledEvents: list.length, sources, total, tokensHint: sized, compactCandidates: compaction }
}

export function formatReport(a: any, opts: { json?: boolean } = {}): string {
  if (opts.json) return JSON.stringify(a, null, 2)
  const head = '[context-map] ' + a.total + ' event(s) across ' + a.sources.length + ' source families' +
    (a.tokensHint ? ' · ~' + a.tokensHint + ' tokens reported' : '')
  if (a.sources.length === 0) return head + '\n  no context events observed yet'
  const lines = a.sources.slice(0, 12).map(s =>
    '  ' + redact(s.family) + '  ' + s.count + ' event(s)' +
    (a.compactCandidates.includes(s.family) ? '  [compact candidate]' : ''))
  return [head, ...lines].join('\n')
}
