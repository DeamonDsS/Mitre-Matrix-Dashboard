// src/api/fetchMitreTechniques.ts
import type { MitreTechnique, ElasticsearchResponse } from '../types/mitre';

const PROXY_URL = 'http://localhost:4000/api/searchNew';
const MAX_BATCH = 1000;

export async function fetchMitreTechniques(
  esUrl: string,
  esIndex: string,
  filters?: {
    search?: string;
    tactic?: string;
    severity?: string;
  }
): Promise<MitreTechnique[]> {

  const query = {
    bool: { must: [] as any[] }
  };

  if (filters?.search) {
    query.bool.must.push({
      multi_match: {
        query: filters.search,
        fields: ['event.code', 'message', 'host.name', 'user.name'],
        fuzziness: 'AUTO',
      },
    });
  }

  const requestBase = {
    query: query.bool.must.length > 0 ? query : { match_all: {} },
    sort: [{ '@timestamp': { order: 'desc' } }],
    size: MAX_BATCH,
  };

  const allHits: any[] = [];
  let searchAfter: any[] | undefined = undefined;
  let batchCount = 0;

  console.log('🔍 Starting Elasticsearch scroll via proxy...');

  while (true) {
    const body = searchAfter ? { ...requestBase, search_after: searchAfter } : requestBase;

    const res = await fetch(`${PROXY_URL}?index=${encodeURIComponent(esIndex)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) throw new Error(`Elasticsearch error: ${res.statusText}`);

    const data: ElasticsearchResponse = await res.json();
    const hits = data.hits?.hits || [];
    if (hits.length === 0) break;

    allHits.push(...hits);
    batchCount++;

    console.log(`📦 Batch ${batchCount}: ${hits.length} hits (total so far ${allHits.length})`);

    // set new search_after from last hit sort value
    searchAfter = hits[hits.length - 1].sort;
    if (!searchAfter) break;
  }

  console.log(`✅ Total ${allHits.length} documents fetched from Elasticsearch`);

  // Transform to MitreTechnique[]
  return allHits.map(hit => {
    const src = hit._source || {};
    const code = src.event?.code || 'unknown';
    const message = src.message || '';
    const tactic = mapEventToTactic(code);
    const severity = mapEventToSeverity(code);

    return {
      id: hit._id,
      technique_id: `Event-${code}`,
      technique_name: src.winlog?.event_data?.ProcessName || src.event?.action || 'Unknown Event',
      description: message.slice(0, 250),
      severity,
      tactic,
      timestamp: src['@timestamp'] || new Date().toISOString(),
      platform: [src.host?.os?.family || 'Windows'],
      _raw: src,
    };
  });
}

// helper functions
function mapEventToSeverity(code: string): 'low' | 'medium' | 'high' | 'critical' {
  if (['1102', '1104'].includes(code)) return 'critical';
  if (['4672', '4740', '7045'].includes(code)) return 'high';
  if (['4625', '4723', '7001'].includes(code)) return 'medium';
  return 'low';
}

function mapEventToTactic(code: string): string {
  if (['4688', '4689'].includes(code)) return 'Execution';
  if (['7045', '4720'].includes(code)) return 'Persistence';
  if (['4672', '4732'].includes(code)) return 'Privilege Escalation';
  if (['1102', '1104'].includes(code)) return 'Defense Evasion';
  return 'Discovery';
}
