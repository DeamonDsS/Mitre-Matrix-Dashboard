import axios from 'axios';
import type { MitreTechnique, FilterState } from '../types/mitre';

export const fetchMitreTechniques = async (
  esUrl: string,
  esIndex: string,
  filters: FilterState
): Promise<MitreTechnique[]> => {
  try {
    const query = {
      size: 50,  // ดึงน้อย ๆ ก่อน
      query: {
        bool: {
          must: [
            { term: { 'technique_id.keyword': 'T1059.001' } } // PowerShell only
          ]
        }
      }
    };

    const resp = await axios.post(`${esUrl}/${esIndex}/_search`, query);
    const hits = resp.data.hits.hits;

    return hits.map((hit: any) => ({
      id: hit._id,
      technique_id: hit._source.technique_id,
      technique_name: hit._source.technique_name,
      tactic: hit._source.tactic,
      description: hit._source.description,
      severity: hit._source.severity,
      timestamp: hit._source.timestamp,
      source: hit._source.source,
      platform: hit._source.platform
    }));
  } catch (error) {
    console.error(error);
    return [];
  }
};
