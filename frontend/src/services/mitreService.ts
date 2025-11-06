// services/mitreService.ts
// Service สำหรับดึงข้อมูลจาก MITRE ATT&CK CTI
import type { MitreStats, MitreTechniqueFramework, TechniqueStatsFramework } from "../types/mitre";
import axios from "axios";


const BACKEND_API_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

export interface MitreTechnique {
  id: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  dataSource: string[];
  detection: string;
  version: string;
  created: string;
  modified: string;
  killChainPhases: Array<{
    killChainName: string;
    phaseName: string;
  }>;
}

export interface MitreTactic {
  id: string;
  name: string;
  description: string;
  shortName: string;
}

export interface Technique {
  id: string;
  eventIds: number[];
}

export interface DateRange {
  start: string;
  end: string;
}

export interface MitreStatsRequest {
  esIndex: string;
  techniques: Technique[];
  dateRange?: DateRange;
}

export async function fetchStatsWithPayload(baseUrl: string, data: MitreStatsRequest) {
  const response = await axios.post(`${baseUrl}/api/stats-date`, data);
  return response.data;
}

/**
 * ดึงข้อมูล Tactics จาก CTI
 */
export const fetchTactics = async (): Promise<MitreTactic[]> => {
  try {
    // ดึงจาก enterprise-attack.json
    const response = await fetch('/data/enterprise-attack.json');
    // const response = await fetch('/backend/cti/enterprise-attack/enterprise-attack.json');
    const data = await response.json();
    
    // Filter เฉพาะ x-mitre-tactic objects
    const tactics = data.objects
      .filter((obj: any) => obj.type === 'x-mitre-tactic')
      .map((tactic: any) => ({
        id: tactic.external_references?.find((ref: any) => ref.source_name === 'mitre-attack')?.external_id || '',
        name: tactic.name,
        description: tactic.description,
        shortName: tactic.x_mitre_shortname || tactic.name
      }));
    
    return tactics;
  } catch (error) {
    console.error('Error fetching tactics from CTI:', error);
    return [];
  }
};

/**
 * ดึงข้อมูล Techniques จาก CTI
 */
export const fetchTechniques = async (): Promise<MitreTechnique[]> => {
  try {
    const response = await fetch('/data/enterprise-attack.json');
    const data = await response.json();
    
    // Filter เฉพาะ attack-pattern (techniques)
    const techniques = data.objects
      .filter((obj: any) => obj.type === 'attack-pattern' && !obj.revoked && !obj.x_mitre_deprecated)
      .map((tech: any) => {
        // ดึง external_id (T####)
        const externalId = tech.external_references?.find(
          (ref: any) => ref.source_name === 'mitre-attack'
        )?.external_id || '';
        
        // ดึง tactics จาก kill_chain_phases
        const tactics = tech.kill_chain_phases?.map(
          (phase: any) => phase.phase_name
        ) || [];
        
        // ดึง data sources
        const dataSources = tech.x_mitre_data_sources || [];
        
        return {
          id: externalId,
          name: tech.name,
          description: tech.description,
          tactics: tactics,
          platforms: tech.x_mitre_platforms || [],
          dataSource: dataSources,
          detection: tech.x_mitre_detection || '',
          version: tech.x_mitre_version || '1.0',
          created: tech.created,
          modified: tech.modified,
          killChainPhases: tech.kill_chain_phases || []
        };
      })
      .filter((tech: MitreTechnique) => tech.id.startsWith('T')); // เฉพาะ techniques ที่มี ID
    
    return techniques;
  } catch (error) {
    console.error('Error fetching techniques from CTI:', error);
    return [];
  }
};

/**
 * ดึง Sub-techniques (T####.###)
 */
export const fetchSubTechniques = async (): Promise<MitreTechnique[]> => {
  try {
    const response = await fetch('/data/enterprise-attack.json');
    const data = await response.json();
    
    const subTechniques = data.objects
      .filter((obj: any) => 
        obj.type === 'attack-pattern' && 
        !obj.revoked && 
        !obj.x_mitre_deprecated &&
        obj.x_mitre_is_subtechnique === true
      )
      .map((tech: any) => {
        const externalId = tech.external_references?.find(
          (ref: any) => ref.source_name === 'mitre-attack'
        )?.external_id || '';
        
        const tactics = tech.kill_chain_phases?.map(
          (phase: any) => phase.phase_name
        ) || [];
        
        return {
          id: externalId,
          name: tech.name,
          description: tech.description,
          tactics: tactics,
          platforms: tech.x_mitre_platforms || [],
          dataSource: tech.x_mitre_data_sources || [],
          detection: tech.x_mitre_detection || '',
          version: tech.x_mitre_version || '1.0',
          created: tech.created,
          modified: tech.modified,
          killChainPhases: tech.kill_chain_phases || []
        };
      });
    
    return subTechniques;
  } catch (error) {
    console.error('Error fetching sub-techniques from CTI:', error);
    return [];
  }
};

/**
 * Map tactics name to external ID
 */
export const mapTacticNameToId = (tacticName: string, tactics: MitreTactic[]): string => {
  const tactic = tactics.find(t => 
    t.shortName.toLowerCase() === tacticName.toLowerCase() ||
    t.name.toLowerCase() === tacticName.toLowerCase()
  );
  return tactic?.id || '';
};

/**
 * ดึง Windows Event IDs ที่เกี่ยวข้องกับ technique (จาก data sources)
 */
export const getRelatedEventIds = (technique: MitreTechnique): number[] => {
  // Mapping ระหว่าง MITRE Data Sources กับ Windows Event IDs
  const dataSourceToEventId: { [key: string]: number[] } = {
    'Process: Process Creation': [4688],
    'Command: Command Execution': [4688, 4104],
    'Service: Service Creation': [7045, 4697],
    'Windows Registry: Windows Registry Key Modification': [4657, 13],
    'User Account: User Account Creation': [4720, 4722],
    'User Account: User Account Authentication': [4624, 4625],
    'Logon Session: Logon Session Creation': [4624, 4648],
    'Scheduled Job: Scheduled Job Creation': [4698, 4699, 4700, 4701],
    'File: File Modification': [4663, 4656],
    'File: File Deletion': [4663, 4660],
    'Network Traffic: Network Connection Creation': [5156, 3],
    'Active Directory: Active Directory Object Access': [4662],
    'Windows Event Logs: Windows Event Log Cleared': [1102, 1100]
  };
  
  const eventIds = new Set<number>();
  
  technique.dataSource.forEach(ds => {
    const ids = dataSourceToEventId[ds];
    if (ids) {
      ids.forEach(id => eventIds.add(id));
    }
  });
  
  return Array.from(eventIds);
};

/**
 * Query Elasticsearch เพื่อนับจำนวน events ตาม technique
 */
// export const fetchTechniqueStats = async (
//   esUrl: string,
//   esIndex: string,
//   techniques: MitreTechnique[]
// ) => {
//   try {
//     const stats: { [key: string]: any } = {};
    
//     // สร้าง query สำหรับแต่ละ technique
//     const promises = techniques.map(async (tech) => {
//       const eventIds = getRelatedEventIds(tech);
      
//       if (eventIds.length === 0) {
//         stats[tech.id] = { count: 0, severity: 'none', lastSeen: null };
//         return;
//       }
      
//       // Query Elasticsearch
//       const query = {
//         query: {
//           bool: {
//             must: [
//               {
//                 terms: {
//                   'event.code': eventIds
//                 }
//               },
//               {
//                 range: {
//                   '@timestamp': {
//                     gte: 'now-7d' // ข้อมูล 7 วันล่าสุด
//                   }
//                 }
//               }
//             ]
//           }
//         },
//         size: 0,
//         aggs: {
//           latest: {
//             max: {
//               field: '@timestamp'
//             }
//           }
//         }
//       };
      
//       const response = await fetch(`${esUrl}/${esIndex}/_search`, {
//         method: 'POST',
//         headers: {
//           'Content-Type': 'application/json'
//         },
//         body: JSON.stringify(query)
//       });
      
//       const data = await response.json();
//       const count = data.hits?.total?.value || 0;
      
//       stats[tech.id] = {
//         count: count,
//         severity: count > 70 ? 'critical' : count > 40 ? 'high' : count > 10 ? 'medium' : count > 0 ? 'low' : 'none',
//         lastSeen: data.aggregations?.latest?.value_as_string || null,
//         eventIds: eventIds
//       };
//     });
    
//     await Promise.all(promises);
//     return stats;
//   } catch (error) {
//     console.error('Error fetching technique stats:', error);
//     return {};
//   }
// };


export const fetchAllTechniqueStats = async (
  techniques: MitreTechniqueFramework[],
  esIndex: string,
): Promise<Record<string, TechniqueStatsFramework>> => {
  try {
    // 1. เตรียมข้อมูล (Payload) ที่จะส่งไปให้ FastAPI
    // เราต้องการแค่ id และ eventIds ของแต่ละเทคนิค
    const techniquesPayload = techniques.map(tech => ({
      id: tech.id,
      eventIds: tech.eventIds || [],
    }));

    // 2. เรียกไปยัง Endpoint ของ FastAPI เพียงครั้งเดียว
    const response = await fetch(`${BACKEND_API_URL}'/api/technique-stats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        esIndex: esIndex,
        techniques: techniquesPayload,
      } ),
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error("Backend Error:", errorData);
      throw new Error('Failed to fetch technique stats from backend');
    }

    // 3. Backend จะตอบกลับมาเป็น Object ที่มีสถิติของทุกเทคนิคเรียบร้อย
    const allStats = await response.json();
    return allStats;

  } catch (error) {
    console.error('Error fetching all technique stats:', error);
    // คืนค่าว่างในกรณีที่เกิดข้อผิดพลาด เพื่อไม่ให้แอปพัง
    return {};
  }
};

export const fetchAllTechniqueStatsWithDateRange = async (
  techniques: MitreTechniqueFramework[],
  esIndex: string,
  dateRange: { start: string; end: string }
): Promise<Record<string, TechniqueStatsFramework>> => {
  try {
    // 1. เตรียมข้อมูล (Payload) ที่จะส่งไปให้ FastAPI
    // เราต้องการแค่ id และ eventIds ของแต่ละเทคนิค
    const techniquesPayload = techniques.map(tech => ({
      id: tech.id,
      eventIds: tech.eventIds || [],
    }));

    // 2. แปลง date range เป็น timestamp สำหรับ Elasticsearch
    const startDate = new Date(dateRange.start);
    startDate.setHours(0, 0, 0, 0); // เริ่มต้นวัน
    
    const endDate = new Date(dateRange.end);
    endDate.setHours(23, 59, 59, 999); // สิ้นสุดวัน

    // 3. เรียกไปยัง Endpoint ของ FastAPI เพียงครั้งเดียว พร้อม date range
    const response = await fetch('http://localhost:8000/api/technique-stats-date', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        esIndex: esIndex,
        techniques: techniquesPayload,
        dateRange: {
          start: startDate.toISOString(),
          end: endDate.toISOString(),
        },
      }),
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error("Backend Error:", errorData);
      throw new Error('Failed to fetch technique stats from backend');
    }

    // 4. Backend จะตอบกลับมาเป็น Object ที่มีสถิติของทุกเทคนิคเรียบร้อย
    const allStats = await response.json();
    return allStats;

  } catch (error) {
    console.error('Error fetching all technique stats:', error);
    // คืนค่าว่างในกรณีที่เกิดข้อผิดพลาด เพื่อไม่ให้แอปพัง
    return {};
  }
};

export async function fetchTechniqueStatsFramework(
  eventIds: number[],
  esUrl: string,
  esIndex: string
): Promise<TechniqueStatsFramework> {
  if (!eventIds.length) {
    return { count: 0, severity: 'none', lastSeen: null };
  }

  try {
    const query = {
      query: {
        bool: {
          must: [
            { terms: { 'event.code': eventIds } },
            { range: { '@timestamp': { gte: 'now-7d' } } }
          ]
        }
      },
      size: 0,
      aggs: {
        latest: {
          max: { field: '@timestamp' }
        }
      }
    };

    const response = await fetch(`${esUrl}/${esIndex}/_search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(query)
    });

    if (response.ok) {
      const data = await response.json();
      const count = data.hits?.total?.value || 0;

      return {
        count,
        severity: count > 70 ? 'critical' : count > 40 ? 'high' : count > 10 ? 'medium' : count > 0 ? 'low' : 'none',
        lastSeen: data.aggregations?.latest?.value_as_string || null
      };
    }
  } catch (err) {
    console.warn('Error fetching stats:', err);
  }

  return { count: 0, severity: 'none', lastSeen: null };
}

export async function fetchStats(
  esIndex: string,
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    dayRange?: number; // ✅ เพิ่ม dayRange parameter
  }
): Promise<MitreStats> {
  try {
    const url = `${BACKEND_API_URL}/api/stats-date?index=${encodeURIComponent(esIndex)}`;
    
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        search: filters.search || null,
        tactic: filters.tactic || 'all',
        severity: filters.severity || 'all',
        dayRange: filters.dayRange || 7, // ✅ ส่ง dayRange ไปด้วย (default 7 วัน)
      }),
    });

    if (!response.ok) {
      throw new Error(`Backend API error for stats: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching stats from Backend API:', error);
    return { total: 0, critical: 0, high: 0, medium: 0, low: 0, tactics: 0 };
  }
}

/**
 * ดึงข้อมูล techniques ที่ filter ตาม platform
 */
export const getTechniquesByPlatform = (
  techniques: MitreTechnique[],
  platform: string
): MitreTechnique[] => {
  return techniques.filter(tech => 
    tech.platforms.some(p => 
      p.toLowerCase().includes(platform.toLowerCase())
    )
  );
};

/**
 * ดึงข้อมูล techniques ที่ filter ตาม tactic
 */
export const getTechniquesByTactic = (
  techniques: MitreTechnique[],
  tacticName: string
): MitreTechnique[] => {
  return techniques.filter(tech =>
    tech.tactics.some(t => 
      t.toLowerCase() === tacticName.toLowerCase()
    )
  );
};