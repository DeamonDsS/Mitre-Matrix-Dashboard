// backend/routes/cti.ts
import { Router, Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

// ✅ สร้าง __dirname ขึ้นมาใหม่ (ใช้ได้ใน ES Module environment)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = Router();

// ✅ ตอนนี้ path.join จะไม่พัง
const CTI_PATH = path.join(__dirname, '../../cti/enterprise-attack/enterprise-attack.json');


// Types
interface ExternalReference {
  source_name: string;
  external_id?: string;
  url?: string;
}

interface KillChainPhase {
  kill_chain_name: string;
  phase_name: string;
}

interface CTIObject {
  type: string;
  name: string;
  description: string;
  external_references?: ExternalReference[];
  x_mitre_shortname?: string;
  x_mitre_platforms?: string[];
  x_mitre_data_sources?: string[];
  x_mitre_detection?: string;
  x_mitre_version?: string;
  x_mitre_is_subtechnique?: boolean;
  x_mitre_deprecated?: boolean;
  revoked?: boolean;
  kill_chain_phases?: KillChainPhase[];
  created: string;
  modified: string;
}

interface CTIData {
  type: string;
  id: string;
  spec_version: string;
  objects: CTIObject[];
}

/**
 * GET /api/cti/enterprise-attack
 * ดึงข้อมูล enterprise-attack.json ทั้งหมด
 */
router.get('/enterprise-attack', async (req: Request, res: Response) => {
  try {
    const data = await fs.readFile(CTI_PATH, 'utf8');
    const ctiData: CTIData = JSON.parse(data);
    
    res.json(ctiData);
  } catch (error: any) {
    console.error('Error reading CTI data:', error);
    res.status(500).json({ 
      error: 'Failed to load CTI data',
      message: error.message 
    });
  }
});

/**
 * GET /api/cti/tactics
 * ดึงเฉพาะ Tactics
 */
router.get('/tactics', async (req: Request, res: Response) => {
  try {
    const data = await fs.readFile(CTI_PATH, 'utf8');
    const ctiData: CTIData = JSON.parse(data);
    
    const tactics = ctiData.objects
      .filter(obj => obj.type === 'x-mitre-tactic')
      .map(tactic => ({
        id: tactic.external_references?.find(ref => ref.source_name === 'mitre-attack')?.external_id || '',
        name: tactic.name,
        description: tactic.description,
        shortName: tactic.x_mitre_shortname || tactic.name,
        created: tactic.created,
        modified: tactic.modified
      }))
      .sort((a, b) => {
        const order = ['initial-access', 'execution', 'persistence', 'privilege-escalation', 
                      'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
                      'collection', 'command-and-control', 'exfiltration', 'impact'];
        return order.indexOf(a.shortName) - order.indexOf(b.shortName);
      });
    
    res.json(tactics);
  } catch (error: any) {
    console.error('Error reading tactics:', error);
    res.status(500).json({ 
      error: 'Failed to load tactics',
      message: error.message 
    });
  }
});

/**
 * GET /api/cti/techniques
 * ดึงเฉพาะ Techniques (ไม่รวม sub-techniques)
 * Query params:
 *   - platform: filter ตาม platform (เช่น 'windows')
 *   - tactic: filter ตาม tactic (เช่น 'initial-access')
 */
router.get('/techniques', async (req: Request, res: Response) => {
  try {
    const platform = req.query.platform as string | undefined;
    const tactic = req.query.tactic as string | undefined;
    
    const data = await fs.readFile(CTI_PATH, 'utf8');
    const ctiData: CTIData = JSON.parse(data);
    
    let techniques = ctiData.objects
      .filter(obj => 
        obj.type === 'attack-pattern' && 
        !obj.revoked && 
        !obj.x_mitre_deprecated &&
        !obj.x_mitre_is_subtechnique
      )
      .map(tech => {
        const externalId = tech.external_references?.find(
          ref => ref.source_name === 'mitre-attack'
        )?.external_id || '';
        
        const tactics = tech.kill_chain_phases?.map(
          phase => phase.phase_name
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
          url: `https://attack.mitre.org/techniques/${externalId}/`
        };
      })
      .filter(tech => tech.id.startsWith('T'));
    
    // Filter by platform
    if (platform) {
      techniques = techniques.filter(tech =>
        tech.platforms.some(p => 
          p.toLowerCase().includes(platform.toLowerCase())
        )
      );
    }
    
    // Filter by tactic
    if (tactic) {
      techniques = techniques.filter(tech =>
        tech.tactics.some(t => 
          t.toLowerCase() === tactic.toLowerCase()
        )
      );
    }
    
    res.json({
      total: techniques.length,
      techniques: techniques
    });
  } catch (error: any) {
    console.error('Error reading techniques:', error);
    res.status(500).json({ 
      error: 'Failed to load techniques',
      message: error.message 
    });
  }
});

/**
 * GET /api/cti/techniques/:id
 * ดึงรายละเอียด technique เฉพาะ ID
 */
router.get('/techniques/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    
    const data = await fs.readFile(CTI_PATH, 'utf8');
    const ctiData: CTIData = JSON.parse(data);
    
    const technique = ctiData.objects.find(obj => {
      if (obj.type !== 'attack-pattern') return false;
      const externalId = obj.external_references?.find(
        ref => ref.source_name === 'mitre-attack'
      )?.external_id;
      return externalId === id;
    });
    
    if (!technique) {
      return res.status(404).json({ error: 'Technique not found' });
    }
    
    const externalId = technique.external_references?.find(
      ref => ref.source_name === 'mitre-attack'
    )?.external_id || '';
    
    const tactics = technique.kill_chain_phases?.map(
      phase => phase.phase_name
    ) || [];
    
    res.json({
      id: externalId,
      name: technique.name,
      description: technique.description,
      tactics: tactics,
      platforms: technique.x_mitre_platforms || [],
      dataSource: technique.x_mitre_data_sources || [],
      detection: technique.x_mitre_detection || '',
      version: technique.x_mitre_version || '1.0',
      created: technique.created,
      modified: technique.modified,
      isSubtechnique: technique.x_mitre_is_subtechnique || false,
      url: `https://attack.mitre.org/techniques/${externalId}/`,
      references: technique.external_references || []
    });
  } catch (error: any) {
    console.error('Error reading technique:', error);
    res.status(500).json({ 
      error: 'Failed to load technique',
      message: error.message 
    });
  }
});

/**
 * GET /api/cti/stats
 * ดึงสถิติรวมของ CTI
 */
router.get('/stats', async (req: Request, res: Response) => {
  try {
    const data = await fs.readFile(CTI_PATH, 'utf8');
    const ctiData: CTIData = JSON.parse(data);
    
    const tactics = ctiData.objects.filter(obj => obj.type === 'x-mitre-tactic').length;
    const techniques = ctiData.objects.filter(obj => 
      obj.type === 'attack-pattern' && 
      !obj.revoked && 
      !obj.x_mitre_deprecated &&
      !obj.x_mitre_is_subtechnique
    ).length;
    const subTechniques = ctiData.objects.filter(obj => 
      obj.type === 'attack-pattern' && 
      !obj.revoked && 
      !obj.x_mitre_deprecated &&
      obj.x_mitre_is_subtechnique
    ).length;
    
    res.json({
      tactics,
      techniques,
      subTechniques,
      total: tactics + techniques + subTechniques,
      version: ctiData.spec_version || 'unknown',
      lastModified: ctiData.objects[0]?.modified || null
    });
  } catch (error: any) {
    console.error('Error reading stats:', error);
    res.status(500).json({ 
      error: 'Failed to load stats',
      message: error.message 
    });
  }
});

export { router };


