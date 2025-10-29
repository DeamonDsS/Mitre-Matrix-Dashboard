// killChainService.ts

import type { MultiIndexStats, } from "./multiMitreService";

const BACKEND_API_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

// ===========================
// Types
// ===========================

export interface KillChainStatsRequest {
  indices: string[];
  search?: string;
  tactic?: string; // e.g., 'all' or specific tactic
  severity?: string;
  dayRange?: number;
}

export interface KillChainStatsResponse {
  total: number;
  tactics: Array<{
    id: string;
    name: string;
    count: number;
    sources: Record<string, number>; // Index pattern -> count
  }>;
  sources: Record<string, number>; // Index pattern -> total
}

export interface PhaseCoverage {
  phase_id: string;
  phase_name: string;
  phase_name_th: string;
  techniques_detected: number;
  total_detections: number;
  top_techniques: Array<{
    technique_id: string;
    technique_name: string;
    count: number;
    sources: Record<string, number>;
    tactic_id?: string;
    tactic_name?: string;
  }>;
  coverage_percentage: number;
  sources: Record<string, number>;
  available_techniques: number;
  mitre_tactics: string[];
}

export interface CyberKillChainResponse {
  phases: PhaseCoverage[];
  total_detections: number;
  unique_techniques: number;
  time_range: {
    start: string;
    end: string;
  };
  indices_queried: string[];
  active_phases: number;
  methodology: string;
}


/**
 * Fetch Cyber Kill Chain coverage data from backend
 */
export async function fetchCyberKillChainCoverage(
  indices: string[],
  options: {
    dayRange?: number;
    search?: string | null;
  } = {}
): Promise<CyberKillChainResponse> {
  try {
    const validIndices = filterValidIndices(indices);
    
    if (validIndices.length === 0) {
      console.error('No valid indices provided for cyber kill chain endpoint');
      return {
        phases: [],
        total_detections: 0,
        unique_techniques: 0,
        active_phases: 0,
        time_range: { start: '', end: '' },
        indices_queried: [],
        methodology: 'Cyber Kill Chain (Lockheed Martin)'
      };
    }

    const response = await fetch(`${BACKEND_API_URL}/api/unified/cyber-kill-chain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        indices: validIndices,
        dayRange: options.dayRange || 7,
        search: options.search || null,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Backend API error for cyber kill chain: ${response.status} - ${errorText}`);
    }

    const data: CyberKillChainResponse = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching cyber kill chain coverage:', error);
    return {
      phases: [],
      total_detections: 0,
      unique_techniques: 0,
      active_phases: 0,
      time_range: { start: '', end: '' },
      indices_queried: [],
      methodology: 'Cyber Kill Chain (Lockheed Martin)'
    };
  }
}


// Cyber Kill Chain Helper Functions
// ===========================

/**
 * Get cyber kill chain coverage summary statistics
 */
export function getCyberKillChainSummary(killChain: CyberKillChainResponse): {
  activePhases: number;
  totalPhases: number;
  averageCoverage: number;
  highestPhase: PhaseCoverage | null;
  lowestCoverage: PhaseCoverage | null;
  totalDetections: number;
  uniqueTechniques: number;
  criticalPhases: PhaseCoverage[];
  completionPercentage: number;
} {
  const activePhases = killChain.phases.filter(p => p.total_detections > 0);
  
  const averageCoverage = activePhases.length > 0
    ? activePhases.reduce((sum, p) => sum + p.coverage_percentage, 0) / activePhases.length
    : 0;
  
  const highestPhase = activePhases.length > 0
    ? activePhases.reduce((max, p) => 
        p.total_detections > max.total_detections ? p : max
      )
    : null;
  
  const lowestCoverage = activePhases.length > 0
    ? activePhases.reduce((min, p) => 
        p.coverage_percentage < min.coverage_percentage ? p : min
      )
    : null;
  
  // Critical phases are those with high detection counts (potential active attacks)
  const criticalPhases = activePhases
    .filter(p => p.total_detections > 100)
    .sort((a, b) => b.total_detections - a.total_detections);
  
  // Kill chain completion percentage (how many phases are active)
  const completionPercentage = (activePhases.length / killChain.phases.length) * 100;
  
  return {
    activePhases: activePhases.length,
    totalPhases: killChain.phases.length,
    averageCoverage: Math.round(averageCoverage * 100) / 100,
    highestPhase,
    lowestCoverage,
    totalDetections: killChain.total_detections,
    uniqueTechniques: killChain.unique_techniques,
    criticalPhases,
    completionPercentage: Math.round(completionPercentage * 100) / 100
  };
}

/**
 * Filter kill chain phases by minimum detection threshold
 */
export function filterPhasesByThreshold(
  killChain: CyberKillChainResponse,
  minDetections: number
): PhaseCoverage[] {
  return killChain.phases.filter(p => p.total_detections >= minDetections);
}

/**
 * Get phases with zero coverage (blind spots)
 */
export function getKillChainBlindSpots(killChain: CyberKillChainResponse): PhaseCoverage[] {
  return killChain.phases.filter(p => p.total_detections === 0);
}

/**
 * Get phases that indicate active attack progression
 * (multiple consecutive phases are active)
 */
export function detectActiveAttackChain(killChain: CyberKillChainResponse): {
  isActive: boolean;
  activeChain: PhaseCoverage[];
  longestChain: number;
  startPhase: string | null;
  endPhase: string | null;
} {
  const activePhases = killChain.phases.filter(p => p.total_detections > 0);
  
  if (activePhases.length < 2) {
    return {
      isActive: false,
      activeChain: activePhases,
      longestChain: activePhases.length,
      startPhase: null,
      endPhase: null
    };
  }
  
  // Check for consecutive phases
  let longestChain = 0;
  let currentChain = 0;
  let startPhase: string | null = null;
  let endPhase: string | null = null;
  let tempStart: string | null = null;
  
  killChain.phases.forEach((phase, index) => {
    if (phase.total_detections > 0) {
      if (currentChain === 0) {
        tempStart = phase.phase_name;
      }
      currentChain++;
      
      if (currentChain > longestChain) {
        longestChain = currentChain;
        startPhase = tempStart;
        endPhase = phase.phase_name;
      }
    } else {
      currentChain = 0;
      tempStart = null;
    }
  });
  
  return {
    isActive: longestChain >= 3, // 3+ consecutive phases = likely active attack
    activeChain: activePhases,
    longestChain,
    startPhase,
    endPhase
  };
}

/**
 * Sort phases by detection count (descending)
 */
export function sortPhasesByActivity(phases: PhaseCoverage[]): PhaseCoverage[] {
  return [...phases].sort((a, b) => b.total_detections - a.total_detections);
}

/**
 * Sort phases by coverage percentage (descending)
 */
export function sortPhasesByCoverage(phases: PhaseCoverage[]): PhaseCoverage[] {
  return [...phases].sort((a, b) => b.coverage_percentage - a.coverage_percentage);
}

/**
 * Get color coding for coverage percentage
 */
export function getCoverageColor(coveragePercent: number): {
  color: string;
  bgColor: string;
  label: string;
  severity: 'none' | 'low' | 'medium' | 'high' | 'excellent';
} {
  if (coveragePercent === 0) {
    return { 
      color: '#94a3b8', 
      bgColor: '#f1f5f9',
      label: 'No Coverage',
      severity: 'none'
    };
  } else if (coveragePercent < 25) {
    return { 
      color: '#ef4444', 
      bgColor: '#fee2e2',
      label: 'Low Coverage',
      severity: 'low'
    };
  } else if (coveragePercent < 50) {
    return { 
      color: '#f97316', 
      bgColor: '#ffedd5',
      label: 'Fair Coverage',
      severity: 'medium'
    };
  } else if (coveragePercent < 75) {
    return { 
      color: '#eab308', 
      bgColor: '#fef9c3',
      label: 'Good Coverage',
      severity: 'high'
    };
  } else {
    return { 
      color: '#22c55e', 
      bgColor: '#dcfce7',
      label: 'Excellent Coverage',
      severity: 'excellent'
    };
  }
}

/**
 * Get threat level based on phase activity
 */
export function getPhaseThreadLevel(phase: PhaseCoverage): {
  level: 'info' | 'low' | 'medium' | 'high' | 'critical';
  color: string;
  label: string;
  description: string;
} {
  const { phase_id, total_detections } = phase;
  
  // Early phases with high activity = recon/weaponization attempts
  if (['reconnaissance', 'weaponization'].includes(phase_id)) {
    if (total_detections > 1000) {
      return {
        level: 'high',
        color: '#f97316',
        label: 'High Activity',
        description: 'Significant reconnaissance or preparation activity detected'
      };
    } else if (total_detections > 100) {
      return {
        level: 'medium',
        color: '#eab308',
        label: 'Moderate Activity',
        description: 'Moderate preparation phase activity'
      };
    }
  }
  
  // Mid-chain phases = active exploitation
  if (['delivery', 'exploitation', 'installation'].includes(phase_id)) {
    if (total_detections > 500) {
      return {
        level: 'critical',
        color: '#ef4444',
        label: 'Critical',
        description: 'Active exploitation or installation detected'
      };
    } else if (total_detections > 100) {
      return {
        level: 'high',
        color: '#f97316',
        label: 'High Priority',
        description: 'Multiple exploitation attempts detected'
      };
    }
  }
  
  // Late phases = successful breach
  if (['command_control', 'actions_objectives'].includes(phase_id)) {
    if (total_detections > 100) {
      return {
        level: 'critical',
        color: '#ef4444',
        label: 'Critical Alert',
        description: 'Active C2 or objective execution detected'
      };
    } else if (total_detections > 10) {
      return {
        level: 'high',
        color: '#f97316',
        label: 'High Alert',
        description: 'Command and control activity present'
      };
    }
  }
  
  if (total_detections > 10) {
    return {
      level: 'low',
      color: '#3b82f6',
      label: 'Low Activity',
      description: 'Some activity detected in this phase'
    };
  }
  
  return {
    level: 'info',
    color: '#94a3b8',
    label: 'No Activity',
    description: 'No significant activity detected'
  };
}

/**
 * Get phase description in Thai and English
 */
export function getPhaseDescription(phaseId: string): {
  en: string;
  th: string;
  icon: string;
} {
  const descriptions: Record<string, { en: string; th: string; icon: string }> = {
    reconnaissance: {
      en: 'Attackers gather information about targets, identifying vulnerabilities and planning attack vectors.',
      th: 'ผู้โจมตีรวบรวมข้อมูลเกี่ยวกับเป้าหมาย ระบุจุดอ่อน และวางแผนการโจมตี',
      icon: '🔍'
    },
    weaponization: {
      en: 'Creating malicious payloads and preparing attack tools for delivery.',
      th: 'สร้างโปรแกรมที่เป็นอันตรายและเตรียมเครื่องมือโจมตีสำหรับส่งมอบ',
      icon: '⚔️'
    },
    delivery: {
      en: 'Transmitting the weapon to the target environment through various vectors.',
      th: 'ส่งมอบอาวุธไปยังสภาพแวดล้อมเป้าหมายผ่านช่องทางต่างๆ',
      icon: '📦'
    },
    exploitation: {
      en: 'Triggering vulnerabilities to execute malicious code and gain initial access.',
      th: 'เรียกใช้ช่องโหว่เพื่อรันโค้ดที่เป็นอันตรายและเข้าถึงระบบ',
      icon: '💥'
    },
    installation: {
      en: 'Installing persistent malware and backdoors on compromised systems.',
      th: 'ติดตั้งมัลแวร์และช่องทางลับบนระบบที่ถูกบุกรุก',
      icon: '⚙️'
    },
    command_control: {
      en: 'Establishing communication channels for remote control of compromised systems.',
      th: 'สร้างช่องทางการสื่อสารเพื่อควบคุมระบบที่ถูกบุกรุกจากระยะไกล',
      icon: '📡'
    },
    actions_objectives: {
      en: 'Executing final objectives such as data theft, destruction, or lateral movement.',
      th: 'ดำเนินการตามเป้าหมายสุดท้าย เช่น ขโมยข้อมูล ทำลาย หรือแพร่กระจายในเครือข่าย',
      icon: '🎯'
    }
  };
  
  return descriptions[phaseId] || { en: '', th: '', icon: '❓' };
}

/**
 * Export kill chain data to CSV format
 */
export function exportKillChainToCSV(killChain: CyberKillChainResponse): string {
  const headers = [
    'Phase ID',
    'Phase Name',
    'Phase Name (Thai)',
    'Total Detections',
    'Techniques Detected',
    'Available Techniques',
    'Coverage %',
    'Top Technique',
    'Top Technique Count',
    'Sources'
  ];
  
  const rows = killChain.phases.map(phase => [
    phase.phase_id,
    phase.phase_name,
    phase.phase_name_th,
    phase.total_detections,
    phase.techniques_detected,
    phase.available_techniques,
    phase.coverage_percentage,
    phase.top_techniques[0]?.technique_name || 'N/A',
    phase.top_techniques[0]?.count || 0,
    Object.keys(phase.sources).join('; ')
  ]);
  
  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
  ].join('\n');
  
  return csvContent;
}

/**
 * Generate kill chain report summary
 */
export function generateKillChainReport(killChain: CyberKillChainResponse): {
  executiveSummary: string;
  keyFindings: string[];
  recommendations: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
} {
  const summary = getCyberKillChainSummary(killChain);
  const attackChain = detectActiveAttackChain(killChain);
  
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  if (attackChain.isActive && attackChain.longestChain >= 5) {
    riskLevel = 'critical';
  } else if (attackChain.isActive && attackChain.longestChain >= 3) {
    riskLevel = 'high';
  } else if (summary.activePhases >= 3) {
    riskLevel = 'medium';
  }
  
  const executiveSummary = `Cyber Kill Chain analysis detected activity across ${summary.activePhases} out of ${summary.totalPhases} phases, with ${summary.totalDetections.toLocaleString()} total detections covering ${summary.uniqueTechniques} unique techniques. ${attackChain.isActive ? `Active attack chain detected spanning ${attackChain.longestChain} consecutive phases from ${attackChain.startPhase} to ${attackChain.endPhase}.` : 'No continuous attack chain detected across multiple phases.'}`;
  
  const keyFindings: string[] = [];
  
  if (summary.highestPhase) {
    keyFindings.push(`Highest activity in ${summary.highestPhase.phase_name} phase (${summary.highestPhase.phase_name_th}) with ${summary.highestPhase.total_detections.toLocaleString()} detections`);
  }
  
  if (summary.criticalPhases.length > 0) {
    keyFindings.push(`${summary.criticalPhases.length} critical phases with over 100 detections each`);
  }
  
  if (attackChain.isActive) {
    keyFindings.push(`Active attack chain detected: ${attackChain.startPhase} → ${attackChain.endPhase} (${attackChain.longestChain} phases)`);
  }
  
  const blindSpots = getKillChainBlindSpots(killChain);
  if (blindSpots.length > 0) {
    keyFindings.push(`${blindSpots.length} phases with no detection coverage`);
  }
  
  const recommendations: string[] = [];
  
  if (riskLevel === 'critical' || riskLevel === 'high') {
    recommendations.push('Immediate investigation required for active attack chain');
    recommendations.push('Isolate affected systems and review C2 communications');
  }
  
  if (blindSpots.length > 0) {
    recommendations.push(`Enhance detection capabilities for: ${blindSpots.map(p => p.phase_name).join(', ')}`);
  }
  
  if (summary.averageCoverage < 50) {
    recommendations.push('Improve overall detection coverage across kill chain phases');
  }
  
  return {
    executiveSummary,
    keyFindings,
    recommendations,
    riskLevel
  };
}


// ===========================
// Helper Functions
// ===========================

/**
 * Filter out Windows indices (not supported in unified killchain)
 */
function filterValidIndices(indices: string[]): string[] {
  return indices.filter(idx => {
    const indexLower = idx.toLowerCase();
    return !indexLower.includes('windows') && !indexLower.includes('winlog');
  });
}

// ===========================
// Unified API Functions
// ===========================

/**
 * Fetch Kill Chain stats across multiple indices (Unified Endpoint)
 */
export async function fetchUnifiedKillChainStats(
  indices: string[],
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    dayRange?: number;
  } = {}
): Promise<KillChainStatsResponse> {
  try {
    const validIndices = filterValidIndices(indices);
    if (validIndices.length === 0) {
      console.error('No valid indices provided for unified kill chain stats');
      return { total: 0, tactics: [], sources: {} };
    }

    const response = await fetch(`${BACKEND_API_URL}/api/unified/killchain-stats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indices: validIndices,
        search: filters.search || null,
        tactic: filters.tactic || 'all',
        severity: filters.severity || 'all',
        dayRange: filters.dayRange || 7,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Backend API error for unified kill chain stats: ${response.status} - ${errorText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching unified kill chain stats:', error);
    return { total: 0, tactics: [], sources: {} };
  }
}

// ===========================
// Multi-Index API Functions
// ===========================

/**
 * Fetch Kill Chain stats for a single index pattern (Multi-Index)
 */
export async function fetchMultiIndexKillChainStats(
  esIndex: string,
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    dayRange?: number;
  } = {}
): Promise<MultiIndexStats> {
  try {
    const response = await fetch(`${BACKEND_API_URL}/api/multi-index/killchain-stats`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indexPattern: esIndex,
        search: filters.search || null,
        tactic: filters.tactic || 'all',
        severity: filters.severity || 'all',
        dayRange: filters.dayRange || 7,
      }),
    });

    if (!response.ok) {
      throw new Error(`Backend API error for multi-index kill chain stats: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching multi-index kill chain stats:', error);
    return { total: 0, critical: 0, high: 0, medium: 0, low: 0, tactics: [], categories: [] };
  }
}

// ===========================
// Universal Fetcher (Smart)
// ===========================

/**
 * Auto-detect endpoint and fetch Kill Chain stats
 */
export async function fetchKillChainStats(
  indices: string[] | string,
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    dayRange?: number;
  } = {},
  useMultiIndex: boolean = true
): Promise<KillChainStatsResponse | MultiIndexStats> {
  if (Array.isArray(indices) && useMultiIndex) {
    return fetchUnifiedKillChainStats(indices, filters);
  }
  if (typeof indices === 'string' && useMultiIndex) {
    return fetchMultiIndexKillChainStats(indices, filters);
  }
  // Fallback to unified if input is array but multi-index disabled
  if (Array.isArray(indices)) {
    return fetchUnifiedKillChainStats(indices, filters);
  }
  // Fallback to multi-index for single string
  return fetchMultiIndexKillChainStats(indices, filters);
}

// ===========================
// Export all
// ===========================

export default {
  fetchUnifiedKillChainStats,
  fetchMultiIndexKillChainStats,
  fetchKillChainStats
};
