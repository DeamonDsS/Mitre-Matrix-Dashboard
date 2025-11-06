// postgresKillChainService.ts
// Service for PostgreSQL Cyber Kill Chain endpoint (Keyword Mapping Only)

const BACKEND_API_URL = import.meta.env.POSTGRES_API_URL || 'http://localhost:8001';

// ===========================
// Request/Response Types
// ===========================

export interface PostgresKillChainRequest {
  dayRange: number;
  search?: string | null;
  tactic?: string;
  severity?: string;
}

export interface DetectionSource {
  source_text: string;
  count: number;
  source_type: 'alert_category' | 'event_name' | 'event_objective';
}

export interface PhaseCoverage {
  phase_id: string;
  phase_name: string;
  phase_name_th: string;
  total_detections: number;
  sources: Record<string, number>; // crowdstrike, palo-xsiam, suricata counts
  detection_methods: string[]; // Keywords that triggered this phase
  top_detection_sources: DetectionSource[]; // Top specific sources
}

export interface PostgresCyberKillChainResponse {
  phases: PhaseCoverage[];
  total_detections: number;
  time_range: {
    start: string;
    end: string;
  };
  active_phases: number;
  methodology: string;
}

export interface KillChainSummaryPhase {
  phase_id: string;
  phase_name: string;
  phase_name_th: string;
  detections: number;
  top_detection_method: string | null;
  source_breakdown: Record<string, number>;
}

export interface PostgresKillChainSummaryResponse {
  summary: KillChainSummaryPhase[];
  total_detections: number;
  active_phases: number;
  time_range: {
    start: string;
    end: string;
  };
}

// ===========================
// API Functions
// ===========================

/**
 * Fetch Cyber Kill Chain coverage from PostgreSQL (Keyword Mapping Only)
 */
export async function fetchPostgresKillChain(
  options: {
    dayRange?: number;
    search?: string | null;
    tactic?: string;
    severity?: string;
  } = {}
): Promise<PostgresCyberKillChainResponse> {
  try {
    const requestBody: PostgresKillChainRequest = {
      dayRange: options.dayRange || 7,
      search: options.search || null,
      tactic: options.tactic || 'all',
      severity: options.severity || 'all',
    };

    const response = await fetch(`${BACKEND_API_URL}/api/postgres/cyber-kill-chain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Backend API error: ${response.status} - ${errorText}`);
    }

    const data: PostgresCyberKillChainResponse = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching PostgreSQL cyber kill chain:', error);
    return {
      phases: [],
      total_detections: 0,
      active_phases: 0,
      time_range: { start: '', end: '' },
      methodology: 'Cyber Kill Chain (Keyword Mapping Only)',
    };
  }
}

// ===========================
// Analysis & Helper Functions
// ===========================

/**
 * Get comprehensive kill chain statistics
 */
export function getKillChainStatistics(killChain: PostgresCyberKillChainResponse): {
  activePhases: number;
  totalPhases: number;
  highestPhase: PhaseCoverage | null;
  totalDetections: number;
  criticalPhases: PhaseCoverage[];
  completionPercentage: number;
  sourcesBreakdown: Record<string, number>;
  topDetectionMethods: Array<{ method: string; count: number }>;
} {
  const activePhases = killChain.phases.filter(p => p.total_detections > 0);
  
  const highestPhase = activePhases.length > 0
    ? activePhases.reduce((max, p) => 
        p.total_detections > max.total_detections ? p : max
      )
    : null;
  
  // Critical phases (high detection counts)
  const criticalPhases = activePhases
    .filter(p => p.total_detections > 100)
    .sort((a, b) => b.total_detections - a.total_detections);
  
  // Kill chain completion percentage
  const completionPercentage = (activePhases.length / killChain.phases.length) * 100;
  
  // Aggregate sources across all phases
  const sourcesBreakdown: Record<string, number> = {};
  killChain.phases.forEach(phase => {
    Object.entries(phase.sources).forEach(([source, count]) => {
      sourcesBreakdown[source] = (sourcesBreakdown[source] || 0) + count;
    });
  });
  
  // Get top detection methods across all phases
  const methodCounts: Record<string, number> = {};
  killChain.phases.forEach(phase => {
    phase.top_detection_sources.forEach(source => {
      methodCounts[source.source_text] = (methodCounts[source.source_text] || 0) + source.count;
    });
  });
  
  const topDetectionMethods = Object.entries(methodCounts)
    .map(([method, count]) => ({ method, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  
  return {
    activePhases: activePhases.length,
    totalPhases: killChain.phases.length,
    highestPhase,
    totalDetections: killChain.total_detections,
    criticalPhases,
    completionPercentage: Math.round(completionPercentage * 100) / 100,
    sourcesBreakdown,
    topDetectionMethods,
  };
}

/**
 * Detect active attack progression
 */
export function detectAttackProgression(killChain: PostgresCyberKillChainResponse): {
  isActive: boolean;
  activeChain: PhaseCoverage[];
  longestChain: number;
  startPhase: string | null;
  endPhase: string | null;
  consecutivePhases: string[];
  riskScore: number;
} {
  const activePhases = killChain.phases.filter(p => p.total_detections > 0);
  
  if (activePhases.length < 2) {
    return {
      isActive: false,
      activeChain: activePhases,
      longestChain: activePhases.length,
      startPhase: null,
      endPhase: null,
      consecutivePhases: [],
      riskScore: 0,
    };
  }
  
  // Check for consecutive phases
  let longestChain = 0;
  let currentChain = 0;
  let startPhase: string | null = null;
  let endPhase: string | null = null;
  let tempStart: string | null = null;
  const consecutivePhases: string[] = [];
  let tempConsecutive: string[] = [];
  
  killChain.phases.forEach((phase) => {
    if (phase.total_detections > 0) {
      if (currentChain === 0) {
        tempStart = phase.phase_name;
        tempConsecutive = [];
      }
      currentChain++;
      tempConsecutive.push(phase.phase_name);
      
      if (currentChain > longestChain) {
        longestChain = currentChain;
        startPhase = tempStart;
        endPhase = phase.phase_name;
        consecutivePhases.length = 0;
        consecutivePhases.push(...tempConsecutive);
      }
    } else {
      currentChain = 0;
      tempStart = null;
      tempConsecutive = [];
    }
  });
  
  // Calculate risk score based on:
  // - Number of consecutive phases
  // - Presence of critical late-stage phases
  // - Total detection count
  let riskScore = 0;
  
  if (longestChain >= 5) riskScore += 40;
  else if (longestChain >= 3) riskScore += 25;
  else if (longestChain >= 2) riskScore += 10;
  
  // Check for late-stage phases (C2, Actions on Objectives)
  const lateStagePhases = activePhases.filter(p => 
    ['command_control', 'actions_objectives'].includes(p.phase_id)
  );
  if (lateStagePhases.length > 0) {
    riskScore += 30;
    if (lateStagePhases.some(p => p.total_detections > 100)) {
      riskScore += 20;
    }
  }
  
  // Total detection volume
  if (killChain.total_detections > 1000) riskScore += 10;
  
  riskScore = Math.min(riskScore, 100);
  
  return {
    isActive: longestChain >= 3,
    activeChain: activePhases,
    longestChain,
    startPhase,
    endPhase,
    consecutivePhases,
    riskScore,
  };
}

/**
 * Get phases with no coverage (blind spots)
 */
export function getBlindSpots(killChain: PostgresCyberKillChainResponse): PhaseCoverage[] {
  return killChain.phases.filter(p => p.total_detections === 0);
}

/**
 * Filter phases by minimum detection threshold
 */
export function filterPhasesByThreshold(
  killChain: PostgresCyberKillChainResponse,
  minDetections: number
): PhaseCoverage[] {
  return killChain.phases.filter(p => p.total_detections >= minDetections);
}

/**
 * Sort phases by activity (detection count)
 */
export function sortPhasesByActivity(phases: PhaseCoverage[]): PhaseCoverage[] {
  return [...phases].sort((a, b) => b.total_detections - a.total_detections);
}

/**
 * Get color coding for detection volume
 */
export function getDetectionVolumeColorScheme(detectionCount: number): {
  color: string;
  bgColor: string;
  label: string;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
} {
  if (detectionCount === 0) {
    return { 
      color: '#94a3b8', 
      bgColor: '#f1f5f9',
      label: 'No Detections',
      severity: 'none'
    };
  } else if (detectionCount < 10) {
    return { 
      color: '#3b82f6', 
      bgColor: '#dbeafe',
      label: 'Low Volume',
      severity: 'low'
    };
  } else if (detectionCount < 50) {
    return { 
      color: '#eab308', 
      bgColor: '#fef9c3',
      label: 'Medium Volume',
      severity: 'medium'
    };
  } else if (detectionCount < 200) {
    return { 
      color: '#f97316', 
      bgColor: '#ffedd5',
      label: 'High Volume',
      severity: 'high'
    };
  } else {
    return { 
      color: '#ef4444', 
      bgColor: '#fee2e2',
      label: 'Critical Volume',
      severity: 'critical'
    };
  }
}

/**
 * Get threat level for a phase
 */
export function getPhaseThreadLevel(phase: PhaseCoverage): {
  level: 'info' | 'low' | 'medium' | 'high' | 'critical';
  color: string;
  label: string;
  description: string;
} {
  const { phase_id, total_detections } = phase;
  
  // Early phases
  if (['reconnaissance', 'weaponization'].includes(phase_id)) {
    if (total_detections > 1000) {
      return {
        level: 'high',
        color: '#f97316',
        label: 'High Activity',
        description: 'Significant reconnaissance or preparation detected'
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
  
  // Mid-chain phases
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
  
  // Late phases
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
      description: 'Some activity detected'
    };
  }
  
  return {
    level: 'info',
    color: '#94a3b8',
    label: 'No Activity',
    description: 'No significant activity'
  };
}

/**
 * Get phase metadata
 */
export function getPhaseMetadata(phaseId: string): {
  description_en: string;
  description_th: string;
  icon: string;
  examples: string[];
} {
  const metadata: Record<string, any> = {
    reconnaissance: {
      description_en: 'Attackers gather intelligence about targets, identifying vulnerabilities and planning attack vectors.',
      description_th: 'ผู้โจมตีรวบรวมข้อมูลเกี่ยวกับเป้าหมาย ระบุจุดอ่อน และวางแผนการโจมตี',
      icon: '🔍',
      examples: ['Port scanning', 'OSINT gathering', 'Network enumeration']
    },
    weaponization: {
      description_en: 'Creating malicious payloads and preparing attack tools for delivery.',
      description_th: 'สร้างโปรแกรมที่เป็นอันตรายและเตรียมเครื่องมือโจมตีสำหรับส่งมอบ',
      icon: '⚔️',
      examples: ['Malware creation', 'Exploit bundling', 'Payload preparation']
    },
    delivery: {
      description_en: 'Transmitting the weapon to the target environment through various vectors.',
      description_th: 'ส่งมอบอาวุธไปยังสภาพแวดล้อมเป้าหมายผ่านช่องทางต่างๆ',
      icon: '📦',
      examples: ['Phishing emails', 'Drive-by downloads', 'USB drops']
    },
    exploitation: {
      description_en: 'Triggering vulnerabilities to execute malicious code and gain initial access.',
      description_th: 'เรียกใช้ช่องโหว่เพื่อรันโค้ดที่เป็นอันตรายและเข้าถึงระบบ',
      icon: '💥',
      examples: ['CVE exploitation', 'Zero-day attacks', 'Credential abuse']
    },
    installation: {
      description_en: 'Installing persistent malware and backdoors on compromised systems.',
      description_th: 'ติดตั้งมัลแวร์และช่องทางลับบนระบบที่ถูกบุกรุก',
      icon: '⚙️',
      examples: ['Backdoor installation', 'Rootkit deployment', 'Persistence mechanisms']
    },
    command_control: {
      description_en: 'Establishing communication channels for remote control of compromised systems.',
      description_th: 'สร้างช่องทางการสื่อสารเพื่อควบคุมระบบที่ถูกบุกรุกจากระยะไกล',
      icon: '📡',
      examples: ['C2 beaconing', 'Lateral movement', 'Remote access']
    },
    actions_objectives: {
      description_en: 'Executing final objectives such as data theft, destruction, or lateral movement.',
      description_th: 'ดำเนินการตามเป้าหมายสุดท้าย เช่น ขโมยข้อมูล ทำลาย หรือแพร่กระจายในเครือข่าย',
      icon: '🎯',
      examples: ['Data exfiltration', 'Ransomware deployment', 'System destruction']
    }
  };
  
  return metadata[phaseId] || { 
    description_en: '', 
    description_th: '', 
    icon: '❓',
    examples: []
  };
}

/**
 * Generate executive report
 */
export function generateExecutiveReport(killChain: PostgresCyberKillChainResponse): {
  executiveSummary: string;
  keyFindings: string[];
  recommendations: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskScore: number;
} {
  const stats = getKillChainStatistics(killChain);
  const attack = detectAttackProgression(killChain);
  const blindSpots = getBlindSpots(killChain);
  
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  
  if (attack.riskScore >= 70) {
    riskLevel = 'critical';
  } else if (attack.riskScore >= 50) {
    riskLevel = 'high';
  } else if (attack.riskScore >= 30) {
    riskLevel = 'medium';
  }
  
  const executiveSummary = `Analysis of ${killChain.total_detections.toLocaleString()} detections across ${stats.activePhases} active phases using keyword-based classification. ${attack.isActive ? `Critical: Active attack chain detected spanning ${attack.longestChain} consecutive phases (${attack.startPhase} → ${attack.endPhase}).` : 'No continuous attack chain detected.'} Risk score: ${attack.riskScore}/100.`;
  
  const keyFindings: string[] = [];
  
  if (stats.highestPhase) {
    keyFindings.push(`Highest activity: ${stats.highestPhase.phase_name} (${stats.highestPhase.total_detections.toLocaleString()} detections)`);
  }
  
  if (attack.isActive) {
    keyFindings.push(`Active attack progression: ${attack.consecutivePhases.join(' → ')}`);
  }
  
  if (stats.criticalPhases.length > 0) {
    keyFindings.push(`${stats.criticalPhases.length} critical phases with 100+ detections`);
  }
  
  if (blindSpots.length > 0) {
    keyFindings.push(`${blindSpots.length} blind spots detected: ${blindSpots.map(p => p.phase_name).join(', ')}`);
  }
  
  if (stats.topDetectionMethods.length > 0) {
    const topMethod = stats.topDetectionMethods[0];
    keyFindings.push(`Most frequent detection: ${topMethod.method} (${topMethod.count} occurrences)`);
  }
  
  const recommendations: string[] = [];
  
  if (riskLevel === 'critical') {
    recommendations.push('🚨 Immediate action required: Isolate affected systems');
    recommendations.push('🔍 Conduct full incident response and forensic analysis');
  }
  
  if (riskLevel === 'high') {
    recommendations.push('⚠️ Investigate attack chain progression immediately');
    recommendations.push('🔒 Review and strengthen access controls');
  }
  
  if (blindSpots.length > 0) {
    recommendations.push(`📊 Enhance detection for: ${blindSpots.map(p => p.phase_name).join(', ')}`);
  }
  
  if (stats.criticalPhases.some(p => p.phase_id === 'command_control' || p.phase_id === 'actions_objectives')) {
    recommendations.push('🔴 Review C2 communications and data exfiltration logs');
  }
  
  if (stats.completionPercentage < 50) {
    recommendations.push('🎯 Expand detection coverage across more kill chain phases');
  }
  
  return {
    executiveSummary,
    keyFindings,
    recommendations,
    riskLevel,
    riskScore: attack.riskScore,
  };
}

/**
 * Get detection source breakdown for a phase
 */
export function getDetectionSourceBreakdown(phase: PhaseCoverage): {
  byType: Record<string, number>;
  bySource: Record<string, number>;
  topSources: DetectionSource[];
} {
  const byType: Record<string, number> = {
    alert_category: 0,
    event_name: 0,
    event_objective: 0,
  };
  
  phase.top_detection_sources.forEach(source => {
    byType[source.source_type] = (byType[source.source_type] || 0) + source.count;
  });
  
  return {
    byType,
    bySource: phase.sources,
    topSources: phase.top_detection_sources.slice(0, 5),
  };
}

/**
 * Export to CSV
 */
export function exportToCSV(killChain: PostgresCyberKillChainResponse): string {
  const headers = [
    'Phase ID',
    'Phase Name',
    'Phase Name (TH)',
    'Total Detections',
    'Top Detection Method',
    'Detection Method Count',
    'Sources',
    'CrowdStrike Count',
    'Palo-XSIAM Count',
    'Suricata Count'
  ];
  
  const rows = killChain.phases.map(phase => [
    phase.phase_id,
    phase.phase_name,
    phase.phase_name_th,
    phase.total_detections,
    phase.top_detection_sources[0]?.source_text || 'N/A',
    phase.top_detection_sources[0]?.count || 0,
    Object.keys(phase.sources).join('; '),
    phase.sources.crowdstrike || 0,
    phase.sources['palo-xsiam'] || 0,
    phase.sources.suricata || 0
  ]);
  
  return [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
  ].join('\n');
}

/**
 * Export to JSON
 */
export function exportToJSON(killChain: PostgresCyberKillChainResponse): string {
  return JSON.stringify(killChain, null, 2);
}

// ===========================
// Export All
// ===========================

export default {
  fetchPostgresKillChain,
  getKillChainStatistics,
  detectAttackProgression,
  getBlindSpots,
  filterPhasesByThreshold,
  sortPhasesByActivity,
  getDetectionVolumeColorScheme,
  getPhaseThreadLevel,
  getPhaseMetadata,
  generateExecutiveReport,
  getDetectionSourceBreakdown,
  exportToCSV,
  exportToJSON,
};