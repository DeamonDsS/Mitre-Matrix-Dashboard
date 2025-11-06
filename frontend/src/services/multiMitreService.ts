import type { 
  MitreStats, 
  MitreTechniqueFramework, 
  TechniqueStatsFramework 
} from "../types/mitre";

const BACKEND_API_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

// ===========================
// Types for Multi-Index
// ===========================

export interface MultiIndexStatsRequest {
  search?: string;
  tactic?: string;
  severity?: string;
  dayRange?: number;
  indexPattern: string;
}

export interface MultiIndexTechniqueRequest {
  esIndex: string;
  techniques: Array<{
    id: string;
    eventIds: number[];
  }>;
  dateRange?: {
    start: string;
    end: string;
  };
  indexPattern: string;
}

export interface MultiIndexSearchResult {
  total: number;
  page: number;
  size: number;
  results: Array<{
    id: string;
    timestamp: string;
    tactic?: string;
    tacticId?: string;
    technique?: string;
    techniqueId?: string;
    category?: string;
    host?: string;
    message?: string;
  }>;
}

export interface MultiIndexStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  tactics: Array<{
    name: string;
    count: number;
  }>;
  categories?: Array<{
    name: string;
    count: number;
  }>;
}

// ===========================
// Types for Unified Endpoints
// ===========================

export interface UnifiedTechniqueRequest {
  indices: string[];
  techniques: Array<{
    id: string;
    eventIds: number[];
  }>;
  dateRange?: {
    start: string;
    end: string;
  };
}

export interface UnifiedTechniqueStats extends TechniqueStatsFramework {
  sources: Record<string, number>;
}

export interface UnifiedStatsRequest {
  indices: string[];
  search?: string;
  tactic?: string;
  severity?: string;
  dayRange?: number;
}

export interface SoloSummaryStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  tactics: number;
}

export interface UnifiedStats {
  total: number;
  tactics: Array<{
    id: string;
    name: string;
    count: number;
    sources: Record<string, number>;
  }>;
  sources: Record<string, number>;
  breakdown: Array<{
    index: string;
    total: number;
    tactics: number;
  }>;
}

export interface UnifiedSearchRequest {
  indices: string[];
  search?: string;
  tactic?: string;
  severity?: string;
  size?: number;
  page?: number;
}

export interface UnifiedSearchResult {
  total: number;
  page: number;
  size: number;
  results: Array<{
    id: string;
    index: string;
    timestamp: string;
    tactic?: string;
    tacticId?: string;
    technique?: string;
    techniqueId?: string;
    category?: string;
    host?: string;
    message?: string;
  }>;
  sources: string[];
}

// ===========================
// Types for Top Techniques
// ===========================

export interface TopTechniqueResult {
  technique_id: string;
  technique_name: string;
  count: number;
  tactic_ids: string[];
  tactic_names: string[];
  sources: Record<string, number>;
}

export interface TopTechniquesResponse {
  techniques: TopTechniqueResult[];
  total_detections: number;
  time_range: {
    start: string;
    end: string;
  };
  limit: number;
  tactic_filter: string;
}

export interface TopTechniquesRequest {
  indices: string[];
  dayRange?: number;
  limit?: number;
  tactic?: string;
}

// ===========================
// Types for Kill Chain Coverage
// ===========================

export interface TechniqueInTactic {
  technique_id: string;
  technique_name: string;
  count: number;
  sources: Record<string, number>;
}

export interface TacticCoverage {
  tactic_id: string;
  tactic_name: string;
  techniques_detected: number;
  total_detections: number;
  top_techniques: TechniqueInTactic[];
  coverage_percentage: number;
  sources: Record<string, number>;
  available_techniques: number;
}

export interface KillChainResponse {
  tactics: TacticCoverage[];
  total_detections: number;
  unique_techniques: number;
  total_tactics: number;
  time_range: {
    start: string;
    end: string;
  };
  indices_queried: string[];
}

export interface KillChainRequest {
  indices: string[];
  dayRange?: number;
  search?: string | null;
}

// ===========================
// Helper Functions
// ===========================

/**
 * Detect index pattern type from index name
 */
export function detectIndexPattern(esIndex: string): string {
  const indexLower = esIndex.toLowerCase();
  
  if (indexLower.includes('palo-xsiam')) {
    return 'palo-xsiam';
  } else if (indexLower.includes('crowdstrike')) {
    return 'crowdstrike';
  } else if (indexLower.includes('winlog') || indexLower.includes('windows')) {
    return 'windows';
  }
  
  console.warn(`Unknown index pattern: ${esIndex}, defaulting to legacy Windows endpoint`);
  return 'windows';
}

/**
 * Filter out Windows indices from array
 */
export function filterValidIndices(indices: string[]): string[] {
  return indices.filter(idx => {
    const indexLower = idx.toLowerCase();
    return !indexLower.includes('windows') && !indexLower.includes('winlog');
  });
}

/**
 * Format date for Elasticsearch query
 */
function formatDateForES(date: Date): string {
  return date.toISOString();
}

/**
 * Convert MultiIndexStats to legacy MitreStats format
 */
export function convertToLegacyStats(stats: MultiIndexStats): MitreStats {
  return {
    total: stats.total,
    critical: stats.critical,
    high: stats.high,
    medium: stats.medium,
    low: stats.low,
    tactics: stats.tactics.length,
  };
}

/**
 * Convert legacy MitreStats to MultiIndexStats format
 */
export function convertToMultiIndexStats(
  stats: MitreStats,
  tacticsArray: Array<{ name: string; count: number }> = []
): MultiIndexStats {
  return {
    total: stats.total,
    critical: stats.critical,
    high: stats.high,
    medium: stats.medium,
    low: stats.low,
    tactics: tacticsArray,
    categories: [],
  };
}

/**
 * Convert UnifiedStats to MultiIndexStats format
 */
export function convertUnifiedToMultiIndexStats(stats: UnifiedStats): MultiIndexStats {
  return {
    total: stats.total,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    tactics: stats.tactics.map(t => ({ name: t.id, count: t.count })),
    categories: [],
  };
}

// ===========================
// Unified API Functions (NEW - Recommended)
// ===========================

/**
 * Fetch technique statistics across multiple index patterns
 * Combines data from Palo Alto XSIAM, CrowdStrike, and other supported sources
 */
export const fetchUnifiedTechniqueStats = async (
  techniques: MitreTechniqueFramework[],
  indices: string[],
  dateRange: { start: string; end: string }
): Promise<Record<string, UnifiedTechniqueStats>> => {
  try {
    const validIndices = filterValidIndices(indices);
    
    if (validIndices.length === 0) {
      console.error('No valid indices provided for unified endpoint');
      return {};
    }

    const techniquesPayload = techniques.map(tech => ({
      id: tech.id,
      eventIds: tech.eventIds || [],
    }));

    const startDate = new Date(dateRange.start);
    startDate.setHours(0, 0, 0, 0);
    
    const endDate = new Date(dateRange.end);
    endDate.setHours(23, 59, 59, 999);

    const response = await fetch(`${BACKEND_API_URL}/api/unified/technique-stats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        indices: validIndices,
        techniques: techniquesPayload,
        dateRange: {
          start: formatDateForES(startDate),
          end: formatDateForES(endDate),
        },
      }),
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error("Backend Error:", errorData);
      throw new Error(`Failed to fetch unified technique stats: ${response.status}`);
    }

    const allStats = await response.json();
    return allStats;
  } catch (error) {
    console.error('Error fetching unified technique stats:', error);
    return {};
  }
};

/**
 * Fetch overall statistics across multiple index patterns
 */
export async function fetchUnifiedStats(
  indices: string[],
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    dayRange?: number;
  }
): Promise<UnifiedStats> {
  try {
    const validIndices = filterValidIndices(indices);
    
    if (validIndices.length === 0) {
      console.error('No valid indices provided for unified endpoint');
      return {
        total: 0,
        tactics: [],
        sources: {},
        breakdown: []
      };
    }

    const response = await fetch(`${BACKEND_API_URL}/api/unified/stats`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json' 
      },
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
      throw new Error(`Backend API error for unified stats: ${response.status} - ${errorText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching unified stats:', error);
    return {
      total: 0,
      tactics: [],
      sources: {},
      breakdown: []
    };
  }
}

/**
 * Search MITRE detections across multiple index patterns
 */
export async function searchUnified(
  indices: string[],
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    size?: number;
    page?: number;
  }
): Promise<UnifiedSearchResult> {
  try {
    const validIndices = filterValidIndices(indices);
    
    if (validIndices.length === 0) {
      console.error('No valid indices provided for unified search');
      return {
        total: 0,
        page: 1,
        size: 10,
        results: [],
        sources: []
      };
    }

    const response = await fetch(`${BACKEND_API_URL}/api/unified/search`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json' 
      },
      body: JSON.stringify({
        indices: validIndices,
        search: filters.search || null,
        tactic: filters.tactic || 'all',
        severity: filters.severity || 'all',
        size: filters.size || 10,
        page: filters.page || 1,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Backend API error for unified search: ${response.status} - ${errorText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error in unified search:', error);
    return {
      total: 0,
      page: 1,
      size: 10,
      results: [],
      sources: []
    };
  }
}

/**
 * Fetch top N most detected techniques across multiple index patterns
 */
export async function fetchTopTechniques(
  indices: string[],
  options: {
    dayRange?: number;
    limit?: number;
    tactic?: string;
  } = {}
): Promise<TopTechniquesResponse> {
  try {
    const validIndices = filterValidIndices(indices);
    
    if (validIndices.length === 0) {
      console.error('No valid indices provided for top techniques endpoint');
      return {
        techniques: [],
        total_detections: 0,
        time_range: { start: '', end: '' },
        limit: options.limit || 5,
        tactic_filter: options.tactic || 'all'
      };
    }

    const response = await fetch(`${BACKEND_API_URL}/api/unified/top-techniques`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        indices: validIndices,
        dayRange: options.dayRange || 7,
        limit: options.limit || 5,
        tactic: options.tactic || 'all',
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Backend API error for top techniques: ${response.status} - ${errorText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching top techniques:', error);
    return {
      techniques: [],
      total_detections: 0,
      time_range: { start: '', end: '' },
      limit: options.limit || 5,
      tactic_filter: options.tactic || 'all'
    };
  }
}

/**
 * Fetch complete MITRE ATT&CK kill chain coverage across multiple index patterns
 * Maps all detections to tactics with detailed technique-level information
 * 
 * @example
 * const killChain = await fetchKillChainCoverage(
 *   ['palo-xsiam-*', 'crowdstrike-*'],
 *   { dayRange: 7, search: null }
 * );
 */
export async function fetchKillChainCoverage(
  indices: string[],
  options: {
    dayRange?: number;
    search?: string | null;
  } = {}
): Promise<KillChainResponse> {
  try {
    const validIndices = filterValidIndices(indices);
    
    if (validIndices.length === 0) {
      console.error('No valid indices provided for kill chain endpoint');
      return {
        tactics: [],
        total_detections: 0,
        unique_techniques: 0,
        total_tactics: 0,
        time_range: { start: '', end: '' },
        indices_queried: []
      };
    }

    const response = await fetch(`${BACKEND_API_URL}/api/unified/kill-chain`, {
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
      throw new Error(`Backend API error for kill chain: ${response.status} - ${errorText}`);
    }

    const data: KillChainResponse = await response.json();
    return data;
  } catch (error) {
    console.error('Error fetching kill chain coverage:', error);
    return {
      tactics: [],
      total_detections: 0,
      unique_techniques: 0,
      total_tactics: 0,
      time_range: { start: '', end: '' },
      indices_queried: []
    };
  }
}

// ===========================
// Kill Chain Helper Functions
// ===========================

/**
 * Get kill chain coverage summary statistics
 */
export function getKillChainSummary(killChain: KillChainResponse): {
  activeTactics: number;
  totalTactics: number;
  averageCoverage: number;
  highestTactic: TacticCoverage | null;
  lowestCoverage: TacticCoverage | null;
  totalDetections: number;
  uniqueTechniques: number;
} {
  const activeTactics = killChain.tactics.filter(t => t.total_detections > 0);
  
  const averageCoverage = activeTactics.length > 0
    ? activeTactics.reduce((sum, t) => sum + t.coverage_percentage, 0) / activeTactics.length
    : 0;
  
  const highestTactic = activeTactics.length > 0
    ? activeTactics.reduce((max, t) => 
        t.total_detections > max.total_detections ? t : max
      )
    : null;
  
  const lowestCoverage = activeTactics.length > 0
    ? activeTactics.reduce((min, t) => 
        t.coverage_percentage < min.coverage_percentage ? t : min
      )
    : null;
  
  return {
    activeTactics: activeTactics.length,
    totalTactics: killChain.tactics.length,
    averageCoverage: Math.round(averageCoverage * 100) / 100,
    highestTactic,
    lowestCoverage,
    totalDetections: killChain.total_detections,
    uniqueTechniques: killChain.unique_techniques
  };
}

/**
 * Filter kill chain data by minimum detection threshold
 */
export function filterKillChainByThreshold(
  killChain: KillChainResponse,
  minDetections: number
): TacticCoverage[] {
  return killChain.tactics.filter(t => t.total_detections >= minDetections);
}

/**
 * Get tactics with zero coverage (no detections)
 */
export function getBlindSpots(killChain: KillChainResponse): TacticCoverage[] {
  return killChain.tactics.filter(t => t.total_detections === 0);
}

/**
 * Sort tactics by detection count (descending)
 */
export function sortTacticsByActivity(tactics: TacticCoverage[]): TacticCoverage[] {
  return [...tactics].sort((a, b) => b.total_detections - a.total_detections);
}

/**
 * Sort tactics by coverage percentage (descending)
 */
export function sortTacticsByCoverage(tactics: TacticCoverage[]): TacticCoverage[] {
  return [...tactics].sort((a, b) => b.coverage_percentage - a.coverage_percentage);
}

/**
 * Get color coding for coverage percentage
 */
export function getCoverageColor(coveragePercent: number): {
  color: string;
  label: string;
} {
  if (coveragePercent === 0) {
    return { color: '#94a3b8', label: 'No Coverage' };
  } else if (coveragePercent < 25) {
    return { color: '#ef4444', label: 'Low Coverage' };
  } else if (coveragePercent < 50) {
    return { color: '#f97316', label: 'Fair Coverage' };
  } else if (coveragePercent < 75) {
    return { color: '#eab308', label: 'Good Coverage' };
  } else {
    return { color: '#22c55e', label: 'Excellent Coverage' };
  }
}

/**
 * Format kill chain data for heatmap visualization
 */
export function formatForHeatmap(killChain: KillChainResponse): Array<{
  tactic: string;
  value: number;
  coverage: number;
  color: string;
}> {
  return killChain.tactics.map(tactic => {
    const { color } = getCoverageColor(tactic.coverage_percentage);
    return {
      tactic: tactic.tactic_name,
      value: tactic.total_detections,
      coverage: tactic.coverage_percentage,
      color
    };
  });
}

// ===========================
// Multi-Index API Functions (Single Index Pattern)
// ===========================

export const fetchMultiIndexTechniqueStats = async (
  techniques: MitreTechniqueFramework[],
  esIndex: string,
  dateRange: { start: string; end: string }
): Promise<Record<string, TechniqueStatsFramework>> => {
  try {
    const indexPattern = detectIndexPattern(esIndex);

    const techniquesPayload = techniques.map(tech => ({
      id: tech.id,
      eventIds: tech.eventIds || [],
    }));

    const startDate = new Date(dateRange.start);
    startDate.setHours(0, 0, 0, 0);
    
    const endDate = new Date(dateRange.end);
    endDate.setHours(23, 59, 59, 999);

    const response = await fetch(`${BACKEND_API_URL}/api/multi-index/technique-stats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        esIndex: esIndex,
        techniques: techniquesPayload,
        dateRange: {
          start: formatDateForES(startDate),
          end: formatDateForES(endDate),
        },
        indexPattern: indexPattern,
      }),
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error("Backend Error:", errorData);
      throw new Error(`Failed to fetch technique stats: ${response.status}`);
    }

    const allStats = await response.json();
    return allStats;
  } catch (error) {
    console.error('Error fetching multi-index technique stats:', error);
    return {};
  }
};

export async function fetchMultiIndexStats(
  esIndex: string,
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    dayRange?: number;
  }
): Promise<MultiIndexStats> {
  try {
    const indexPattern = detectIndexPattern(esIndex);

    const response = await fetch(`${BACKEND_API_URL}/api/multi-index/stats`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json' 
      },
      body: JSON.stringify({
        search: filters.search || null,
        tactic: filters.tactic || 'all',
        severity: filters.severity || 'all',
        dayRange: filters.dayRange || 7,
        indexPattern: indexPattern,
      }),
    });

    if (!response.ok) {
      throw new Error(`Backend API error for stats: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching multi-index stats:', error);
    return { 
      total: 0, 
      critical: 0, 
      high: 0, 
      medium: 0, 
      low: 0, 
      tactics: [],
      categories: []
    };
  }
}

export async function searchMultiIndex(
  esIndex: string,
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    size?: number;
    page?: number;
  }
): Promise<MultiIndexSearchResult> {
  try {
    const params = new URLSearchParams({
      index: esIndex,
    });

    if (filters.search) params.append('search', filters.search);
    if (filters.tactic && filters.tactic !== 'all') params.append('tactic', filters.tactic);
    if (filters.severity && filters.severity !== 'all') params.append('severity', filters.severity);
    if (filters.size) params.append('size', filters.size.toString());
    if (filters.page) params.append('page', filters.page.toString());

    const response = await fetch(
      `${BACKEND_API_URL}/api/multi-index/search?${params.toString()}`,
      {
        method: 'GET',
        headers: { 
          'Content-Type': 'application/json' 
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Backend API error for search: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error searching multi-index:', error);
    return {
      total: 0,
      page: 1,
      size: 10,
      results: []
    };
  }
}

// ===========================
// Legacy API Functions
// ===========================

export const fetchAllTechniqueStatsWithDateRange = async (
  techniques: MitreTechniqueFramework[],
  esIndex: string,
  dateRange: { start: string; end: string }
): Promise<Record<string, TechniqueStatsFramework>> => {
  try {
    const techniquesPayload = techniques.map(tech => ({
      id: tech.id,
      eventIds: tech.eventIds || [],
    }));

    const startDate = new Date(dateRange.start);
    startDate.setHours(0, 0, 0, 0);
    
    const endDate = new Date(dateRange.end);
    endDate.setHours(23, 59, 59, 999);

    const response = await fetch(`${BACKEND_API_URL}/api/technique-stats-date`, {
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

    const allStats = await response.json();
    return allStats;
  } catch (error) {
    console.error('Error fetching all technique stats:', error);
    return {};
  }
};

export async function fetchStats(
  esIndex: string,
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    dayRange?: number;
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
        dayRange: filters.dayRange || 7,
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

// ===========================
// Smart API Functions
// ===========================

export const fetchTechniqueStats = async (
  techniques: MitreTechniqueFramework[],
  esIndex: string,
  dateRange: { start: string; end: string },
  useMultiIndex: boolean = true
): Promise<Record<string, TechniqueStatsFramework>> => {
  if (useMultiIndex) {
    try {
      detectIndexPattern(esIndex);
      return await fetchMultiIndexTechniqueStats(techniques, esIndex, dateRange);
    } catch (error) {
      console.warn('Multi-index not supported, falling back to legacy endpoint');
      return await fetchAllTechniqueStatsWithDateRange(techniques, esIndex, dateRange);
    }
  }
  return await fetchAllTechniqueStatsWithDateRange(techniques, esIndex, dateRange);
};

export const fetchStatsUnified = async (
  esIndex: string,
  filters: {
    search?: string;
    tactic?: string;
    severity?: string;
    dayRange?: number;
  },
  useMultiIndex: boolean = true
): Promise<MultiIndexStats> => {
  if (useMultiIndex) {
    try {
      detectIndexPattern(esIndex);
      return await fetchMultiIndexStats(esIndex, filters);
    } catch (error) {
      console.warn('Multi-index not supported, falling back to legacy endpoint');
      const legacyStats = await fetchStats(esIndex, filters);
      return convertToMultiIndexStats(legacyStats);
    }
  }
  const legacyStats = await fetchStats(esIndex, filters);
  return convertToMultiIndexStats(legacyStats);
};

// ===========================
// Export
// ===========================

export default {
  // Unified (Recommended)
  fetchUnifiedTechniqueStats,
  fetchUnifiedStats,
  searchUnified,
  fetchTopTechniques,
  fetchKillChainCoverage,
  
  // Multi-Index
  fetchMultiIndexTechniqueStats,
  fetchMultiIndexStats,
  searchMultiIndex,
  
  // Legacy
  fetchAllTechniqueStatsWithDateRange,
  fetchStats,
  
  // Smart
  fetchTechniqueStats,
  fetchStatsUnified,
  
  // Helpers
  detectIndexPattern,
  filterValidIndices,
  convertToLegacyStats,
  convertToMultiIndexStats,
  convertUnifiedToMultiIndexStats,
  
  // Kill Chain Helpers
  getKillChainSummary,
  filterKillChainByThreshold,
  getBlindSpots,
  sortTacticsByActivity,
  sortTacticsByCoverage,
  getCoverageColor,
  formatForHeatmap,
};