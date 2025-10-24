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
  indexPattern: string; // "palo-xsiam-*" or "crowdstrike-*"
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

// MultiIndexStats uses array for tactics instead of number
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
// Helper Functions
// ===========================

/**
 * Detect index pattern type from index name
 */
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
    // Windows event logs - use legacy endpoint
    return 'windows';
  }
  
  // Default to windows for unknown patterns (backward compatible)
  console.warn(`Unknown index pattern: ${esIndex}, defaulting to legacy Windows endpoint`);
  return 'windows';
}

/**
 * Format date for Elasticsearch query
 */
function formatDateForES(date: Date): string {
  return date.toISOString();
}

/**
 * Convert MultiIndexStats to legacy MitreStats format
 * Useful for components expecting the old format
 */
export function convertToLegacyStats(stats: MultiIndexStats): MitreStats {
  return {
    total: stats.total,
    critical: stats.critical,
    high: stats.high,
    medium: stats.medium,
    low: stats.low,
    tactics: stats.tactics.length, // Convert array to count
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

// ===========================
// Multi-Index API Functions
// ===========================

/**
 * Fetch technique statistics for multiple techniques across different index patterns
 * Works with both Palo Alto XSIAM and CrowdStrike indices
 */
export const fetchMultiIndexTechniqueStats = async (
  techniques: MitreTechniqueFramework[],
  esIndex: string,
  dateRange: { start: string; end: string }
): Promise<Record<string, TechniqueStatsFramework>> => {
  try {
    // Detect index pattern automatically
    const indexPattern = detectIndexPattern(esIndex);

    // Prepare payload
    const techniquesPayload = techniques.map(tech => ({
      id: tech.id,
      eventIds: tech.eventIds || [],
    }));

    // Format date range
    const startDate = new Date(dateRange.start);
    startDate.setHours(0, 0, 0, 0);
    
    const endDate = new Date(dateRange.end);
    endDate.setHours(23, 59, 59, 999);

    // Call multi-index endpoint
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

/**
 * Fetch overall statistics across different index patterns
 * Returns aggregated counts by tactic, severity, and categories
 */
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
    // Detect index pattern
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
      tactics: [], // Return empty array instead of 0
      categories: []
    };
  }
}

/**
 * Search MITRE detections across different index patterns
 * Supports pagination and filtering
 */
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
// Legacy API Functions (for backward compatibility)
// ===========================

/**
 * Legacy function - uses original endpoint
 * Use fetchMultiIndexTechniqueStats for multi-index support
 */
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

/**
 * Legacy function - uses original endpoint
 * Use fetchMultiIndexStats for multi-index support
 */
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
// Unified API Functions (Recommended)
// ===========================

/**
 * Universal technique stats fetcher
 * Automatically chooses the right endpoint based on index pattern
 */
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

/**
 * Universal stats fetcher
 * Automatically chooses the right endpoint based on index pattern
 * Returns MultiIndexStats (with tactics array) by default
 */
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
      // Convert legacy format to multi-index format
      return convertToMultiIndexStats(legacyStats);
    }
  }
  const legacyStats = await fetchStats(esIndex, filters);
  return convertToMultiIndexStats(legacyStats);
};

// ===========================
// Export all functions
// ===========================

export default {
  // Multi-Index (New)
  fetchMultiIndexTechniqueStats,
  fetchMultiIndexStats,
  searchMultiIndex,
  
  // Legacy (Backward Compatible)
  fetchAllTechniqueStatsWithDateRange,
  fetchStats,
  
  // Unified (Recommended)
  fetchTechniqueStats,
  fetchStatsUnified,
  
  // Helpers
  detectIndexPattern,
  convertToLegacyStats,
  convertToMultiIndexStats,
};