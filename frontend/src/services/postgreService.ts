// services/postgresService.ts
// Service for fetching MITRE ATT&CK data from PostgreSQL backend
import type { SummaryStats } from "../components/mitreCard/SummaryView";
import type { MitreStats, TechniqueStatsFramework } from "../types/mitre";
import axios from "axios";

const POSTGRES_API_URL = import.meta.env.VITE_POSTGRES_API_URL || 'http://localhost:8001';

export interface Technique {
  id: string;
  eventIds: number[];
}

export interface DateRange {
  start: string;
  end: string;
}

export interface TechniqueStatsRequest {
  techniques: Technique[];
  dateRange?: DateRange;
}

export interface StatsRequest {
  search?: string;
  tactic?: string;
  severity?: string;
  dayRange?: number;
}

export interface SearchRequest {
  search?: string;
  tactic?: string;
  severity?: string;
  size?: number;
  page?: number;
}

export interface TopTechniquesRequest {
  dayRange?: number;
  limit?: number;
  tactic?: string;
}

export interface SearchResult {
  id: string;
  timestamp: string | null;
  description: string;
  severity: string;
  crowdstrike_severity?: string;
  tactics: string[];
  techniques: string[];
  categories: string[];
  source: string;
}

export interface SearchResponse {
  total: number;
  page: number;
  size: number;
  results: SearchResult[];
}

export interface TopTechniqueResult {
  technique_id: string;
  count: number;
  percentage: number;
}

export interface TopTechniquesResponse {
  techniques: TopTechniqueResult[];
  total_events: number;
  time_range: {
    start: string;
    end: string;
  };
}

/**
 * Fetch technique statistics from PostgreSQL
 * @param techniques - Array of techniques with IDs and event IDs
 * @param dateRange - Optional date range filter
 * @returns Object mapping technique IDs to their statistics
 */
export async function fetchPostgresTechniqueStats(
  techniques: Technique[],
  dateRange?: DateRange
): Promise<Record<string, TechniqueStatsFramework>> {
  try {
    const response = await axios.post(
      `${POSTGRES_API_URL}/api/postgres/technique-stats`,
      {
        techniques,
        dateRange,
      }
    );

    // Ensure severity values match the expected type
    const result: Record<string, TechniqueStatsFramework> = {};
    Object.entries(response.data).forEach(([techId, stat]: [string, any]) => {
      result[techId] = {
        count: stat.count,
        severity: stat.severity as "critical" | "high" | "medium" | "low" | "none",
        lastSeen: stat.lastSeen,
      };
    });

    return result;
  } catch (error) {
    console.error('Error fetching technique stats from PostgreSQL:', error);
    return {};
  }
}

export async function fetchPostgresAggregateTechniqueStats(
  techniques: Technique[],
  dateRange?: DateRange
): Promise<Record<string, TechniqueStatsFramework>> {
  try {
    const response = await axios.post(
      `${POSTGRES_API_URL}/api/postgres/technique-aggregate-stats`,
      {
        techniques,
        dateRange,
      }
    );

    // Ensure severity values match the expected type
    const result: Record<string, TechniqueStatsFramework> = {};
    Object.entries(response.data).forEach(([techId, stat]: [string, any]) => {
      result[techId] = {
        count: stat.count,
        severity: stat.severity as "critical" | "high" | "medium" | "low" | "none",
        lastSeen: stat.lastSeen,
      };
    });

    return result;
  } catch (error) {
    console.error('Error fetching technique stats from PostgreSQL:', error);
    return {};
  }
}

// New Technique card service

export interface AggregateStatsRequest {
  search?: string;
  tactic?: string;
  severity?: string;
  dayRange?: number;
  includeSubTechniques?: boolean;
  includeCrowdStrikeSpecific?: boolean;
}

export interface SubTechniqueStats {
  count: number;
  severity: "critical" | "high" | "medium" | "low" | "none";
  lastSeen: string | null;
  sources: string[];
}

export interface TechniqueAggregateStats {
  count: number;
  severity: "critical" | "high" | "medium" | "low" | "none";
  lastSeen: string | null;
  sources: string[];
  subTechniques: Record<string, SubTechniqueStats>;
}

export interface AggregateStatsResponse {
  total: number;
  techniques: Record<string, TechniqueAggregateStats>;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    none: number;
  };
  crowdStrikeSpecific: Record<string, any> | null;
  dateRange: {
    start: string;
    end: string;
  };
}

// Flattened format for TechniqueCard compatibility
export interface FlattenedTechniqueStats {
  [techniqueId: string]: {
    count: number;
    severity: "critical" | "high" | "medium" | "low" | "none";
    lastSeen: string | null;
    sources: string[];
    subTechniques?: Array<{
      id: string;
      count: number;
      severity: "critical" | "high" | "medium" | "low" | "none";
      lastSeen: string | null;
      sources: string[];
    }>;
  };
}

export async function fetchPostgresAggregateStats(
  request: AggregateStatsRequest = {}
): Promise<AggregateStatsResponse> {
  try {
    const response = await axios.post<AggregateStatsResponse>(
      `${POSTGRES_API_URL}/api/postgres/technique-aggregate-stats-sum`,
      {
        dayRange: request.dayRange || 7,
        search: request.search || null,
        tactic: request.tactic || "all",
        severity: request.severity || "all",
        includeSubTechniques: request.includeSubTechniques ?? true,
        includeCrowdStrikeSpecific: request.includeCrowdStrikeSpecific ?? false,
      }
    );

    return response.data;
  } catch (error) {
    console.error('Error fetching aggregate technique stats from PostgreSQL:', error);
    // Return default empty stats on error
    return {
      total: 0,
      techniques: {},
      severityCounts: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        none: 0,
      },
      crowdStrikeSpecific: null,
      dateRange: {
        start: new Date().toISOString(),
        end: new Date().toISOString(),
      },
    };
  }
}

// Transform API response to flattened format for TechniqueCard
export function flattenTechniqueStats(
  apiResponse: AggregateStatsResponse
): FlattenedTechniqueStats {
  const flattened: FlattenedTechniqueStats = {};

  Object.entries(apiResponse.techniques).forEach(([techId, techData]) => {
    // Add parent technique
    flattened[techId] = {
      count: techData.count,
      severity: techData.severity,
      lastSeen: techData.lastSeen,
      sources: techData.sources,
      subTechniques: Object.entries(techData.subTechniques || {}).map(([subId, subData]) => ({
        id: subId,
        count: subData.count,
        severity: subData.severity,
        lastSeen: subData.lastSeen,
        sources: subData.sources,
      })),
    };

    // Also add sub-techniques as individual entries for direct access
    Object.entries(techData.subTechniques || {}).forEach(([subId, subData]) => {
      flattened[subId] = {
        count: subData.count,
        severity: subData.severity,
        lastSeen: subData.lastSeen,
        sources: subData.sources,
      };
    });
  });

  return flattened;
}

// Convenience function with common filters (similar to existing stats service)
export async function fetchPostgresAggregateStatsByFilter(
  search?: string,
  tactic?: string,
  severity?: string,
  dayRange: number = 7
): Promise<AggregateStatsResponse> {
  return fetchPostgresAggregateStats({
    search,
    tactic,
    severity,
    dayRange,
  });
}

// Function to get stats for specific time range
export async function fetchPostgresAggregateStatsByTimeRange(
  dayRange: number,
  includeSubTechniques: boolean = true
): Promise<AggregateStatsResponse> {
  return fetchPostgresAggregateStats({
    dayRange,
    includeSubTechniques,
  });
}

// Function to compare stats between different filters
export async function compareAggregateStats(
  filters: AggregateStatsRequest[]
): Promise<AggregateStatsResponse[]> {
  try {
    const results = await Promise.all(
      filters.map(filter => fetchPostgresAggregateStats(filter))
    );
    return results;
  } catch (error) {
    console.error('Error comparing aggregate stats:', error);
    return [];
  }
}

// Get technique stats in format compatible with existing TechniqueCard
export async function fetchTechniqueStatsForCard(
  request: AggregateStatsRequest = {}
): Promise<FlattenedTechniqueStats> {
  const response = await fetchPostgresAggregateStats(request);
  return flattenTechniqueStats(response);
}


/**
 * Fetch overall statistics from PostgreSQL
 * @param request - Statistics request with filters
 * @returns Overall statistics including total, severity counts, and tactics
 */
export async function fetchPostgresStats(
  request: StatsRequest
): Promise<MitreStats> {
  try {
    const response = await axios.post(
      `${POSTGRES_API_URL}/api/postgres/stats`,
      {
        search: request.search || null,
        tactic: request.tactic || 'all',
        severity: request.severity || 'all',
        dayRange: request.dayRange || 7,
      }
    );

    return response.data;
  } catch (error) {
    console.error('Error fetching stats from PostgreSQL:', error);
    return { total: 0, critical: 0, high: 0, medium: 0, low: 0, tactics: 0 };
  }
}

/**
 * Fetch detailed summary statistics from PostgreSQL
 * @param request - Statistics request with filters
 * @returns Summary statistics including total, severity counts, tactics array, and sources
 */
export async function fetchPostgresSummaryStats(
  request: StatsRequest
): Promise<SummaryStats> {
  try {
    const response = await axios.post(`${POSTGRES_API_URL}/api/postgres/summary_stats`, {
      search: request.search || null,
      tactic: request.tactic || "all",
      severity: request.severity || "all",
      dayRange: request.dayRange || 7,
    });

    return response.data as SummaryStats;
  } catch (error) {
    console.error("Error fetching summary stats from PostgreSQL:", error);
    // return empty/default structure matching SummaryStats
    return {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      tactics: [],
      sources: {},
    };
  }
}

/**
 * Search and paginate through detection events
 * @param request - Search request with filters and pagination
 * @returns Paginated search results
 */
export async function searchPostgresEvents(
  request: SearchRequest
): Promise<SearchResponse> {
  try {
    const response = await axios.post(
      `${POSTGRES_API_URL}/api/postgres/search`,
      {
        search: request.search || null,
        tactic: request.tactic || 'all',
        severity: request.severity || 'all',
        size: request.size || 10,
        page: request.page || 1,
      }
    );

    return response.data;
  } catch (error) {
    console.error('Error searching events in PostgreSQL:', error);
    return {
      total: 0,
      page: request.page || 1,
      size: request.size || 10,
      results: [],
    };
  }
}

/**
 * Get top N most detected MITRE techniques
 * @param request - Top techniques request with filters
 * @returns Top techniques with counts and percentages
 */
export async function fetchPostgresTopTechniques(
  request: TopTechniquesRequest
): Promise<TopTechniquesResponse> {
  try {
    const response = await axios.post(
      `${POSTGRES_API_URL}/api/postgres/top-techniques`,
      {
        dayRange: request.dayRange || 7,
        limit: request.limit || 5,
        tactic: request.tactic || 'all',
      }
    );

    return response.data;
  } catch (error) {
    console.error('Error fetching top techniques from PostgreSQL:', error);
    return {
      techniques: [],
      total_events: 0,
      time_range: {
        start: new Date().toISOString(),
        end: new Date().toISOString(),
      },
    };
  }
}

/**
 * Check PostgreSQL database health
 * @returns Health check status with database info
 */
export async function checkPostgresHealth(): Promise<{
  status: string;
  database: string;
  total_records: number;
  latest_record: string | null;
}> {
  try {
    const response = await axios.get(`${POSTGRES_API_URL}/api/postgres/health`);
    return response.data;
  } catch (error) {
    console.error('Error checking PostgreSQL health:', error);
    return {
      status: 'error',
      database: 'disconnected',
      total_records: 0,
      latest_record: null,
    };
  }
}

/**
 * Helper function to format date range for API calls
 * @param dayRange - Number of days to look back
 * @returns DateRange object with start and end dates
 */
export function createDateRangeFromDays(dayRange: number): DateRange {
  const endDate = new Date();
  endDate.setHours(23, 59, 59, 999);
  
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - dayRange);
  startDate.setHours(0, 0, 0, 0);
  
  return {
    start: startDate.toISOString(),
    end: endDate.toISOString(),
  };
}

/**
 * Helper function to parse technique ID from combined format
 * @param value - Technique value (e.g., "T1059 - Command and Scripting")
 * @returns Extracted technique ID (e.g., "T1059")
 */
export function extractTechniqueId(value: string): string {
  if (!value) return '';
  if (value.includes(' - ')) {
    return value.split(' - ')[0].trim();
  }
  return value.trim();
}

/**
 * Helper function to parse tactic ID from combined format
 * @param value - Tactic value (e.g., "TA0002 - Execution")
 * @returns Extracted tactic ID (e.g., "TA0002")
 */
export function extractTacticId(value: string): string {
  if (!value) return '';
  if (value.includes(' - ')) {
    return value.split(' - ')[0].trim();
  }
  return value.trim();
}

/**
 * Map severity string to numeric value for comparisons
 * @param severity - Severity string (critical, high, medium, low, none)
 * @returns Numeric severity value
 */
export function severityToNumber(severity: string): number {
  const map: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    none: 1,
  };
  return map[severity.toLowerCase()] || 0;
}

/**
 * Get severity color class for UI rendering
 * @param severity - Severity string
 * @returns Tailwind color class
 */
export function getSeverityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: 'text-red-600 bg-red-100',
    high: 'text-orange-600 bg-orange-100',
    medium: 'text-yellow-600 bg-yellow-100',
    low: 'text-blue-600 bg-blue-100',
    none: 'text-gray-600 bg-gray-100',
  };
  return map[severity.toLowerCase()] || 'text-gray-600 bg-gray-100';
}