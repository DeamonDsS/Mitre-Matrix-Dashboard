// services/categoryService.ts
// Add this to your React services folder

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// ===================================
// Type Definitions
// ===================================

export interface CategoryStats {
  name: string;
  count: number;
  sources: Record<string, number>;
  percentage: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  field_types: string[];
}

export interface CategoryStatsResponse {
  categories: CategoryStats[];
  total_events: number;
  breakdown_by_source: Record<string, number>;
  time_range: {
    start: string;
    end: string;
  };
  indices_queried: string[];
}

export interface TechniqueBreakdown {
  technique_id: string;
  technique_name: string;
  count: number;
  tactics: string[];
  sources: Record<string, number>;
}

export interface TacticBreakdown {
  tactic_id: string;
  tactic_name: string;
  count: number;
}

export interface CategoryBreakdownResponse {
  category: string;
  total_count: number;
  techniques: TechniqueBreakdown[];
  tactics: TacticBreakdown[];
  top_hosts: Array<{ host: string; count: number }>;
  timeline: Array<{ date: string; count: number }>;
  sources: Record<string, number>;
  indices_queried: string[];
}

export interface CategoryComparison {
  category: string;
  total: number;
  by_index: Record<string, number>;
}

export interface CoverageAnalysis {
  total_categories: number;
  by_index: Record<string, {
    detected_categories: number;
    coverage_percentage: number;
    total_events: number;
  }>;
}

export interface CategoryComparisonResponse {
  comparison: CategoryComparison[];
  coverage_analysis: CoverageAnalysis;
  time_range: {
    start: string;
    end: string;
  };
  indices_queried: string[];
  categories_analyzed: number;
}

// ===================================
// API Functions
// ===================================

/**
 * Fetch unified category statistics across multiple indices
 */
export async function fetchCategoryStats(
  indices: string[],
  options: {
    dayRange?: number;
    search?: string;
    tactic?: string;
    limit?: number;
  } = {}
): Promise<CategoryStatsResponse> {
  const {
    dayRange = 7,
    search,
    tactic = 'all',
    limit = 10
  } = options;

  try {
    console.log('📊 Fetching category stats from:', indices);

    const response = await fetch(`${API_URL}/api/unified/category-stats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        indices,
        dayRange,
        search,
        tactic,
        limit
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(
        errorData?.detail || `HTTP error! status: ${response.status}`
      );
    }

    const data = await response.json();
    console.log('✅ Category stats loaded:', data);
    return data;
  } catch (error) {
    console.error('❌ Error fetching category stats:', error);
    throw error;
  }
}

/**
 * Fetch detailed breakdown for a specific category
 */
export async function fetchCategoryBreakdown(
  indices: string[],
  category: string,
  options: {
    dayRange?: number;
    groupBy?: 'technique' | 'tactic' | 'host';
  } = {}
): Promise<CategoryBreakdownResponse> {
  const {
    dayRange = 7,
    groupBy = 'technique'
  } = options;

  try {
    console.log(`🔍 Fetching breakdown for category: ${category}`);

    const response = await fetch(`${API_URL}/api/unified/category-breakdown`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        indices,
        category,
        dayRange,
        groupBy
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(
        errorData?.detail || `HTTP error! status: ${response.status}`
      );
    }

    const data = await response.json();
    console.log('✅ Category breakdown loaded:', data);
    return data;
  } catch (error) {
    console.error('❌ Error fetching category breakdown:', error);
    throw error;
  }
}

/**
 * Fetch cross-index category comparison
 */
export async function fetchCategoryComparison(
  indices: string[],
  options: {
    dayRange?: number;
    categories?: string[];
  } = {}
): Promise<CategoryComparisonResponse> {
  const {
    dayRange = 7,
    categories
  } = options;

  try {
    console.log('🔄 Fetching category comparison across indices');

    const response = await fetch(`${API_URL}/api/unified/category-comparison`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        indices,
        dayRange,
        categories
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => null);
      throw new Error(
        errorData?.detail || `HTTP error! status: ${response.status}`
      );
    }

    const data = await response.json();
    console.log('✅ Category comparison loaded:', data);
    return data;
  } catch (error) {
    console.error('❌ Error fetching category comparison:', error);
    throw error;
  }
}

// ===================================
// Helper Functions
// ===================================

/**
 * Get severity color class for categories
 */
export function getCategorySeverityColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'bg-purple-600';
    case 'high':
      return 'bg-red-600';
    case 'medium':
      return 'bg-orange-500';
    case 'low':
      return 'bg-yellow-500';
    default:
      return 'bg-gray-600';
  }
}

/**
 * Get field type label
 */
export function getFieldTypeLabel(fieldType: string): string {
  const labels: Record<string, string> = {
    'alert_category': 'Alert Category',
    'objective': 'Objective',
    'event_name': 'Event Name',
    'classification': 'Classification',
    'category': 'Category'
  };
  return labels[fieldType] || fieldType;
}

/**
 * Format percentage with color coding
 */
export function formatPercentage(percentage: number): {
  value: string;
  colorClass: string;
} {
  const formatted = percentage.toFixed(2);
  let colorClass = 'text-gray-400';
  
  if (percentage >= 20) {
    colorClass = 'text-red-500';
  } else if (percentage >= 10) {
    colorClass = 'text-orange-500';
  } else if (percentage >= 5) {
    colorClass = 'text-yellow-500';
  } else if (percentage > 0) {
    colorClass = 'text-blue-500';
  }
  
  return {
    value: `${formatted}%`,
    colorClass
  };
}

/**
 * Get source label from index pattern
 */
export function getSourceLabel(indexPattern: string): string {
  const labels: Record<string, string> = {
    'palo-xsiam-*': 'Palo Alto XSIAM',
    'crowdstrike-*': 'CrowdStrike',
    'suricata-*': 'Suricata',
    'winlogbeat-*': 'Windows Events'
  };
  return labels[indexPattern] || indexPattern;
}

/**
 * Calculate total events across sources
 */
export function calculateTotalEvents(sources: Record<string, number>): number {
  return Object.values(sources).reduce((sum, count) => sum + count, 0);
}

/**
 * Get top N categories by count
 */
export function getTopCategories(
  categories: CategoryStats[],
  limit: number = 5
): CategoryStats[] {
  return [...categories]
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

/**
 * Filter categories by severity
 */
export function filterBySeverity(
  categories: CategoryStats[],
  severity: string
): CategoryStats[] {
  if (severity === 'all') return categories;
  return categories.filter(cat => cat.severity === severity);
}

/**
 * Search categories by name
 */
export function searchCategories(
  categories: CategoryStats[],
  searchTerm: string
): CategoryStats[] {
  if (!searchTerm) return categories;
  
  const term = searchTerm.toLowerCase();
  return categories.filter(cat => 
    cat.name.toLowerCase().includes(term)
  );
}

/**
 * Group categories by field type
 */
export function groupByFieldType(
  categories: CategoryStats[]
): Record<string, CategoryStats[]> {
  const grouped: Record<string, CategoryStats[]> = {};
  
  categories.forEach(cat => {
    cat.field_types.forEach(fieldType => {
      if (!grouped[fieldType]) {
        grouped[fieldType] = [];
      }
      grouped[fieldType].push(cat);
    });
  });
  
  return grouped;
}

/**
 * Calculate coverage metrics
 */
export function calculateCoverageMetrics(comparison: CategoryComparisonResponse) {
  const totalCategories = comparison.categories_analyzed;
  const metrics = {
    overall: {
      total_events: 0,
      categories_detected: 0
    },
    by_source: {} as Record<string, {
      events: number;
      categories: number;
      coverage: number;
    }>
  };
  
  // Calculate overall metrics
  comparison.comparison.forEach(cat => {
    if (cat.total > 0) {
      metrics.overall.categories_detected++;
      metrics.overall.total_events += cat.total;
    }
  });
  
  // Calculate per-source metrics
  Object.entries(comparison.coverage_analysis.by_index).forEach(([index, data]) => {
    metrics.by_source[index] = {
      events: data.total_events,
      categories: data.detected_categories,
      coverage: data.coverage_percentage
    };
  });
  
  return metrics;
}

/**
 * Export data to CSV format
 */
export function exportCategoriesToCSV(categories: CategoryStats[]): string {
  const headers = ['Category', 'Count', 'Percentage', 'Severity', 'Field Types', 'Sources'];
  const rows = categories.map(cat => [
    cat.name,
    cat.count.toString(),
    cat.percentage.toFixed(2),
    cat.severity,
    cat.field_types.join('; '),
    Object.entries(cat.sources)
      .map(([src, count]) => `${getSourceLabel(src)}: ${count}`)
      .join('; ')
  ]);
  
  return [headers, ...rows]
    .map(row => row.map(cell => `"${cell}"`).join(','))
    .join('\n');
}

/**
 * Download CSV file
 */
export function downloadCSV(content: string, filename: string = 'categories.csv') {
  const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  const url = URL.createObjectURL(blob);
  
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  link.style.visibility = 'hidden';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}