// components/CategoryDashboard.tsx
// Example component to use with your existing MITRE Navigator

import React, { useState, useEffect } from 'react';
import { 
  BarChart3, 
  TrendingUp, 
  Search, 
  Download,
  Layers,
  PieChart,
  Activity
} from 'lucide-react';
import {
  fetchCategoryStats,
  fetchCategoryBreakdown,
  fetchCategoryComparison,
  getCategorySeverityColor,
  getFieldTypeLabel,
  formatPercentage,
  getSourceLabel,
  exportCategoriesToCSV,
  downloadCSV,
  type CategoryStats,
  type CategoryBreakdownResponse,
  type CategoryComparisonResponse
} from '../../services/categoryService';


interface CategoryDashboardProps {
  selectedIndices: string[];
  dayRange: number;
}

type ViewMode = 'overview' | 'breakdown' | 'comparison';

const CategoryDashboard: React.FC<CategoryDashboardProps> = ({
  selectedIndices,
  dayRange
}) => {
  const [viewMode, setViewMode] = useState<ViewMode>('overview');
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  
  // Overview data
  const [categoryStats, setCategoryStats] = useState<CategoryStats[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [sourceBreakdown, setSourceBreakdown] = useState<Record<string, number>>({});
  
  // Breakdown data
  const [breakdownData, setBreakdownData] = useState<CategoryBreakdownResponse | null>(null);
  
  // Comparison data
  const [comparisonData, setComparisonData] = useState<CategoryComparisonResponse | null>(null);

  useEffect(() => {
    loadOverviewData();
  }, [selectedIndices, dayRange]);

  useEffect(() => {
    if (selectedCategory && viewMode === 'breakdown') {
      loadBreakdownData(selectedCategory);
    }
  }, [selectedCategory, selectedIndices, dayRange]);

  useEffect(() => {
    if (viewMode === 'comparison') {
      loadComparisonData();
    }
  }, [viewMode, selectedIndices, dayRange]);

  const loadOverviewData = async () => {
    setLoading(true);
    try {
      const data = await fetchCategoryStats(selectedIndices, {
        dayRange,
        limit: 20
      });
      
      setCategoryStats(data.categories);
      setTotalEvents(data.total_events);
      setSourceBreakdown(data.breakdown_by_source);
    } catch (error) {
      console.error('Error loading category stats:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadBreakdownData = async (category: string) => {
    setLoading(true);
    try {
      const data = await fetchCategoryBreakdown(selectedIndices, category, {
        dayRange,
        groupBy: 'technique'
      });
      
      setBreakdownData(data);
    } catch (error) {
      console.error('Error loading category breakdown:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadComparisonData = async () => {
    setLoading(true);
    try {
      const data = await fetchCategoryComparison(selectedIndices, {
        dayRange,
        categories: categoryStats.slice(0, 10).map(c => c.name) // Top 10
      });
      
      setComparisonData(data);
    } catch (error) {
      console.error('Error loading comparison data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCategoryClick = (category: string) => {
    setSelectedCategory(category);
    setViewMode('breakdown');
  };

  const handleExportCSV = () => {
    const csv = exportCategoriesToCSV(categoryStats);
    downloadCSV(csv, `categories_${new Date().toISOString().split('T')[0]}.csv`);
  };

  const filteredCategories = categoryStats.filter(cat =>
    cat.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading && !categoryStats.length) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto mb-3"></div>
          <p className="text-white">Loading categories...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <PieChart className="w-6 h-6" />
            Category Analytics
          </h2>
          <p className="text-gray-400 text-sm mt-1">
            Analysis across {selectedIndices.length} data sources
          </p>
        </div>
        
        <div className="flex gap-2">
          <button
            onClick={handleExportCSV}
            className="px-3 py-2 bg-gray-700 text-white rounded hover:bg-gray-600 transition-colors flex items-center gap-2 text-sm"
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>
      </div>

      {/* View Mode Tabs */}
      <div className="flex gap-2 border-b border-gray-700">
        <button
          onClick={() => setViewMode('overview')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${
            viewMode === 'overview'
              ? 'text-white border-b-2 border-red-500'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <BarChart3 className="w-4 h-4" />
          Overview
        </button>
        
        <button
          onClick={() => setViewMode('breakdown')}
          disabled={!selectedCategory}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${
            viewMode === 'breakdown'
              ? 'text-white border-b-2 border-red-500'
              : 'text-gray-400 hover:text-white'
          } disabled:opacity-50 disabled:cursor-not-allowed`}
        >
          <Activity className="w-4 h-4" />
          Breakdown {selectedCategory && `(${selectedCategory})`}
        </button>
        
        <button
          onClick={() => setViewMode('comparison')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors ${
            viewMode === 'comparison'
              ? 'text-white border-b-2 border-red-500'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <TrendingUp className="w-4 h-4" />
          Comparison
        </button>
      </div>

      {/* Overview View */}
      {viewMode === 'overview' && (
        <div className="space-y-4">
          {/* Summary Cards */}
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Total Events</div>
              <div className="text-3xl font-bold text-white">
                {totalEvents.toLocaleString()}
              </div>
            </div>
            
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Categories Detected</div>
              <div className="text-3xl font-bold text-white">
                {categoryStats.length}
              </div>
            </div>
            
            <div className="bg-gray-900 rounded-lg p-4">
              <div className="text-gray-400 text-sm mb-1">Active Sources</div>
              <div className="text-3xl font-bold text-white">
                {selectedIndices.length}
              </div>
            </div>
          </div>

          {/* Search Bar */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search categories..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-gray-900 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-500"
            />
          </div>

          {/* Categories List */}
          <div className="space-y-2">
            {filteredCategories.map((category, index) => {
              const percentage = formatPercentage(category.percentage);
              
              return (
                <div
                  key={`${category.name}-${index}`}
                  onClick={() => handleCategoryClick(category.name)}
                  className="bg-gray-900 rounded-lg p-4 hover:bg-gray-800 transition-colors cursor-pointer"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <div className={`w-3 h-3 rounded ${getCategorySeverityColor(category.severity)}`}></div>
                        <h3 className="text-white font-medium">{category.name}</h3>
                        <span className={`text-sm ${percentage.colorClass}`}>
                          {percentage.value}
                        </span>
                      </div>
                      
                      <div className="flex items-center gap-4 text-sm text-gray-400">
                        <span>Events: {category.count.toLocaleString()}</span>
                        <span className="capitalize">Severity: {category.severity}</span>
                        <span>
                          Types: {category.field_types.map(getFieldTypeLabel).join(', ')}
                        </span>
                      </div>
                      
                      {/* Source Breakdown */}
                      <div className="mt-2 flex gap-2">
                        {Object.entries(category.sources).map(([source, count]) => (
                          <div
                            key={source}
                            className="bg-gray-800 rounded px-2 py-1 text-xs"
                          >
                            <span className="text-gray-400">{getSourceLabel(source)}: </span>
                            <span className="text-white font-medium">{count.toLocaleString()}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    {/* Progress Bar */}
                    <div className="w-32 ml-4">
                      <div className="bg-gray-700 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${getCategorySeverityColor(category.severity)}`}
                          style={{ width: `${Math.min(category.percentage, 100)}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Breakdown View */}
      {viewMode === 'breakdown' && breakdownData && (
        <div className="space-y-4">
          <button
            onClick={() => setViewMode('overview')}
            className="text-gray-400 hover:text-white text-sm flex items-center gap-1"
          >
            ← Back to Overview
          </button>
          
          <div className="bg-gray-900 rounded-lg p-4">
            <h3 className="text-xl font-bold text-white mb-4">
              {breakdownData.category}
            </h3>
            
            <div className="grid grid-cols-4 gap-4 mb-6">
              <div>
                <div className="text-gray-400 text-sm mb-1">Total Events</div>
                <div className="text-2xl font-bold text-white">
                  {breakdownData.total_count.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="text-gray-400 text-sm mb-1">Techniques</div>
                <div className="text-2xl font-bold text-white">
                  {breakdownData.techniques.length}
                </div>
              </div>
              <div>
                <div className="text-gray-400 text-sm mb-1">Tactics</div>
                <div className="text-2xl font-bold text-white">
                  {breakdownData.tactics.length}
                </div>
              </div>
              <div>
                <div className="text-gray-400 text-sm mb-1">Affected Hosts</div>
                <div className="text-2xl font-bold text-white">
                  {breakdownData.top_hosts.length}
                </div>
              </div>
            </div>
          </div>

          {/* Top Techniques */}
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="text-white font-bold mb-3">Top Techniques</h4>
            <div className="space-y-2">
              {breakdownData.techniques.slice(0, 10).map(tech => (
                <div key={tech.technique_id} className="flex items-center justify-between p-2 bg-gray-800 rounded">
                  <div className="flex-1">
                    <div className="text-white font-medium">
                      {tech.technique_id} - {tech.technique_name}
                    </div>
                    <div className="text-xs text-gray-400">
                      Tactics: {tech.tactics.join(', ')}
                    </div>
                  </div>
                  <div className="text-red-400 font-bold">
                    {tech.count.toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Top Hosts */}
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="text-white font-bold mb-3">Most Affected Hosts</h4>
            <div className="space-y-2">
              {breakdownData.top_hosts.map(host => (
                <div key={host.host} className="flex items-center justify-between p-2 bg-gray-800 rounded">
                  <span className="text-white">{host.host}</span>
                  <span className="text-red-400 font-bold">{host.count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Comparison View */}
      {viewMode === 'comparison' && comparisonData && (
        <div className="space-y-4">
          <div className="bg-gray-900 rounded-lg p-4">
            <h3 className="text-xl font-bold text-white mb-4">
              Cross-Source Comparison
            </h3>
            
            <div className="space-y-3">
              {comparisonData.comparison.map(cat => (
                <div key={cat.category} className="bg-gray-800 rounded-lg p-3">
                  <div className="text-white font-medium mb-2">{cat.category}</div>
                  
                  <div className="grid grid-cols-4 gap-3">
                    {Object.entries(cat.by_index).map(([index, count]) => (
                      <div key={index} className="bg-gray-900 rounded p-2">
                        <div className="text-xs text-gray-400 mb-1">
                          {getSourceLabel(index)}
                        </div>
                        <div className="text-lg font-bold text-white">
                          {count.toLocaleString()}
                        </div>
                      </div>
                    ))}
                  </div>
                  
                  <div className="mt-2 text-sm text-gray-400">
                    Total: <span className="text-white font-bold">{cat.total.toLocaleString()}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Coverage Analysis */}
          <div className="bg-gray-900 rounded-lg p-4">
            <h4 className="text-white font-bold mb-3">Coverage Analysis</h4>
            <div className="grid grid-cols-3 gap-4">
              {Object.entries(comparisonData.coverage_analysis.by_index).map(([index, data]) => (
                <div key={index} className="bg-gray-800 rounded-lg p-3">
                  <div className="text-sm text-gray-400 mb-2">
                    {getSourceLabel(index)}
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Events:</span>
                      <span className="text-white font-medium">
                        {data.total_events.toLocaleString()}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Categories:</span>
                      <span className="text-white font-medium">
                        {data.detected_categories}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Coverage:</span>
                      <span className="text-green-400 font-medium">
                        {data.coverage_percentage.toFixed(1)}%
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CategoryDashboard;